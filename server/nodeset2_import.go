package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

type nsIDLookup map[uint16]uint16

func visitNodeSetNodes(nodes *schema.UANodeSet, visit func(*schema.UANode)) {
	for i := range nodes.UAReferenceType {
		visit(nodes.UAReferenceType[i].UANode)
	}
	for i := range nodes.UADataType {
		visit(nodes.UADataType[i].UANode)
	}
	for i := range nodes.UAObjectType {
		visit(nodes.UAObjectType[i].UANode)
	}
	for i := range nodes.UAVariableType {
		visit(nodes.UAVariableType[i].UANode)
	}
	for i := range nodes.UAVariable {
		visit(nodes.UAVariable[i].UANode)
	}
	for i := range nodes.UAMethod {
		visit(nodes.UAMethod[i].UANode)
	}
	for i := range nodes.UAObject {
		visit(nodes.UAObject[i].UANode)
	}
}

func (s *serverImpl) shouldImportNodeSetNode(n *schema.UANode) bool {
	if n == nil {
		return false
	}
	if s.importDeprecatedNodeSetNodes {
		return true
	}
	return !strings.EqualFold(n.ReleaseStatusAttr, "Deprecated")
}

// ImportNodeSet imports nodes, attributes, and references from a NodeSet2
// document into the server.
//
// For imported DataType nodes, this includes loading modern
// AttributeIDDataTypeDefinition metadata from UADataType.Definition when the
// NodeSet provides enough information to classify and convert the definition.
// Malformed or unsupported definitions are logged and omitted for that node
// without aborting the full import.
//
// The importer intentionally does not populate the legacy Definition property;
// the supported metadata surface is the DataTypeDefinition attribute. By
// default, NodeSet nodes marked ReleaseStatus="Deprecated" are skipped.
func (s *serverImpl) ImportNodeSet(ctx context.Context, nodes *schema.UANodeSet) error {
	idLookup, err := s.namespacesImportNodeSet(nodes)
	if err != nil {
		return fmt.Errorf("problem creating namespaces: %w", err)
	}

	err = s.nodesImportNodeSet(ctx, nodes, idLookup)
	if err != nil {
		return fmt.Errorf("problem creating nodes: %w", err)
	}

	err = s.refsImportNodeSet(ctx, nodes, idLookup)
	if err != nil {
		return fmt.Errorf("problem creating references: %w", err)
	}

	return nil
}

func (s *serverImpl) namespacesImportNodeSet(nodes *schema.UANodeSet) (*nsIDLookup, error) {
	nameSpaceLookup := nsIDLookup{}

	if nodes.NamespaceUris == nil {
		return &nameSpaceLookup, nil
	}

	for i := range nodes.NamespaceUris.Uri {
		name := nodes.NamespaceUris.Uri[i]

		idx := slices.IndexFunc(s.Namespaces(), func(ns types.NameSpace) bool {
			return strings.Compare(ns.Name(), name) == 0
		})

		var ns types.NameSpace

		if idx >= 0 {
			ns = s.Namespaces()[idx]
		} else {
			ns = NewNodeNameSpace(s, name)
		}

		if ns.ID() != 0 || i != 0 {
			lookupKey := uint16(i + 1)
			if lookupKey != ns.ID() {
				nameSpaceLookup[lookupKey] = ns.ID()
			}
		}
	}

	return &nameSpaceLookup, nil
}

func (s *serverImpl) nodesImportNodeSet(ctx context.Context, nodes *schema.UANodeSet, nsID *nsIDLookup) error {

	ualog.Info(ctx, "new node set", ualog.String("last_modified", nodes.LastModifiedAttr))

	localizedTextsFromSchema := func(localizedText []*schema.LocalizedText, defaultText string) []*ua.LocalizedText {
		nrofTexts := len(localizedText)
		if nrofTexts > 0 {
			names := make([]*ua.LocalizedText, 0, nrofTexts)
			for idx := range nrofTexts {
				names = append(names, ua.NewLocalizedTextWithLocale(
					localizedText[idx].Value, localizedText[idx].LocaleAttr,
				))
			}
			return names
		}
		return []*ua.LocalizedText{ua.NewLocalizedText(defaultText)}
	}

	aliases := map[string]string{}
	if nodes.Aliases != nil {
		aliases = make(map[string]string, len(nodes.Aliases.Alias))
		for i := range nodes.Aliases.Alias {
			alias := nodes.Aliases.Alias[i]
			aliases[alias.AliasAttr] = alias.Value
		}
	}

	mustParseAndConvertNodeID := func(nodeID string) *ua.NodeID {
		nid := ua.MustParseNodeID(nodeID)
		if correctNS, ok := (*nsID)[nid.Namespace()]; ok {
			nid.SetNamespace(uint16(correctNS))
		}
		return nid
	}
	convertNamespaceIndex := func(ns uint16) uint16 {
		if correctNS, ok := (*nsID)[ns]; ok {
			return correctNS
		}
		return ns
	}
	parseAndConvertQualifiedName := func(name string) *ua.QualifiedName {
		nsPart, localName, hasNamespace := strings.Cut(name, ":")
		if !hasNamespace {
			return &ua.QualifiedName{Name: name}
		}

		nsIndex, err := strconv.ParseUint(nsPart, 10, 16)
		if err != nil {
			return &ua.QualifiedName{Name: name}
		}

		return &ua.QualifiedName{
			NamespaceIndex: convertNamespaceIndex(uint16(nsIndex)),
			Name:           localName,
		}
	}
	convertQualifiedNameValue := func(name *schema.ValueQualifiedName) *ua.QualifiedName {
		if name == nil {
			return nil
		}

		return &ua.QualifiedName{
			NamespaceIndex: convertNamespaceIndex(uint16(name.NamespaceIndex)),
			Name:           name.Name,
		}
	}
	resolveImportedNodeID := newImportedNodeIDResolver(aliases, nsID)

	valueFromSchema := func(v *schema.Value) any {
		if v == nil {
			return nil
		}

		if v.StringAttr != nil {
			return v.StringAttr.Data
		} else if v.StringListAttr != nil {
			data := make([]string, 0, len(v.StringListAttr.Data))
			for _, s := range v.StringListAttr.Data {
				data = append(data, s.Data)
			}
			return data
		} else if v.DateTimeAttr != nil {
			return v.DateTimeAttr.Data
		} else if v.Int32Attr != nil {
			return v.Int32Attr.Data
		} else if v.UInt32Attr != nil {
			return v.UInt32Attr.Data
		} else if v.Int32ListAttr != nil {
			data := make([]int32, 0, len(v.Int32ListAttr.Data))
			for _, i := range v.Int32ListAttr.Data {
				data = append(data, i.Data)
			}
			return data
		} else if v.BoolAttr != nil {
			return v.BoolAttr.Data
		} else if v.ByteStringAttr != nil {
			bs := v.ByteStringAttr.Data
			if b64b, err := base64.StdEncoding.DecodeString(bs); err == nil {
				return b64b
			}
		} else if v.TextAttr != nil {
			v := ua.NewLocalizedTextWithLocale(v.TextAttr.Text, v.TextAttr.Locale)
			return v
		} else if v.TextListAttr != nil {
			data := make([]*ua.LocalizedText, 0, len(v.TextListAttr.Data))
			for _, t := range v.TextListAttr.Data {
				data = append(data, ua.NewLocalizedTextWithLocale(t.Text, t.Locale))
			}
			return data
		} else if v.ExtObjAttr != nil {
			extObj := v.ExtObjAttr
			typeId := mustParseAndConvertNodeID(extObj.TypeID.Identifier)
			if typeId.IntID() == id.Argument_Encoding_DefaultXML {
				arg := &ua.Argument{
					Name:            extObj.Body.Argument.Name,
					DataType:        mustParseAndConvertNodeID(extObj.Body.Argument.DataType.Identifier),
					ValueRank:       int32(extObj.Body.Argument.ValueRank),
					ArrayDimensions: make([]uint32, 0, len(extObj.Body.Argument.ArrayDimensions.Data)),
					Description:     ua.NewLocalizedText(extObj.Body.Argument.Description.Text),
				}

				for _, ad := range extObj.Body.Argument.ArrayDimensions.Data {
					arg.ArrayDimensions = append(arg.ArrayDimensions, ad.Data)
				}
				v := ua.NewExtensionObject(arg)
				return v
			} else if typeId.IntID() == id.EnumValueType_Encoding_DefaultXML {
				evt := v.ExtObjAttr.Body.EnumValueType
				data := &ua.EnumValueType{
					Value:       int64(evt.Value),
					DisplayName: ua.NewLocalizedText(evt.DisplayName.Text),
					Description: ua.NewLocalizedText(evt.Description.Text),
				}
				v := ua.NewExtensionObject(data)
				return v
			}
		} else if v.ExtObjListAttr != nil {
			supportedTypes := map[string]struct{}{"i=297": {}, "i=7616": {}}
			if !slices.ContainsFunc(v.ExtObjListAttr.Data, func(eo schema.ValueExtensionObject) bool {
				_, ok := supportedTypes[eo.TypeID.Identifier]
				return !ok
			}) {
				data := make([]*ua.ExtensionObject, 0, len(v.ExtObjListAttr.Data))
				for _, extObj := range v.ExtObjListAttr.Data {
					typeId := mustParseAndConvertNodeID(extObj.TypeID.Identifier)
					if typeId.IntID() == id.Argument_Encoding_DefaultXML {
						arg := &ua.Argument{
							Name:            extObj.Body.Argument.Name,
							DataType:        mustParseAndConvertNodeID(extObj.Body.Argument.DataType.Identifier),
							ValueRank:       int32(extObj.Body.Argument.ValueRank),
							ArrayDimensions: make([]uint32, 0, len(extObj.Body.Argument.ArrayDimensions.Data)),
							Description:     ua.NewLocalizedText(extObj.Body.Argument.Description.Text),
						}

						for _, ad := range extObj.Body.Argument.ArrayDimensions.Data {
							arg.ArrayDimensions = append(arg.ArrayDimensions, ad.Data)
						}
						data = append(data, ua.NewExtensionObject(arg))
					} else if typeId.IntID() == id.EnumValueType_Encoding_DefaultXML {
						evt := extObj.Body.EnumValueType
						data = append(data, ua.NewExtensionObject(&ua.EnumValueType{
							Value:       int64(evt.Value),
							DisplayName: ua.NewLocalizedText(evt.DisplayName.Text),
							Description: ua.NewLocalizedText(evt.Description.Text),
						}))
					}
				}
				return data
			}
		} else if v.QualifiedNameAttr != nil {
			return convertQualifiedNameValue(v.QualifiedNameAttr)
		}

		return nil
	}

	reftypes := make(map[string]*schema.UAReferenceType)

	// the first thing we have to do is go through and define all the nodes.
	// set up the reference types.
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		if !s.shouldImportNodeSetNode(rt.UANode) {
			continue
		}
		reftypes[rt.BrowseNameAttr] = rt // sometimes they use browse name
		reftypes[rt.NodeIdAttr] = rt     // sometimes they use node id

		nid := mustParseAndConvertNodeID(rt.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(rt.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(rt.DisplayName, browseName.Name)
		descriptions := localizedTextsFromSchema(rt.Description, "")

		n := node.NewReferenceTypeNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions),
			),
			node.WithAbstract(rt.IsAbstractAttr),
			node.WithInverseNames(func() []*ua.LocalizedText {
				if len(rt.InverseName) == 0 {
					return nil
				}

				return localizedTextsFromSchema(rt.InverseName, "")
			}()),
		)
		ns.AddNode(n)
	}

	// set up the data types.
	for i := range nodes.UADataType {
		dt := nodes.UADataType[i]
		if !s.shouldImportNodeSetNode(dt.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(dt.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(dt.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(dt.DisplayName, browseName.Name)
		descriptions := localizedTextsFromSchema(dt.Description, "")

		n := node.NewDataTypeNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions),
			),
			node.WithAbstractType(dt.IsAbstractAttr),
		)
		if definition, err := importSchemaDataTypeDefinition(dt, resolveImportedNodeID); err != nil {
			ualog.Warn(ctx, "failed to import data type definition",
				ualog.String("node_id", nid.String()),
				ualog.String("browse_name", dt.BrowseNameAttr),
				ualog.Err(err),
			)
		} else if definition != nil {
			if err := n.SetAttribute(ctx, ua.AttributeIDDataTypeDefinition, values.DataValueFromValue(definition)); err != nil {
				ualog.Warn(ctx, "failed to attach data type definition",
					ualog.String("node_id", nid.String()),
					ualog.String("browse_name", dt.BrowseNameAttr),
					ualog.Err(err),
				)
			}
		}

		ns.AddNode(n)
	}

	// set up the object types
	for i := range nodes.UAObjectType {
		ot := nodes.UAObjectType[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(ot.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(ot.DisplayName, browseName.Name)
		descriptions := localizedTextsFromSchema(ot.Description, "")

		n := node.NewObjectTypeNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions),
			),
			node.WithAbstractType(ot.IsAbstractAttr),
		)
		ns.AddNode(n)
	}

	// set up the variable Types
	for i := range nodes.UAVariableType {
		ot := nodes.UAVariableType[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(ot.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(ot.DisplayName, browseName.Name)
		descriptions := localizedTextsFromSchema(ot.Description, "")

		n := node.NewVariableTypeNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions),
			),
			node.WithAbstractVariableType(ot.IsAbstractAttr),
			node.WithDefaultValue(
				mustParseAndConvertNodeID(ot.DataTypeAttr),
				func() int32 {
					if ot.ValueRankAttr == nil {
						return -1
					}
					return int32(*ot.ValueRankAttr)
				}(),
				valueFromSchema(ot.Value),
			),
			// TODO: Handle array dimensions
		)
		ns.AddNode(n)
	}

	// set up the variables
	for i := range nodes.UAVariable {
		ot := nodes.UAVariable[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(ot.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(ot.DisplayName, browseName.Name)
		descriptions := localizedTextsFromSchema(ot.Description, "")

		vartype := func() types.VariableTypeNode {
			for _, r := range ot.References.Reference {
				if r.ReferenceTypeAttr == "HasTypeDefinition" || r.ReferenceTypeAttr == "i=40" {
					if tn := s.Node(mustParseAndConvertNodeID(r.Value)); tn != nil {
						if vartypenode, ok := tn.(types.VariableTypeNode); ok {
							return vartypenode
						}
					}
				}
			}

			if tn := s.Node(ua.NewNumericNodeID(0, id.BaseVariableType)); tn != nil {
				if vartypenode, ok := tn.(types.VariableTypeNode); ok {
					return vartypenode
				}
			}

			return nil
		}()

		dataTypeNodeId := func() *ua.NodeID {
			if ot.DataTypeAttr != "" {
				dtidx := slices.IndexFunc(nodes.UADataType, func(dt *schema.UADataType) bool {
					if strings.Compare(dt.BrowseNameAttr, ot.DataTypeAttr) == 0 {
						return true
					}

					return strings.Compare(dt.NodeIdAttr, ot.DataTypeAttr) == 0
				})
				if dtidx >= 0 {
					dt := nodes.UADataType[dtidx]
					return mustParseAndConvertNodeID(dt.NodeIdAttr)
				}

				if nodes.Aliases != nil {
					aliasidx := slices.IndexFunc(nodes.Aliases.Alias, func(a *schema.NodeIdAlias) bool {
						return strings.Compare(a.AliasAttr, ot.DataTypeAttr) == 0
					})
					if aliasidx >= 0 {
						dt := nodes.Aliases.Alias[aliasidx]
						return mustParseAndConvertNodeID(dt.Value)
					}
				}

				if n := s.Node(mustParseAndConvertNodeID(ot.DataTypeAttr)); n != nil {
					return n.ID()
				}

				fmt.Printf("failed to decode variable data type node id: %s (%s)\n", nid.String(), ot.DataTypeAttr)
			}

			if vartype != nil {
				if expanded := vartype.DataType(); expanded != nil && expanded.NodeID != nil && !expanded.NodeID.Equal(ua.NewTwoByteNodeID(0)) {
					return expanded.NodeID
				}
			}

			return ua.NewNumericNodeID(0, id.BaseDataType)
		}()

		v := valueFromSchema(ot.Value)

		baseOptions := node.WithBase(
			node.WithID(nid),
			node.WithBrowseName(browseName),
			node.WithDisplayNames(displayNames),
			node.WithDescriptions(descriptions),
		)

		var n types.VariableNode

		isNilInterface := func(v any) bool {
			if v == nil {
				return true
			}

			rv := reflect.ValueOf(v)
			switch rv.Kind() {
			case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Interface, reflect.Slice:
				return rv.IsNil()
			default:
				return false
			}
		}

		if dataTypeNodeId.Namespace() == 0 && !isNilInterface(v) {
			n = node.NewVariableNode(
				baseOptions,
				node.WithHistorization(ot.HistorizingAttr),
				node.WithVariableType(vartype),
				node.WithValue(v),
				node.WithAccessLevelEx(
					func() uint32 {
						if ot.AccessLevelAttr == nil {
							return math.MaxUint32
						}
						return *ot.AccessLevelAttr
					}()),
			)
		} else {
			n = node.NewVariableNode(
				baseOptions,
				node.WithHistorization(ot.HistorizingAttr),
				node.WithVariableType(vartype),
				node.WithDataType(dataTypeNodeId),
				node.WithValueRank(func() int32 {
					if ot.ValueRankAttr == nil {
						return -1
					}
					return int32(*ot.ValueRankAttr)
				}()),
				node.WithDataValue(values.DataValueFromValue(v)),
				node.WithAccessLevelEx(
					func() uint32 {
						if ot.AccessLevelAttr == nil {
							return math.MaxUint32
						}
						return *ot.AccessLevelAttr
					}()),
			)
		}

		ns.AddNode(n)
	}

	// set up the methods
	for i := range nodes.UAMethod {
		ot := nodes.UAMethod[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}

		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(ot.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(ot.DisplayName, ot.BrowseNameAttr)
		descriptions := localizedTextsFromSchema(ot.Description, "")

		n := node.NewMethodNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions)),
			node.Executable(ot.ExecutableAttr == nil || *ot.ExecutableAttr),
		)

		ns.AddNode(n)
	}

	// set up the objects
	for i := range nodes.UAObject {
		ot := nodes.UAObject[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			ualog.Warn(ctx, "could not find namespace", ualog.Namespace(nid.Namespace()))
			return err
		}

		browseName := parseAndConvertQualifiedName(ot.BrowseNameAttr)
		displayNames := localizedTextsFromSchema(ot.DisplayName, ot.BrowseNameAttr)
		descriptions := localizedTextsFromSchema(ot.Description, "")

		objtype := func() types.ObjectTypeNode {
			for _, r := range ot.References.Reference {
				if r.ReferenceTypeAttr == "HasTypeDefinition" || r.ReferenceTypeAttr == "i=40" {
					if tn := s.Node(mustParseAndConvertNodeID(r.Value)); tn != nil {
						if objtypenode, ok := tn.(types.ObjectTypeNode); ok {
							return objtypenode
						}
					}
				}
			}

			if tn := s.Node(ua.NewNumericNodeID(0, id.BaseObjectType)); tn != nil {
				if objtypenode, ok := tn.(types.ObjectTypeNode); ok {
					return objtypenode
				}
			}

			return nil
		}()

		n := node.NewObjectNode(
			node.WithBase(
				node.WithID(nid),
				node.WithBrowseName(browseName),
				node.WithDisplayNames(displayNames),
				node.WithDescriptions(descriptions),
			),
			node.WithType(objtype),
			node.WithEventNotifier(ua.EventNotifierType(ot.EventNotifierAttr)),
		)
		ns.AddNode(n)
	}

	return nil
}

func (s *serverImpl) refsImportNodeSet(ctx context.Context, nodes *schema.UANodeSet, nsID *nsIDLookup) error {

	ualog.Info(ctx, "new node set", ualog.String("last_modified", nodes.LastModifiedAttr))

	aliases := make(map[string]string)

	mustParseAndConvertNodeID := func(nodeID string) *ua.NodeID {
		if aliasedID, isAlias := aliases[nodeID]; isAlias {
			nodeID = aliasedID
		}

		nid := ua.MustParseNodeID(nodeID)
		if correctNS, ok := (*nsID)[nid.Namespace()]; ok {
			nid.SetNamespace(uint16(correctNS))
		}
		return nid
	}

	failures := 0
	reftypes := make(map[string]*schema.UAReferenceType)
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		reftypes[rt.BrowseNameAttr] = rt // sometimes they use browse name
		reftypes[rt.NodeIdAttr] = rt     // sometimes they use node id
	}

	if nodes.Aliases != nil {
		for i := range nodes.Aliases.Alias {
			alias := nodes.Aliases.Alias[i]
			aliases[alias.AliasAttr] = alias.Value
		}
	}

	skippedNodes := make(map[string]struct{})
	visitNodeSetNodes(nodes, func(n *schema.UANode) {
		if s.shouldImportNodeSetNode(n) {
			return
		}
		nid := mustParseAndConvertNodeID(n.NodeIdAttr)
		skippedNodes[nid.String()] = struct{}{}
	})

	isSkippedNodeID := func(nid *ua.NodeID) bool {
		if nid == nil {
			return false
		}
		_, ok := skippedNodes[nid.String()]
		return ok
	}

	// any of the aliases could be reference types, so we have to check them all and add them to the reftypes map
	// if they are.
	referenceTypeTargetMatches := func(existing *schema.UAReferenceType, target string) bool {
		if existing == nil {
			return false
		}

		existingID := mustParseAndConvertNodeID(existing.NodeIdAttr)
		targetID := mustParseAndConvertNodeID(target)
		if existingID == nil || targetID == nil {
			return existing.NodeIdAttr == target
		}

		return existingID.Equal(targetID)
	}

	for alias := range aliases {
		aliasID := mustParseAndConvertNodeID(aliases[alias])
		refnode := s.Node(aliasID)
		if refnode == nil {
			ualog.Warn(ctx, "failed to load alias", ualog.String("alias", alias))
			continue
		}
		rt := new(schema.UAReferenceType)
		rt.UAType = new(schema.UAType)
		rt.UAType.UANode = new(schema.UANode)
		rt.BrowseNameAttr = alias
		rt.NodeIdAttr = aliases[alias]
		isSymmetricValue, err := refnode.Attribute(ctx, ua.AttributeIDSymmetric)
		if err == nil {
			rt.SymmetricAttr = isSymmetricValue.Value.Value.Value().(bool)
		}

		_, ok := reftypes[alias]
		if !ok {
			reftypes[alias] = rt // sometimes they use browse name
		} else if !referenceTypeTargetMatches(reftypes[alias], aliases[alias]) {
			ualog.Warn(ctx, "duplicate reference type alias points to different target",
				ualog.String("alias", alias),
				ualog.String("existing", reftypes[alias].NodeIdAttr),
				ualog.String("incoming", aliases[alias]),
			)
			continue
		}

		_, ok = reftypes[aliases[alias]]
		if !ok {
			reftypes[aliases[alias]] = rt // sometimes they use node id
		} else if !referenceTypeTargetMatches(reftypes[aliases[alias]], aliases[alias]) {
			ualog.Warn(ctx, "duplicate reference type alias points to different target",
				ualog.String("alias", aliases[alias]),
				ualog.String("existing", reftypes[aliases[alias]].NodeIdAttr),
				ualog.String("incoming", aliases[alias]),
			)
			continue
		}
	}

	resolveReferenceType := func(browseName, refType string) *schema.UAReferenceType {
		rt, ok := reftypes[refType]
		if ok && rt != nil {
			return rt
		}

		ualog.Error(ctx, "unable to find reference type",
			ualog.String("ref_type", refType),
			ualog.String("browse_name", browseName),
		)
		failures++
		return nil
	}

	// the first thing we have to do is go thorugh and define all the nodes.
	// set up the reference types.
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		if !s.shouldImportNodeSetNode(rt.UANode) {
			continue
		}

		nodeid := mustParseAndConvertNodeID(rt.NodeIdAttr)
		node := s.Node(nodeid)
		if node == nil {
			ualog.Error(ctx, "error loading node", ualog.String("id", rt.NodeIdAttr))
		}

		for rid := range rt.References.Reference {
			ref := rt.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", rt.BrowseNameAttr),
				)
				failures++
				continue
			}

			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(rt.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))

			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	// set up the data types.
	for i := range nodes.UADataType {
		dt := nodes.UADataType[i]
		if !s.shouldImportNodeSetNode(dt.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(dt.NodeIdAttr)
		node := s.Node(nid)

		if nid.IntID() == 24 {
			ualog.Info(ctx, "doing basedatatype")
		}

		if dt.References != nil {
			for rid := range dt.References.Reference {
				ref := dt.References.Reference[rid]
				refnodeid := mustParseAndConvertNodeID(ref.Value)
				if isSkippedNodeID(refnodeid) {
					continue
				}
				n := s.Node(refnodeid)
				if n == nil {
					ualog.Error(ctx, "unable to find node",
						ualog.String("value", ref.Value),
						ualog.String("ref_type", ref.ReferenceTypeAttr),
						ualog.String("browse_name", dt.BrowseNameAttr),
					)
					failures++
					continue
				}

				if ref.IsForwardAttr == nil {
					v := true
					ref.IsForwardAttr = &v
				}

				reftype := resolveReferenceType(dt.BrowseNameAttr, ref.ReferenceTypeAttr)
				if reftype == nil {
					continue
				}
				reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
				node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))

				if !reftype.SymmetricAttr {
					n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
				}
			}
		}
	}

	// set up the object types
	for i := range nodes.UAObjectType {
		ot := nodes.UAObjectType[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)
		node := s.Node(nid)

		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", ot.BrowseNameAttr),
				)
				failures++
				continue
			}
			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(ot.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))

			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	// set up the variable Types
	for i := range nodes.UAVariableType {
		ot := nodes.UAVariableType[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)
		node := s.Node(nid)

		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", ot.BrowseNameAttr),
				)
				failures++
				continue
			}
			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(ot.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))
			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	// set up the variables
	for i := range nodes.UAVariable {
		ot := nodes.UAVariable[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)
		node := s.Node(nid)

		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", ot.BrowseNameAttr),
				)
				failures++
				continue
			}
			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(ot.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))
			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	// set up the methods
	for i := range nodes.UAMethod {
		ot := nodes.UAMethod[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)
		node := s.Node(nid)

		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", ot.BrowseNameAttr),
				)
				failures++
				continue
			}
			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(ot.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))
			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	// set up the objects
	for i := range nodes.UAObject {
		ot := nodes.UAObject[i]
		if !s.shouldImportNodeSetNode(ot.UANode) {
			continue
		}
		nid := mustParseAndConvertNodeID(ot.NodeIdAttr)
		node := s.Node(nid)
		if nid.IntID() == id.RootFolder {
			ualog.Info(ctx, "doing root")
		}

		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid := mustParseAndConvertNodeID(ref.Value)
			if isSkippedNodeID(refnodeid) {
				continue
			}
			n := s.Node(refnodeid)
			if n == nil {
				ualog.Error(ctx, "unable to find node",
					ualog.String("value", ref.Value),
					ualog.String("ref_type", ref.ReferenceTypeAttr),
					ualog.String("browse_name", ot.BrowseNameAttr),
				)
				failures++
				continue
			}
			if ref.IsForwardAttr == nil {
				v := true
				ref.IsForwardAttr = &v
			}
			reftype := resolveReferenceType(ot.BrowseNameAttr, ref.ReferenceTypeAttr)
			if reftype == nil {
				continue
			}
			reftypeid := mustParseAndConvertNodeID(reftype.NodeIdAttr)
			node.AddRef(refs.NewReferenceDescription(n, refs.TypeID(reftypeid.IntID()), *ref.IsForwardAttr))
			if !reftype.SymmetricAttr {
				n.AddRef(refs.NewReferenceDescription(node, refs.TypeID(reftypeid.IntID()), !*ref.IsForwardAttr))
			}
		}
	}

	return nil
}
