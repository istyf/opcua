package server

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/attrs"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/ua"
)

type Attributes map[ua.AttributeID]*ua.DataValue

type References []*ua.ReferenceDescription

type MethodFunc func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode)
type MethodMiddleware func(MethodFunc) MethodFunc

type ValueFunc func() *ua.DataValue

type AttrValue struct {
	Value           *ua.DataValue
	SourceTimestamp time.Time
}

func NewAttrValue(v *ua.DataValue) *AttrValue {
	return &AttrValue{Value: v, SourceTimestamp: time.Now()}
}

func DataValueFromVariant(v *ua.Variant) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           v,
		SourceTimestamp: time.Now(),
	}
}

func DataValueFromValue(val any) *ua.DataValue {
	// if we already have a data value, just return it.
	switch v := val.(type) {
	case *ua.DataValue:
		return v
	case ua.DataValue:
		return &v
	case ua.Variant:
		return DataValueFromVariant(&v)
	case *ua.Variant:
		return DataValueFromVariant(v)
	case int:
		return DataValueFromVariant(ua.MustVariant(int32(v)))
	}

	return DataValueFromVariant(ua.MustVariant(val))
}

type Node struct {
	id   *ua.NodeID
	attr Attributes
	refs References
	val  ValueFunc
	call MethodFunc

	ns NameSpace
}

func NewNode(id *ua.NodeID, attr Attributes, refs References, val ValueFunc) *Node {
	if attr == nil {
		attr = Attributes{}
	}

	n := &Node{
		id:   id,
		attr: maps.Clone(attr),
		refs: slices.Clone(refs),
		val:  val,
	}

	if n.attr[ua.AttributeIDBrowseName] == nil {
		n.SetBrowseName("")
	}
	if n.attr[ua.AttributeIDDisplayName] == nil {
		n.SetDisplayName("", "")
	}
	if n.DisplayName().Text == "" {
		n.SetDisplayName(n.BrowseName().Name, "")
	}
	if n.attr[ua.AttributeIDDescription] == nil {
		n.SetDescription("", "")
	}

	return n
}

func NewFolderNode(nodeID *ua.NodeID, name string) *Node {
	reftype := ua.NewNumericNodeID(0, id.HasComponent)

	n := NewNode(
		nodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
			ua.AttributeIDEventNotifier: DataValueFromValue(int16(0)),
		},
		[]*ua.ReferenceDescription{{
			ReferenceTypeID: reftype,
			IsForward:       true,
			NodeID:          ua.NewNumericExpandedNodeID(nodeID.Namespace(), id.ObjectsFolder),
			BrowseName:      &ua.QualifiedName{NamespaceIndex: nodeID.Namespace(), Name: name},
			DisplayName:     &ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: name},
			NodeClass:       ua.NodeClassObject,
			TypeDefinition:  ua.NewNumericExpandedNodeID(0, id.ObjectsFolder),
		}},
		nil,
	)

	return n
}

var typeNodeIdFromDataType map[int]*ua.NodeID = map[int]*ua.NodeID{
	id.Boolean:    ua.NewNumericNodeID(0, id.Boolean),
	id.SByte:      ua.NewNumericNodeID(0, id.SByte),
	id.Byte:       ua.NewNumericNodeID(0, id.Byte),
	id.Int16:      ua.NewNumericNodeID(0, id.Int16),
	id.UInt16:     ua.NewNumericNodeID(0, id.UInt16),
	id.Int32:      ua.NewNumericNodeID(0, id.Int32),
	id.UInt32:     ua.NewNumericNodeID(0, id.UInt32),
	id.Int64:      ua.NewNumericNodeID(0, id.Int64),
	id.UInt64:     ua.NewNumericNodeID(0, id.UInt64),
	id.Float:      ua.NewNumericNodeID(0, id.Float),
	id.Double:     ua.NewNumericNodeID(0, id.Double),
	id.String:     ua.NewNumericNodeID(0, id.String),
	id.ByteString: ua.NewNumericNodeID(0, id.ByteString),
}

func lookupTypeNodeIDFromValue(value any) (*ua.NodeID, int32) {
	valueRank := int32(-1)

	switch v := value.(type) {
	case func() *ua.DataValue:
		if dataValue := v(); dataValue != nil && dataValue.Value != nil {
			return lookupTypeNodeIDFromValue(dataValue.Value.Value())
		}
	case bool:
		return typeNodeIdFromDataType[id.Boolean], valueRank
	case int8:
		return typeNodeIdFromDataType[id.SByte], valueRank
	case uint8:
		return typeNodeIdFromDataType[id.Byte], valueRank
	case int16:
		return typeNodeIdFromDataType[id.Int16], valueRank
	case uint16:
		return typeNodeIdFromDataType[id.UInt16], valueRank
	case int32:
		return typeNodeIdFromDataType[id.Int32], valueRank
	case uint32:
		return typeNodeIdFromDataType[id.UInt32], valueRank
	case int64:
		return typeNodeIdFromDataType[id.Int64], valueRank
	case uint64:
		return typeNodeIdFromDataType[id.UInt64], valueRank
	case int:
		if strconv.IntSize == 64 {
			return typeNodeIdFromDataType[id.Int64], valueRank
		} else {
			return typeNodeIdFromDataType[id.Int32], valueRank
		}
	case uint:
		if strconv.IntSize == 64 {
			return typeNodeIdFromDataType[id.UInt64], valueRank
		} else {
			return typeNodeIdFromDataType[id.UInt32], valueRank
		}
	case float32:
		return typeNodeIdFromDataType[id.Float], valueRank
	case float64:
		return typeNodeIdFromDataType[id.Double], valueRank
	case string:
		return typeNodeIdFromDataType[id.String], valueRank
	case []byte:
		return typeNodeIdFromDataType[id.ByteString], valueRank
	case []any:
		if len(v) > 0 {
			if typeNode, _ := lookupTypeNodeIDFromValue(v[0]); typeNode != nil {
				return typeNode, 1
			}
		}
	}

	return nil, valueRank
}

func NewVariableNode(nodeID *ua.NodeID, name string, value any) *Node {
	dataTypeNodeID, valueRank := lookupTypeNodeIDFromValue(value)

	var valueFunc func() *ua.DataValue
	if vf, ok := value.(func() *ua.DataValue); ok {
		valueFunc = vf
	} else {
		dataValue := DataValueFromValue(value) // check if the type is supported
		valueFunc = func() *ua.DataValue { return dataValue }
	}

	n := NewNode(
		nodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
			ua.AttributeIDEventNotifier: DataValueFromValue(int16(0)),
			ua.AttributeIDValueRank:     DataValueFromValue(valueRank),
		},
		[]*ua.ReferenceDescription{},
		valueFunc,
	)

	if dataTypeNodeID != nil {
		n.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(dataTypeNodeID))
	}

	return n
}

func (n *Node) ID() *ua.NodeID {
	return n.id
}

func (n *Node) Value() *ua.DataValue {
	if n.val == nil {
		return nil
	}
	return n.val()
}

func (n *Node) Attribute(id ua.AttributeID) (*AttrValue, error) {
	if id == ua.AttributeIDValue {
		if n.attr != nil && n.val != nil {
			val := n.val()
			if val != nil && val.Value != nil {
				return NewAttrValue(val), nil
			}
		}
	} else if n.attr != nil {
		if v := n.attr[id]; v != nil {
			return NewAttrValue(v), nil
		}
	}

	return nil, ua.StatusBadAttributeIDInvalid
}

func (n *Node) SetAttribute(id ua.AttributeID, val *ua.DataValue) error {

	switch id {
	case ua.AttributeIDValue:

		// TODO: probably need to do some type checking here.
		// And some permissions tests
		n.val = func() *ua.DataValue {
			return val
		}
	default:
		n.attr[id] = val
	}

	return nil
}

func (n *Node) BrowseName() *ua.QualifiedName {
	v := n.attr[ua.AttributeIDBrowseName]
	if v == nil || v.Value.Value() == nil {
		return &ua.QualifiedName{}
	}
	return v.Value.Value().(*ua.QualifiedName)
}

func (n *Node) SetBrowseName(s string) {
	n.attr[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{Name: s})
}

func (n *Node) DisplayName() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDisplayName]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	val := v.Value.Value().(*ua.LocalizedText)
	val.UpdateMask()
	return val
}

func (n *Node) SetDisplayName(text, locale string) {
	lt := &ua.LocalizedText{Text: text, Locale: locale}
	lt.UpdateMask()
	n.attr[ua.AttributeIDDisplayName] = DataValueFromValue(lt)
}

func (n *Node) Description() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDescription]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	return v.Value.Value().(*ua.LocalizedText)
}

func (n *Node) SetDescription(text, locale string) {
	n.attr[ua.AttributeIDDescription] = DataValueFromValue(&ua.LocalizedText{Text: text, Locale: locale})
}

func (n *Node) DataType() *ua.ExpandedNodeID {
	if n == nil {
		fmt.Println("n was nil!")
		return ua.NewTwoByteExpandedNodeID(0)
	}

	v, ok := n.attr[ua.AttributeIDDataType]
	if !ok || v == nil || v.Value.Value() == nil {
		// if we have a type definition, return that?
		for i := range n.refs {
			r := n.refs[i]
			if r.ReferenceTypeID == nil {
				fmt.Println("reftypeid was nil!")
			}
			if r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasTypeDefinition && r.IsForward {
				return r.NodeID
			}
		}
		return ua.NewTwoByteExpandedNodeID(0)
	}

	switch val := v.Value.Value().(type) {
	case *ua.ExpandedNodeID:
		return val
	case *ua.NodeID:
		return &ua.ExpandedNodeID{NodeID: val}
	}

	return ua.NewTwoByteExpandedNodeID(0)
}

func (n *Node) CallMethod(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if n.call == nil {
		return nil, ua.StatusBadNotImplemented
	}

	return n.call(ctx, args...)
}

func (n *Node) SetNodeClass(nc ua.NodeClass) {
	n.attr[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(nc))
}

func (n *Node) NodeClass() ua.NodeClass {
	v := n.attr[ua.AttributeIDNodeClass]
	if v == nil || v.Value.Value() == nil {
		return ua.NodeClassObject
	}
	vi32, ok := v.Value.Value().(int32)
	if !ok {
		vui32, ok := v.Value.Value().(uint32)
		if !ok {
			return ua.NodeClassObject
		}
		return ua.NodeClass(int32(vui32))
	}
	return ua.NodeClass(vi32)
}

func (n *Node) AddObject(o *Node) *Node {
	nn := NewNode(o.ID(), o.attr, o.refs, nil)
	nn.SetNodeClass(ua.NodeClassObject)

	n.refs = append(n.refs, refs.NewOrganizesRefDesc(nn.id, nn.BrowseName().Name, nn.DisplayName().Text, nn.DataType()))

	return n.ns.AddNode(nn)
}

func (n *Node) AddVariable(o *Node) *Node {
	nn := NewNode(o.ID(), o.attr, o.refs, o.val)

	nn.SetNodeClass(ua.NodeClassVariable)
	n.refs = append(n.refs, refs.NewOrganizesRefDesc(nn.id, nn.BrowseName().Name, nn.DisplayName().Text, nn.DataType()))
	return nn
}

type RefType int

const (
	RefTypeIDHasComponent = id.HasComponent
	RefTypeIDOrganizes    = id.Organizes
)

func (n *Node) AddRef(o *Node, rt RefType, forward bool) {
	//eoid := ua.NewNumericExpandedNodeID(o.ns.ID(), o.)
	eoid := ua.NewExpandedNodeID(o.ID(), "", 0)

	ref := ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, uint32(rt)), //o.refs[0].ReferenceTypeID,
		IsForward:       forward,
		NodeID:          eoid,
		BrowseName:      o.BrowseName(),
		DisplayName:     o.DisplayName(),
		NodeClass:       o.NodeClass(),
		TypeDefinition:  o.DataType(),
	}

	n.refs = append(n.refs, &ref)
}

// Access returns true if the node has the access level requested.
// It checks both the UserAccessLevel and AccessLevel attributes.
// If neither are present, it assumes global access and returns true.
//
// I'm not sure what the best way to implement "user" specific access levels
// is presently.  Will need functioning user authentication first, and then a way to
// pass it into the nodes user access attribute so it can be checked properly.
func (n Node) Access(flag ua.AccessLevelType) bool {

	access, err := n.Attribute(ua.AttributeIDUserAccessLevel)
	if err == nil { // if we have a user access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}
		if val&uint8(flag) == 0 {
			return false
		}
	}

	access, err = n.Attribute(ua.AttributeIDAccessLevel)
	if err == nil { // if we have an access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}

		if val&uint8(flag) == 0 {
			return false
		}
	}

	return true
}
