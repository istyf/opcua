package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/attrs"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

// This namespaces give a convenient way to have data mapped to the OPC server
// without having to map your application data to the OCP-UA data abstraction
//
// It (currently) supports ints, floats, strings, and timestamps. No maps inside of maps and no arrays.
//
// To notify subscribers of changes, be sure to call ChangeNotification(key) after changing the value.
// To be notified of changes from the opc-ua server to the map, receive on ExternalNotification channel
type MapNamespace struct {
	srv  types.Server
	name string
	mu   sync.RWMutex

	data          map[string]any
	objectsFolder types.Node

	// This can be used to be alerted when a value is changed from the opc server
	ExternalNotification chan string

	id uint16

	logAttributes ualog.Attr
}

// Get the value associated with key from the MapNamespace.
// This function handles locking and getting the value.
//
// Returns nil if the value doesn't exist.
func (s *MapNamespace) GetValue(key string) any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key]
}

// update the value associated with a key and trigger the change notification
// to the OPC server
func (s *MapNamespace) SetValue(ctx context.Context, key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	s.ChangeNotification(ctx, key)
}

func (s *MapNamespace) ValueUpdater(ctx context.Context) func(string, any) {
	return func(key string, value any) {
		s.SetValue(ctx, key, value)
	}
}

// This function is used to notify OPC UA subscribers if a key was changed without using the
// SetValue() function
func (s *MapNamespace) ChangeNotification(ctx context.Context, key string) {
	s.srv.ChangeNotification(ctx, ua.NewStringNodeID(s.id, key))
}

func NewMapNamespace(srv types.Server, name string) *MapNamespace {
	mrw := MapNamespace{
		srv:                  srv,
		name:                 name,
		data:                 make(map[string]any),
		ExternalNotification: make(chan string),
		logAttributes:        ualog.GroupAttrs("namespace", ualog.String("name", name), ualog.String("type", "map")),
	}
	srv.AddNamespace(&mrw)

	folderTypeNode := srv.Node(ua.NewNumericNodeID(0, id.FolderType))
	folderType, _ := folderTypeNode.(types.ObjectTypeNode)

	mrw.objectsFolder = node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(mrw.ID(), id.ObjectsFolder)),
			node.WithBrowseName(mrw.NewQualifiedName("Objects")),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Objects")}),
		),
		node.WithType(folderType),
	)

	refs.LinkWithOrganizesReferenceDescriptions(
		srv.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		mrw.objectsFolder,
	)

	return &mrw
}

func (s *MapNamespace) ID() uint16 {
	return s.id
}

func (ns *MapNamespace) SetID(id uint16) {
	ns.id = id
}

func (ns *MapNamespace) Browse(ctx context.Context, bd *ua.BrowseDescription) *ua.BrowseResult {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	ualog.Debug(ctx, "browse request for node", ns.logAttributes,
		ualog.Any("node_id", bd.NodeID), ualog.Bitmask("mask", bd.ResultMask),
	)

	if bd.NodeID.IntID() != ns.objectsFolder.ID().IntID() {
		return &ua.BrowseResult{
			StatusCode: ua.StatusGood,
			References: []*ua.ReferenceDescription{},
		}
	}

	refsOut := make([]*ua.ReferenceDescription, 0, len(ns.data))

	hasComponentRef := ua.NewNumericNodeID(0, id.HasComponent)

	for key := range ns.data {
		target := ns.nodeForKey(key)
		ref := refs.NewReferenceDescription(target, hasComponentRef, true)
		if !services.SuitableReference(ctx, ns.srv, bd, ref) {
			continue
		}
		refsOut = append(refsOut, ref.Copy(ctx))
	}

	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: refsOut,
	}
}

func (ns *MapNamespace) Attribute(ctx context.Context, n *ua.NodeID, a ua.AttributeID) *ua.DataValue {
	ctx = ualog.WithAttrs(ctx, ns.logAttributes)
	ualog.Debug(ctx, "read node attribute",
		ualog.Any("node_id", n), ualog.Any("attr", a),
	)

	if n.IntID() != 0 {
		// this is not one of our normal tags.
		if n.IntID() != id.ObjectsFolder {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadNodeIDInvalid,
			}
		}

		attrval, err := ns.Objects().Attribute(ctx, a)
		if err != nil {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadAttributeIDInvalid,
			}
		}

		return attrval.Value
	}

	dv := &ua.DataValue{
		EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
		ServerTimestamp: time.Now(),
		Status:          ua.StatusBad,
	}

	key := n.StringID()
	ualog.Debug(ctx, "read request", ualog.String("key", key), ualog.Any("data", ns.data))

	var err error

	// because our data is native go types we don't have any of the ua "attributes" attached to it.
	// so depending on what attribute the client wants, we'll inspect the data and return the appropriate
	// thing
	switch a {

	case ua.AttributeIDNodeID:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(n)

		// we are going to use the node id directly to look it up from our data map.
	case ua.AttributeIDValue:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		v, ok := ns.data[key]
		if !ok {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadNodeIDUnknown,
			}
		}
		switch tv := v.(type) {
		case string:
			dv.Value = ua.MustVariant(tv)
		case int:
			// we can't use an int because it is of unspecified length.  I'm going to use int64 so that we don't
			// have to worry about cutting data off. probably.
			dv.Value = ua.MustVariant(int64(tv))
		case int32:
			dv.Value = ua.MustVariant(tv)
		case float32:
			dv.Value = ua.MustVariant(tv)
		case float64:
			dv.Value = ua.MustVariant(tv)
		case bool:
			dv.Value = ua.MustVariant(tv)
		default:
			dv.Value = ua.MustVariant(tv)
		}
		// nothing in this namespace has an ID Description
	case ua.AttributeIDDescription:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(&ua.LocalizedText{EncodingMask: ua.LocalizedTextText, Text: ""})

	case ua.AttributeIDBrowseName:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(attrs.BrowseName(key))
	case ua.AttributeIDDisplayName:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(attrs.DisplayName(key, key))
	case ua.AttributeIDAccessLevel:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		level := byte(ua.AccessLevelExTypeCurrentWrite | ua.AccessLevelExTypeCurrentRead)
		dv.Value = ua.MustVariant(level)

	case ua.AttributeIDNodeClass:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int32(ua.NodeClassVariable))
		// nothing in this namespace has event notifiers
	case ua.AttributeIDEventNotifier:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int16(0))

	// values are in section 5.1.2 of the standard.
	// https://reference.opcfoundation.org/Core/Part6/v104/docs/5.1.2
	case ua.AttributeIDDataType:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		v := ns.data[key]
		switch v.(type) {
		case string:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 12))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		case int:
			// we can't use an int because it is of unspecified length.  I'm going to use int64 so that we don't
			// have to worry about cutting data off.
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 6))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		case int32:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 6))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		case float32:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 10))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		case float64:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 11))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		case bool:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 1))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		default:
			dv.Value, err = ua.NewVariant(ua.NewNumericNodeID(0, 24))
			if err != nil {
				ualog.Warn(ctx, "problem creating variant", ualog.String("err", err.Error()))
			}
		}

		// when we support arrays this will have to change.
	case ua.AttributeIDValueRank:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant(int32(-1))

	// when we support arrays this will have to change.
	case ua.AttributeIDArrayDimensions:
		dv.Status = ua.StatusOK
		dv.EncodingMask |= ua.DataValueValue
		dv.Value = ua.MustVariant([]uint32{})
	default:
		return dv
	}

	if dv.Value == nil {
		ualog.Warn(ctx, "bad dv value")
	} else {
		ualog.Debug(ctx, "read",
			ualog.String("key", key), ualog.Any("variant", dv.Value), ualog.Any("value", dv.Value.Value()),
		)
	}

	return dv
}

func (s *MapNamespace) SetAttribute(ctx context.Context, node *ua.NodeID, attr ua.AttributeID, val *ua.DataValue) ua.StatusCode {
	ctx = ualog.WithAttrs(ctx, s.logAttributes)
	ualog.Debug(ctx, "write node attribute", ualog.Any("node_id", node), ualog.Any("attr", attr))

	s.mu.Lock()
	defer s.mu.Unlock()

	ualog.Debug(ctx, "data pre-write", ualog.Any("data", s.data))

	key := node.StringID()

	// we would normally look up the node in our actual address space, but since that's dumb, we're just
	// going to use the node id directly to look it up from our data map.
	if attr == ua.AttributeIDValue {
		v := val.Value.Value()
		s.data[key] = v
	}

	// notify the opc ua server the value has changed.
	s.srv.ChangeNotification(ctx, node)
	// notify the non-opc application the value has changed.
	select {
	case s.ExternalNotification <- key:
	default:
	}

	return ua.StatusOK
}

func (ns *MapNamespace) Name() string {
	return ns.name
}
func (ns *MapNamespace) AddNode(n types.Node) types.Node {
	panic("not implemented")
}
func (ns *MapNamespace) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	if id.IntID() == ns.objectsFolder.ID().IntID() {
		return ns.objectsFolder
	}
	if id.IntID() != 0 {
		return nil
	}
	if _, ok := ns.data[id.StringID()]; !ok {
		return nil
	}
	return ns.nodeForKey(id.StringID())
}
func (ns *MapNamespace) Objects() types.ObjectNode {
	return ns.objectsFolder
}

func (ns *MapNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: name}
}

func (ns *MapNamespace) NextAvailableID() *ua.NodeID {
	panic("not implemented")
}

func (ns *MapNamespace) nodeForKey(key string) types.Node {
	return mapNamespaceNode{
		id:          ua.NewStringNodeID(ns.id, key),
		browseName:  ns.NewQualifiedName(key),
		displayName: ua.NewLocalizedText(key),
	}
}

type mapNamespaceNode struct {
	id          *ua.NodeID
	browseName  *ua.QualifiedName
	displayName *ua.LocalizedText
}

func (n mapNamespaceNode) ID() *ua.NodeID { return n.id }

func (n mapNamespaceNode) BrowseName() *ua.QualifiedName { return n.browseName }

func (n mapNamespaceNode) DisplayName(context.Context) *ua.LocalizedText { return n.displayName }

func (n mapNamespaceNode) NodeClass() ua.NodeClass { return ua.NodeClassVariable }

func (n mapNamespaceNode) AddComponent(types.Node) types.Node { return nil }

func (n mapNamespaceNode) AddComponents(...types.Node) types.Node { return nil }

func (n mapNamespaceNode) AddRef(types.ReferenceWrapper) {}

func (n mapNamespaceNode) References() types.ReferenceCollection { return nil }

func (n mapNamespaceNode) Attribute(context.Context, ua.AttributeID) (*types.AttrValue, error) {
	return nil, errors.New("map namespace nodes do not provide direct node attributes")
}

func (n mapNamespaceNode) SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error {
	return errors.New("map namespace nodes do not support direct node attribute writes")
}
