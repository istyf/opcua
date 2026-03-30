package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

// the base "node-centric" namespace
type NodeNameSpace struct {
	srv                 *Server
	name                string
	mu                  sync.RWMutex
	nodes               []types.Node
	m                   map[string]types.Node
	id                  uint16
	nextAvailableNodeID atomic.Uint32

	ExternalNotification chan *ua.NodeID

	logAttributes ualog.Attr
}

func (ns *NodeNameSpace) GetNextNodeID() uint32 {
	return ns.nextAvailableNodeID.Add(1)
}

func NewNodeNameSpace(srv *Server, name string) *NodeNameSpace {
	ns := &NodeNameSpace{
		srv:                  srv,
		name:                 name,
		nodes:                make([]types.Node, 0),
		m:                    make(map[string]types.Node),
		nextAvailableNodeID:  atomic.Uint32{},
		ExternalNotification: make(chan *ua.NodeID),
		logAttributes:        ualog.GroupAttrs("namespace", ualog.String("name", name), ualog.String("type", "node")),
	}
	ns.nextAvailableNodeID.Store(100)
	srv.AddNamespace(ns)

	folderTypeNodeID := ua.NewNumericNodeID(0, id.FolderType)
	var folderType types.ObjectTypeNode

	typeNode := srv.Node(folderTypeNodeID)
	if typeNode != nil {
		if typeNode, ok := typeNode.(types.ObjectTypeNode); ok {
			folderType = typeNode
		} else {
			panic("node " + folderTypeNodeID.String() + "was not an object type")
		}
	}

	if folderType == nil && ns.ID() == 0 {
		folderType = ns.AddNode(node.NewObjectTypeNode(
			node.WithBase(
				node.WithID(folderTypeNodeID),
				node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: folderTypeNodeID.Namespace(), Name: "FolderType"}),
			),
		)).(types.ObjectTypeNode)
	}

	ns.AddNode(node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: ns.ID(), Name: ns.name}),
		),
		node.WithType(folderType),
	))

	return ns
}

// This function is to notify opc subscribers if a node was changed
// without using the SetAttribute method
func (s *NodeNameSpace) ChangeNotification(ctx context.Context, nodeid *ua.NodeID) {
	s.srv.ChangeNotification(ctx, nodeid)
}

func (ns *NodeNameSpace) Name() string {
	return ns.name
}

func (as *NodeNameSpace) AddNode(n types.Node) types.Node {
	as.mu.Lock()
	defer as.mu.Unlock()

	// todo(fs): this is wrong since this leaves the old node in the list.
	as.nodes = append(as.nodes, n)
	k := n.ID().String()

	as.m[k] = n
	return n
}

func (as *NodeNameSpace) AddNewVariableNode(name string, value any) types.VariableNode {
	n := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(as.id, as.GetNextNodeID())),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: as.ID(), Name: name}),
		),
		node.WithValue(value),
	)
	as.AddNode(n)
	return n
}

func (as *NodeNameSpace) AddNewVariableStringNode(name string, value any) types.VariableNode {
	n := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(as.id, name)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: as.ID(), Name: name}),
		),
		node.WithValue(value),
	)
	as.AddNode(n)
	return n
}

func (as *NodeNameSpace) Attribute(ctx context.Context, id *ua.NodeID, attr ua.AttributeID) *ua.DataValue {
	ctx = ualog.WithAttrs(ctx, as.logAttributes)
	ualog.Debug(ctx, "read node attribute",
		ualog.Any(ualog.NodeIdKey, id), ualog.Any("attr", attr),
	)

	n := as.Node(id)
	if n == nil {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadNodeIDUnknown,
		}
	}

	if !n.Access(ua.AccessLevelTypeCurrentRead) {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadUserAccessDenied,
		}
	}

	var err error
	var a *types.AttrValue

	switch attr {
	case ua.AttributeIDNodeID:
		a = &types.AttrValue{Value: values.DataValueFromValue(id)}
	case ua.AttributeIDEventNotifier:
		// TODO: this is a hack to force the EventNotifier to false for everything.
		// If at some point someone or something needs to use this, this will have to go away and be
		// fixed properly.
		a = &types.AttrValue{Value: values.DataValueFromValue(byte(0))}
	case ua.AttributeIDNodeClass:
		a, err = n.Attribute(attr)
		if err != nil {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadAttributeIDInvalid,
			}
		}
		// TODO: we need int32 instead of uint32 here.  this isn't the right place to fix it, but it is a bandaid
		x, ok := a.Value.Value.Value().(uint32)
		if ok {
			a.Value.Value = ua.MustVariant(int32(x))
		}
	default:
		a, err = n.Attribute(attr)
	}

	if err != nil {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadAttributeIDInvalid,
		}
	}
	return a.Value
}

func (as *NodeNameSpace) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}

	as.mu.RLock()
	defer as.mu.RUnlock()

	k := id.String()

	return as.m[k]
}

func (as *NodeNameSpace) Objects() types.ObjectNode {
	of := ua.NewNumericNodeID(as.id, id.ObjectsFolder)
	return as.Node(of)
}

func (as *NodeNameSpace) Root() types.ObjectNode {
	return as.Node(RootFolder)
}

func (ns *NodeNameSpace) Browse(ctx context.Context, bd *ua.BrowseDescription) *ua.BrowseResult {
	ualog.Debug(ctx, "browse", ns.logAttributes,
		ualog.Any(ualog.NodeIdKey, bd.NodeID), ualog.Bitmask("mask", bd.ResultMask),
	)

	ns.mu.RLock()
	defer ns.mu.RUnlock()

	n := ns.Node(bd.NodeID)
	if n == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	refs := make([]*ua.ReferenceDescription, 0, n.References().Count())

	validReferences := func(r *ua.ReferenceDescription) bool {
		// we can't have nils in these or the encoder will fail.
		if r.NodeID == nil || r.BrowseName == nil || r.DisplayName == nil || r.TypeDefinition == nil {
			return false
		}

		// see if this is a ref the client was interested in.
		if !suitableRef(ctx, ns.srv, bd, r) {
			return false
		}

		return true
	}

	for r := range n.References().Find(validReferences) {

		td := ns.srv.Node(r.NodeID.NodeID)

		rf := &ua.ReferenceDescription{
			ReferenceTypeID: r.ReferenceTypeID,
			IsForward:       r.IsForward,
			NodeID:          r.NodeID,
			BrowseName:      r.BrowseName,
			DisplayName:     r.DisplayName,
			NodeClass:       r.NodeClass,
			TypeDefinition:  td.DataType(),
		}

		if rf.ReferenceTypeID.IntID() == id.HasTypeDefinition && rf.IsForward {
			// this one has to be first!
			refs = append([]*ua.ReferenceDescription{rf}, refs...)
		} else {
			refs = append(refs, rf)
		}
	}

	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: refs,
	}
}

func (ns *NodeNameSpace) ID() uint16 {
	return ns.id
}

func (ns *NodeNameSpace) SetID(id uint16) {
	ns.id = id
}

func (as *NodeNameSpace) SetAttribute(ctx context.Context, id *ua.NodeID, attr ua.AttributeID, val *ua.DataValue) ua.StatusCode {
	ctx = ualog.WithAttrs(ctx, as.logAttributes)
	ualog.Debug(ctx, "write node attribute", ualog.Any(ualog.NodeIdKey, id), ualog.Any("attr", attr))

	n := as.Node(id)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}

	if !n.Access(ua.AccessLevelTypeCurrentWrite) {
		return ua.StatusBadUserAccessDenied
	}

	err := n.SetAttribute(attr, val)
	if err != nil {
		return ua.StatusBadAttributeIDInvalid
	}
	as.srv.ChangeNotification(ctx, id)
	select {
	case as.ExternalNotification <- id:
	default:
	}

	return ua.StatusOK
}

func (as *NodeNameSpace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: as.ID(), Name: name}
}
