package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

// the base "node-centric" namespace
type NodeNameSpace struct {
	srv                 types.Server
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

func NewNodeNameSpace(srv types.Server, name string) *NodeNameSpace {
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

	return ns
}

// This function is to notify opc subscribers if a node was changed
// without using the SetAttribute method
func (s *NodeNameSpace) ChangeNotification(ctx context.Context, nodeid *ua.NodeID) {
	s.srv.ChangeNotification(ctx, nodeid)
}

// EmitEvent emits an OPC UA event from sourceNodeID through the owning server.
func (s *NodeNameSpace) EmitEvent(ctx context.Context, sourceNodeID *ua.NodeID, event *types.Event) error {
	return s.srv.EmitEvent(ctx, sourceNodeID, event)
}

func (ns *NodeNameSpace) Name() string {
	return ns.name
}

func (as *NodeNameSpace) AddNode(n types.Node) types.Node {
	as.mu.Lock()
	defer as.mu.Unlock()

	k := n.ID().String()
	if existing, ok := as.m[k]; ok {
		for i := range as.nodes {
			if as.nodes[i] == existing {
				as.nodes[i] = n
				as.m[k] = n
				if bindable, ok := n.(types.ChangeNotifierBindable); ok {
					nodeID := n.ID()
					bindable.BindChangeNotification(func() {
						as.srv.ChangeNotification(context.Background(), nodeID)
					})
				}
				return n
			}
		}
	}

	as.nodes = append(as.nodes, n)
	as.m[k] = n

	if bindable, ok := n.(types.ChangeNotifierBindable); ok {
		nodeID := n.ID()
		bindable.BindChangeNotification(func() {
			as.srv.ChangeNotification(context.Background(), nodeID)
		})
	}

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

	var err error
	var a *types.AttrValue

	switch attr {
	case ua.AttributeIDNodeID:
		a = &types.AttrValue{Value: values.DataValueFromValue(id)}
	case ua.AttributeIDNodeClass:
		a, err = n.Attribute(ctx, attr)
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
		a, err = n.Attribute(ctx, attr)
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
	refsCollection := n.References()
	if refsCollection == nil {
		return &ua.BrowseResult{
			StatusCode: ua.StatusGood,
			References: []*ua.ReferenceDescription{},
		}
	}

	references := make([]*ua.ReferenceDescription, 0, refsCollection.Count())

	validReferences := func(r types.ReferenceWrapper) bool {

		// see if this is a ref the client was interested in.
		if !services.SuitableReference(ctx, ns.srv, bd, r) {
			return false
		}

		return true
	}

	for r := range refsCollection.Find(validReferences) {
		rf := r.Copy(ctx)

		if rf.ReferenceTypeID.IntID() == id.HasTypeDefinition && rf.IsForward {
			// this one has to be first!
			references = append([]*ua.ReferenceDescription{rf}, references...)
		} else {
			references = append(references, rf)
		}
	}

	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: references,
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

	err := n.SetAttribute(ctx, attr, val)
	if err != nil {
		if status, ok := err.(ua.StatusCode); ok {
			return status
		}
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

func (as *NodeNameSpace) NextAvailableID() *ua.NodeID {
	return ua.NewNumericNodeID(as.ID(), as.GetNextNodeID())
}
