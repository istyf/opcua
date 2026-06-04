package server

import (
	"context"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeNamespaceBrowseHandlesNodesWithoutReferences(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")
	n := nodeNamespaceTestNode{
		id:          ua.NewNumericNodeID(ns.ID(), 1001),
		browseName:  ns.NewQualifiedName("Target"),
		displayName: ua.NewLocalizedText("Target"),
		nodeClass:   ua.NodeClassObject,
	}
	ns.AddNode(n)

	result := ns.Browse(t.Context(), &ua.BrowseDescription{
		NodeID:          n.ID(),
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, 0),
	})

	assert.Equal(t, ua.StatusGood, result.StatusCode)
	assert.Empty(t, result.References)
}

func TestNodeNamespaceBrowseHonorsSharedFiltersAndKeepsTypeDefinitionFirst(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")

	objectType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(ns.ID(), 5002)),
			node.WithBrowseName(ns.NewQualifiedName("Type")),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Type")}),
		),
	)
	parent := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(ns.ID(), 1002)),
			node.WithBrowseName(ns.NewQualifiedName("Parent")),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Parent")}),
		),
		node.WithType(objectType),
	)
	child := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(ns.ID(), 1003)),
			node.WithBrowseName(ns.NewQualifiedName("Child")),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Child")}),
		),
		node.WithType(objectType),
	)

	refs.LinkWithHasComponentReferenceDescriptions(parent, child)
	ns.AddNode(parent)
	ns.AddNode(child)

	result := ns.Browse(t.Context(), &ua.BrowseDescription{
		NodeID:          parent.ID(),
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, 0),
		ResultMask:      uint32(ua.BrowseResultMaskReferenceTypeID | ua.BrowseResultMaskBrowseName),
	})

	require.Equal(t, ua.StatusGood, result.StatusCode)
	require.GreaterOrEqual(t, len(result.References), 2)
	require.NotNil(t, result.References[0].ReferenceTypeID)
	require.NotNil(t, result.References[1].ReferenceTypeID)
	assert.Equal(t, uint32(id.HasTypeDefinition), result.References[0].ReferenceTypeID.IntID())
	assert.Equal(t, uint32(id.HasComponent), result.References[1].ReferenceTypeID.IntID())
}

func TestNodeNamespaceAddNodeReplacesExistingNodeByID(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")
	nodeID := ua.NewNumericNodeID(ns.ID(), 1004)

	original := nodeNamespaceTestNode{
		id:          nodeID,
		browseName:  ns.NewQualifiedName("Original"),
		displayName: ua.NewLocalizedText("Original"),
		nodeClass:   ua.NodeClassObject,
	}
	replacement := nodeNamespaceTestNode{
		id:          nodeID,
		browseName:  ns.NewQualifiedName("Replacement"),
		displayName: ua.NewLocalizedText("Replacement"),
		nodeClass:   ua.NodeClassObject,
	}

	ns.AddNode(original)
	ns.AddNode(replacement)

	got := ns.Node(nodeID)
	require.NotNil(t, got)
	assert.Equal(t, "Replacement", got.BrowseName().Name)

	ns.mu.RLock()
	defer ns.mu.RUnlock()

	require.Len(t, ns.nodes, 1)
	assert.Equal(t, "Replacement", ns.nodes[0].BrowseName().Name)
}

func TestNodeNamespaceAddNodeBindsVariableChangeNotifications(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")
	binding := node.NewValueBinding(int32(1))
	variable := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(ns.ID(), 1005)),
			node.WithBrowseName(ns.NewQualifiedName("Variable")),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Variable")}),
		),
		node.WithVariableType(
			node.NewVariableTypeNode(
				node.WithBase(
					node.WithID(ua.NewNumericNodeID(0, id.BaseDataVariableType)),
					node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BaseDataVariableType"}),
				),
				node.WithDefaultValue(ua.NewNumericNodeID(0, id.Int32), -1, int32(0)),
			),
		),
		node.WithValueBinding(binding),
	)

	ns.AddNode(variable)
	binding.Set(int32(2))

	require.Len(t, srv.changes, 1)
	require.NotNil(t, srv.changes[0])
	assert.True(t, srv.changes[0].Equal(variable.ID()))
}

func TestNodeNamespaceEmitEventDelegatesToServer(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")
	sourceNodeID := ua.NewNumericNodeID(ns.ID(), 1006)
	event := &types.Event{Message: ua.NewLocalizedText("event")}

	require.NoError(t, ns.EmitEvent(t.Context(), sourceNodeID, event))

	require.Len(t, srv.events, 1)
	require.NotNil(t, srv.events[0].sourceNodeID)
	assert.True(t, srv.events[0].sourceNodeID.Equal(sourceNodeID))
	assert.Same(t, event, srv.events[0].event)
}

func TestNodeNamespaceProjectedVariableInstanceBindsMainAndPropertyNotifications(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewNodeNameSpace(srv, "node")
	source := node.NewBinding(struct {
		Value int32
		ID    int32
		Name  string
	}{
		Value: 1,
		ID:    10,
		Name:  "Idle",
	})

	instance := node.NewProjectedVariableInstance(
		source,
		node.ProjectedVariableSpec[struct {
			Value int32
			ID    int32
			Name  string
		}]{
			Base:         node.WithBase(node.WithID(ua.NewNumericNodeID(ns.ID(), 1006)), node.WithBrowseName(ns.NewQualifiedName("CurrentState"))),
			VariableType: newNamespaceNodeTestVariableTypeNode(),
			Value: func(s struct {
				Value int32
				ID    int32
				Name  string
			}) any {
				return s.Value
			},
		},
		node.ProjectedPropertySpec[struct {
			Value int32
			ID    int32
			Name  string
		}]{
			ProjectedVariableSpec: node.ProjectedVariableSpec[struct {
				Value int32
				ID    int32
				Name  string
			}]{
				Base:         node.WithBase(node.WithID(ua.NewNumericNodeID(ns.ID(), 1007)), node.WithBrowseName(ns.NewQualifiedName("Id"))),
				VariableType: newNamespaceNodeTestVariableTypeNode(),
				Value: func(s struct {
					Value int32
					ID    int32
					Name  string
				}) any {
					return s.ID
				},
			},
		},
		node.ProjectedPropertySpec[struct {
			Value int32
			ID    int32
			Name  string
		}]{
			ProjectedVariableSpec: node.ProjectedVariableSpec[struct {
				Value int32
				ID    int32
				Name  string
			}]{
				Base:         node.WithBase(node.WithID(ua.NewNumericNodeID(ns.ID(), 1008)), node.WithBrowseName(ns.NewQualifiedName("Name"))),
				VariableType: newNamespaceNodeTestVariableTypeNode(),
				Value: func(s struct {
					Value int32
					ID    int32
					Name  string
				}) any {
					return s.Name
				},
			},
		},
	)

	ns.AddNode(instance.Main)
	for _, property := range instance.Properties {
		ns.AddNode(property)
	}

	source.Set(struct {
		Value int32
		ID    int32
		Name  string
	}{
		Value: 2,
		ID:    11,
		Name:  "Running",
	})

	require.Len(t, srv.changes, 3)
	assert.True(t, srv.changes[0].Equal(instance.Main.ID()))
	assert.True(t, srv.changes[1].Equal(instance.Properties["Id"].ID()) || srv.changes[2].Equal(instance.Properties["Id"].ID()))
	assert.True(t, srv.changes[1].Equal(instance.Properties["Name"].ID()) || srv.changes[2].Equal(instance.Properties["Name"].ID()))
}

type nodeNamespaceTestNode struct {
	id          *ua.NodeID
	browseName  *ua.QualifiedName
	displayName *ua.LocalizedText
	nodeClass   ua.NodeClass
	refs        types.ReferenceCollection
}

func (n nodeNamespaceTestNode) ID() *ua.NodeID { return n.id }

func (n nodeNamespaceTestNode) BrowseName() *ua.QualifiedName { return n.browseName }

func (n nodeNamespaceTestNode) DisplayName(context.Context) *ua.LocalizedText { return n.displayName }

func (n nodeNamespaceTestNode) NodeClass() ua.NodeClass { return n.nodeClass }

func (n nodeNamespaceTestNode) AddComponent(types.Node) types.Node { return nil }

func (n nodeNamespaceTestNode) AddComponents(...types.Node) types.Node { return nil }

func (n nodeNamespaceTestNode) AddRef(types.ReferenceWrapper) {}

func (n nodeNamespaceTestNode) References() types.ReferenceCollection { return n.refs }

func (n nodeNamespaceTestNode) Attribute(context.Context, ua.AttributeID) (*types.AttrValue, error) {
	return nil, nil
}

func (n nodeNamespaceTestNode) SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error {
	return nil
}

func newNamespaceNodeTestVariableTypeNode() types.VariableTypeNode {
	return node.NewVariableTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.BaseDataVariableType)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BaseDataVariableType"}),
		),
		node.WithDefaultValue(ua.NewNumericNodeID(0, id.Int32), -1, int32(0)),
	)
}
