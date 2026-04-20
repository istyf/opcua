package services

import (
	"context"
	"errors"
	"testing"

	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallReturnsPerMethodStatusForMissingObjectID(t *testing.T) {
	t.Parallel()

	service := NewMethodService(&methodTestBackend{}, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 1},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: nil,
				MethodID: ua.NewNumericNodeID(1, 2001),
			},
		},
	}, 1)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadNodeIDInvalid, callResp.Results[0].StatusCode)
}

func TestCallReturnsPerMethodStatusForMissingMethodID(t *testing.T) {
	t.Parallel()

	service := NewMethodService(&methodTestBackend{}, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 2},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: ua.NewNumericNodeID(1, 1001),
				MethodID: nil,
			},
		},
	}, 2)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadNodeIDInvalid, callResp.Results[0].StatusCode)
}

func TestCallResolvesMethodFromMethodNamespace(t *testing.T) {
	t.Parallel()

	objectType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, 5001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ObjectType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("ObjectType")}),
		),
	)
	objectNode := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 1001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Object"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Object")}),
		),
		node.WithType(objectType),
	)
	methodNode := node.NewMethodNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(2, 2001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "Method"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Method")}),
		),
		node.Executable(true),
		node.WithHandler(func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return nil, ua.StatusOK
		}),
	)
	objectNode.AddComponent(methodNode)

	backend := &methodTestBackend{
		namespaces: map[int]types.NameSpace{
			1: &methodTestNamespace{
				nodes: map[string]types.Node{
					objectNode.ID().String(): objectNode,
				},
			},
			2: &methodTestNamespace{
				nodes: map[string]types.Node{
					methodNode.ID().String(): methodNode,
				},
			},
		},
	}
	service := NewMethodService(backend, func(fn types.MethodFunc) types.MethodFunc { return fn })

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 3},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: objectNode.ID(),
				MethodID: methodNode.ID(),
			},
		},
	}, 3)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
}

type methodTestBackend struct {
	namespaces map[int]types.NameSpace
}

func (*methodTestBackend) RegisterHandler(int, Handler) {}

func (b *methodTestBackend) Namespace(id int) (types.NameSpace, error) {
	if b.namespaces == nil {
		return nil, context.Canceled
	}
	ns, ok := b.namespaces[id]
	if !ok {
		return nil, errors.New("namespace not found")
	}
	return ns, nil
}

type methodTestNamespace struct {
	nodes map[string]types.Node
}

func (*methodTestNamespace) Name() string { return "test" }

func (*methodTestNamespace) AddNode(n types.Node) types.Node { return n }

func (ns *methodTestNamespace) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	return ns.nodes[id.String()]
}

func (*methodTestNamespace) Browse(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
	return nil
}

func (*methodTestNamespace) ID() uint16 { return 0 }

func (*methodTestNamespace) SetID(uint16) {}

func (*methodTestNamespace) Attribute(context.Context, *ua.NodeID, ua.AttributeID) *ua.DataValue {
	return nil
}

func (*methodTestNamespace) SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode {
	return ua.StatusOK
}

func (*methodTestNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{Name: name}
}

func (*methodTestNamespace) NextAvailableID() *ua.NodeID { return ua.NewNumericNodeID(0, 0) }
