package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
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

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})
	service := NewMethodService(fixture.backend, func(fn types.MethodFunc) types.MethodFunc { return fn })

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 3},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 3)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
	assert.Nil(t, callResp.Results[0].InputArgumentResults)
}

func TestCallPreservesRequestOrderForMixedSuccessAndFailure(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})
	service := NewMethodService(fixture.backend, func(fn types.MethodFunc) types.MethodFunc { return fn })

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 4},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: ua.NewNumericNodeID(1, 9999),
				MethodID: fixture.methodNode.ID(),
			},
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 4)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 2)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, callResp.Results[0].StatusCode)
	assert.Equal(t, ua.StatusOK, callResp.Results[1].StatusCode)
}

func TestCallReturnsResultsWhenMethodExecutionFails(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusBadInternalError
	})
	service := NewMethodService(fixture.backend, func(fn types.MethodFunc) types.MethodFunc { return fn })

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 5},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 5)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadInternalError, callResp.Results[0].StatusCode)
	assert.Nil(t, callResp.Results[0].InputArgumentResults)
}

func TestCallReturnsBadNotExecutableForNonExecutableMethod(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, false, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		called = true
		return nil, ua.StatusOK
	})
	service := NewMethodService(fixture.backend, func(fn types.MethodFunc) types.MethodFunc { return fn })

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 6},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 6)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadNotExecutable, callResp.Results[0].StatusCode)
	assert.False(t, called)
}

func TestCallUsesIdentityMiddlewareWhenNilMiddlewareProvided(t *testing.T) {
	t.Parallel()

	var called bool
	fixture := newMethodCallFixture(1, 1, true, func(_ context.Context, _ ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		called = true
		return nil, ua.StatusOK
	})
	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 7},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 7)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
	assert.True(t, called)
}

func TestCallReturnsBadMethodInvalidWhenMethodNodeIsMissing(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})
	delete(fixture.backend.namespaces[2].(*methodTestNamespace).nodes, fixture.methodNode.ID().String())

	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 8},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 8)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadMethodInvalid, callResp.Results[0].StatusCode)
}

func TestCallRejectsTooManyOperations(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})
	fixture.backend.cfg = methodTestConfig{maxMethodOperationsPerCall: 1}

	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 9},
		MethodsToCall: []*ua.CallMethodRequest{
			{ObjectID: fixture.objectNode.ID(), MethodID: fixture.methodNode.ID()},
			{ObjectID: fixture.objectNode.ID(), MethodID: fixture.methodNode.ID()},
		},
	}, 9)
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
	assert.Nil(t, resp)
}

func TestCallResolvesMethodDefinedOnObjectType(t *testing.T) {
	t.Parallel()

	called := false
	objectType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 5001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "ObjectType"}),
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
			node.WithID(ua.NewNumericNodeID(1, 2001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Method")}),
		),
		node.Executable(true),
		node.WithHandler(func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			called = true
			return nil, ua.StatusOK
		}),
	)
	objectType.AddComponent(methodNode)

	backend := &methodTestBackend{
		namespaces: map[int]types.NameSpace{
			1: &methodTestNamespace{
				nodes: map[string]types.Node{
					objectNode.ID().String(): objectNode,
					objectType.ID().String(): objectType,
					methodNode.ID().String(): methodNode,
				},
			},
		},
	}
	service := NewMethodService(backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 10},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: objectNode.ID(),
			MethodID: methodNode.ID(),
		}},
	}, 10)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
	assert.True(t, called)
}

func TestCallResolvesMethodInheritedFromBaseObjectType(t *testing.T) {
	t.Parallel()

	called := false
	baseType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 5002)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "BaseType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("BaseType")}),
		),
	)
	derivedType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 5003)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "DerivedType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("DerivedType")}),
		),
	)
	baseType.AddRef(refs.NewReferenceDescription(derivedType, refs.HasSubtypeRefTypeID, true))
	derivedType.AddRef(refs.NewReferenceDescription(baseType, refs.HasSubtypeRefTypeID, false))

	objectNode := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 1002)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Object"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Object")}),
		),
		node.WithType(derivedType),
	)
	methodNode := node.NewMethodNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 2002)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "InheritedMethod"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("InheritedMethod")}),
		),
		node.Executable(true),
		node.WithHandler(func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			called = true
			return nil, ua.StatusOK
		}),
	)
	baseType.AddComponent(methodNode)

	backend := &methodTestBackend{
		namespaces: map[int]types.NameSpace{
			1: &methodTestNamespace{
				nodes: map[string]types.Node{
					objectNode.ID().String():  objectNode,
					baseType.ID().String():    baseType,
					derivedType.ID().String(): derivedType,
					methodNode.ID().String():  methodNode,
				},
			},
		},
	}
	service := NewMethodService(backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 11},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: objectNode.ID(),
			MethodID: methodNode.ID(),
		}},
	}, 11)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
	assert.True(t, called)
}

type methodCallFixture struct {
	backend    *methodTestBackend
	objectNode types.Node
	methodNode types.MethodNode
}

func newMethodCallFixture(objectNamespace, methodNamespace uint16, executable bool, handler types.MethodFunc) *methodCallFixture {
	objectType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, 5000)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "ObjectType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("ObjectType")}),
		),
	)
	objectNode := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(objectNamespace, 1001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: objectNamespace, Name: "Object"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Object")}),
		),
		node.WithType(objectType),
	)
	methodNode := node.NewMethodNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(methodNamespace, 2001)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: methodNamespace, Name: "Method"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Method")}),
		),
		node.Executable(executable),
		node.WithHandler(handler),
	)
	objectNode.AddComponent(methodNode)

	objectNamespaceNode := &methodTestNamespace{
		nodes: map[string]types.Node{
			objectNode.ID().String(): objectNode,
		},
	}
	methodNamespaceNode := objectNamespaceNode
	if objectNamespace != methodNamespace {
		methodNamespaceNode = &methodTestNamespace{nodes: map[string]types.Node{}}
	}
	methodNamespaceNode.nodes[methodNode.ID().String()] = methodNode

	return &methodCallFixture{
		backend: &methodTestBackend{
			namespaces: map[int]types.NameSpace{
				int(objectNamespace): objectNamespaceNode,
				int(methodNamespace): methodNamespaceNode,
			},
		},
		objectNode: objectNode,
		methodNode: methodNode,
	}
}

type methodTestBackend struct {
	namespaces map[int]types.NameSpace
	cfg        types.ServerConfig
}

func (*methodTestBackend) RegisterHandler(int, Handler) {}

func (b *methodTestBackend) Config() types.ServerConfig {
	if b.cfg == nil {
		return methodTestConfig{}
	}
	return b.cfg
}

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

type methodTestConfig struct {
	maxMethodOperationsPerCall uint32
}

func (cfg methodTestConfig) Certificate() []byte { return nil }

func (cfg methodTestConfig) Endpoints() []string { return nil }

func (cfg methodTestConfig) PrivateKey() *rsa.PrivateKey { return nil }

func (cfg methodTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator { return nil }

func (cfg methodTestConfig) ApplicationURI() string { return "" }

func (cfg methodTestConfig) ManufacturerName() string { return "" }

func (cfg methodTestConfig) ProductName() string { return "" }

func (cfg methodTestConfig) SoftwareVersion() string { return "" }

func (cfg methodTestConfig) MaxNodesPerRead() uint32 { return 0 }

func (cfg methodTestConfig) MaxMethodOperationsPerCall() uint32 {
	return cfg.maxMethodOperationsPerCall
}

func (cfg methodTestConfig) MaxBrowseOperationsPerCall() uint32 { return 0 }

func (cfg methodTestConfig) MaxBrowseContinuationPoints() uint32 { return 0 }

func (cfg methodTestConfig) MaxSubscriptions() uint32 { return 0 }

func (cfg methodTestConfig) MaxSubscriptionsPerSession() uint32 { return 0 }

func (cfg methodTestConfig) MaxSubscriptionOperationsPerCall() uint32 { return 0 }

func (cfg methodTestConfig) MinSubscriptionPublishingInterval() time.Duration { return 0 }

func (cfg methodTestConfig) MinSubscriptionMaxKeepAliveCount() uint32 { return 0 }

func (cfg methodTestConfig) MinSubscriptionLifetimeCount() uint32 { return 0 }

func (cfg methodTestConfig) MethodCallMiddleware() types.MethodMiddleware { return nil }
