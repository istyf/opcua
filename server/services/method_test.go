package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
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

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
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

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
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

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusBadInternalError)
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

func TestCallReturnsRicherMethodResultData(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return &types.MethodResult{
			StatusCode:                   ua.StatusBadInvalidArgument,
			InputArgumentResults:         []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch},
			InputArgumentDiagnosticInfos: []*ua.DiagnosticInfo{{AdditionalInfo: "second argument failed type validation"}},
		}
	})
	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 51},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
				InputArguments: []*ua.Variant{
					ua.MustVariant(int32(1)),
					ua.MustVariant("wrong"),
				},
			},
		},
	}, 51)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadInvalidArgument, callResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch}, callResp.Results[0].InputArgumentResults)
	require.Len(t, callResp.Results[0].InputArgumentDiagnosticInfos, 1)
	require.NotNil(t, callResp.Results[0].InputArgumentDiagnosticInfos[0])
	assert.Equal(t, "second argument failed type validation", callResp.Results[0].InputArgumentDiagnosticInfos[0].AdditionalInfo)
}

func TestCallPropagatesWrapperInputArgumentResultsForTypeMismatch(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, nil)
	node.SetMethod2(fixture.methodNode, func(_ context.Context, _ int32, _ string) error {
		t.Fatal("handler should not be called")
		return nil
	})
	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 53},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
			InputArguments: []*ua.Variant{
				ua.MustVariant(int32(1)),
				ua.MustVariant(true),
			},
		}},
	}, 53)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadTypeMismatch, callResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch}, callResp.Results[0].InputArgumentResults)
}

func TestCallPropagatesWrapperInputArgumentResultsForArgumentCountErrors(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, nil)
	node.SetMethod2(fixture.methodNode, func(_ context.Context, _ int32, _ string) error {
		t.Fatal("handler should not be called")
		return nil
	})
	service := NewMethodService(fixture.backend, nil)

	missingRespRaw, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 54},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
			InputArguments: []*ua.Variant{
				ua.MustVariant(int32(1)),
			},
		}},
	}, 54)
	require.NoError(t, err)

	missingResp, ok := missingRespRaw.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", missingRespRaw)
	require.Len(t, missingResp.Results, 1)
	assert.Equal(t, ua.StatusBadArgumentsMissing, missingResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadArgumentsMissing}, missingResp.Results[0].InputArgumentResults)

	tooManyRespRaw, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 55},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
			InputArguments: []*ua.Variant{
				ua.MustVariant(int32(1)),
				ua.MustVariant("two"),
				ua.MustVariant(true),
			},
		}},
	}, 55)
	require.NoError(t, err)

	tooManyResp, ok := tooManyRespRaw.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", tooManyRespRaw)
	require.Len(t, tooManyResp.Results, 1)
	assert.Equal(t, ua.StatusBadTooManyArguments, tooManyResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusBadTooManyArguments}, tooManyResp.Results[0].InputArgumentResults)
}

func TestCallPanicsWhenMethodHandlerReturnsNilResult(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return nil
	})
	service := NewMethodService(fixture.backend, nil)

	require.PanicsWithValue(t, "method handler returned nil result", func() {
		_, _ = service.Call(t.Context(), nil, &ua.CallRequest{
			RequestHeader: &ua.RequestHeader{RequestHandle: 52},
			MethodsToCall: []*ua.CallMethodRequest{
				{
					ObjectID: fixture.objectNode.ID(),
					MethodID: fixture.methodNode.ID(),
				},
			},
		}, 52)
	})
}

func TestCallReturnsBadNotExecutableForNonExecutableMethod(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, false, func(context.Context, ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
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

func TestCallReturnsBadUserAccessDeniedForUserNonExecutableMethod(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.methodNode.SetUserExecutableHandler(func(context.Context) bool {
		return false
	})

	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 61},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 61)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.NotNil(t, callResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, callResp.ResponseHeader.ServiceResult)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, callResp.Results[0].StatusCode)
	assert.False(t, called)
}

func TestCallAndReadUserExecutableStayConsistentForSameUser(t *testing.T) {
	t.Parallel()

	type contextKey string

	const executableKey contextKey = "method-user-executable"

	session := &methodTestSession{
		user: &auth.AuthenticatedUser{
			UserName: "alice",
			Subject:  "user:alice",
			Roles: []*ua.NodeID{
				ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser),
			},
		},
	}
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.backend.session = session
	fixture.backend.cfg = methodTestConfig{
		authContextDecorator: func(ctx context.Context, user *auth.AuthenticatedUser) context.Context {
			require.Same(t, session.user, user)
			return context.WithValue(ctx, executableKey, false)
		},
	}
	fixture.methodNode.SetUserExecutableHandler(func(ctx context.Context) bool {
		allowed, _ := ctx.Value(executableKey).(bool)
		return allowed
	})

	methodSvc := NewMethodService(fixture.backend, nil)
	attrSvc := NewAttributeService(fixture.backend)

	callRespRaw, err := methodSvc.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       81,
			AuthenticationToken: ua.NewNumericNodeID(1, 9001),
		},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 81)
	require.NoError(t, err)

	callResp, ok := callRespRaw.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", callRespRaw)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, callResp.Results[0].StatusCode)

	readRespRaw, err := attrSvc.Read(t.Context(), nil, &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       82,
			AuthenticationToken: ua.NewNumericNodeID(1, 9001),
		},
		NodesToRead: []*ua.ReadValueID{
			{
				NodeID:      fixture.methodNode.ID(),
				AttributeID: ua.AttributeIDUserExecutable,
			},
		},
	}, 82)
	require.NoError(t, err)

	readResp, ok := readRespRaw.(*ua.ReadResponse)
	require.True(t, ok, "expected *ua.ReadResponse, got %T", readRespRaw)
	require.Len(t, readResp.Results, 1)
	require.NotNil(t, readResp.Results[0])
	require.NotNil(t, readResp.Results[0].Value)
	assert.Equal(t, false, readResp.Results[0].Value.Value())
}

func TestReadUserExecutableCanDifferForDifferentUsers(t *testing.T) {
	t.Parallel()

	type contextKey string

	const userNameKey contextKey = "user-name"

	session := &methodTestSession{}
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.backend.session = session
	fixture.backend.cfg = methodTestConfig{
		authContextDecorator: func(ctx context.Context, user *auth.AuthenticatedUser) context.Context {
			if user == nil {
				return ctx
			}
			return context.WithValue(ctx, userNameKey, user.UserName)
		},
	}
	fixture.methodNode.SetUserExecutableHandler(func(ctx context.Context) bool {
		userName, _ := ctx.Value(userNameKey).(string)
		return userName == "alice"
	})

	attrSvc := NewAttributeService(fixture.backend)
	readUserExecutable := func(t *testing.T, userName string) bool {
		t.Helper()

		session.user = &auth.AuthenticatedUser{
			UserName: userName,
			Subject:  "user:" + userName,
			Roles: []*ua.NodeID{
				ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser),
			},
		}

		respRaw, err := attrSvc.Read(t.Context(), nil, &ua.ReadRequest{
			RequestHeader: &ua.RequestHeader{
				RequestHandle:       83,
				AuthenticationToken: ua.NewNumericNodeID(1, 9002),
			},
			NodesToRead: []*ua.ReadValueID{
				{
					NodeID:      fixture.methodNode.ID(),
					AttributeID: ua.AttributeIDUserExecutable,
				},
			},
		}, 83)
		require.NoError(t, err)

		resp, ok := respRaw.(*ua.ReadResponse)
		require.True(t, ok, "expected *ua.ReadResponse, got %T", respRaw)
		require.Len(t, resp.Results, 1)
		require.NotNil(t, resp.Results[0])
		require.NotNil(t, resp.Results[0].Value)
		value, ok := resp.Results[0].Value.Value().(bool)
		require.True(t, ok, "expected bool UserExecutable value, got %T", resp.Results[0].Value.Value())
		return value
	}

	assert.True(t, readUserExecutable(t, "alice"))
	assert.False(t, readUserExecutable(t, "bob"))
}

func TestReadExecutableStaysStaticWhileUserExecutableIsDynamic(t *testing.T) {
	t.Parallel()

	type contextKey string

	const executableKey contextKey = "method-user-executable"

	session := &methodTestSession{
		user: &auth.AuthenticatedUser{
			UserName: "alice",
			Subject:  "user:alice",
			Roles: []*ua.NodeID{
				ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser),
			},
		},
	}
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.backend.session = session
	fixture.backend.cfg = methodTestConfig{
		authContextDecorator: func(ctx context.Context, user *auth.AuthenticatedUser) context.Context {
			require.Same(t, session.user, user)
			return context.WithValue(ctx, executableKey, false)
		},
	}
	fixture.methodNode.SetUserExecutable(true)
	fixture.methodNode.SetUserExecutableHandler(func(ctx context.Context) bool {
		allowed, _ := ctx.Value(executableKey).(bool)
		return allowed
	})

	attrSvc := NewAttributeService(fixture.backend)

	readAttribute := func(t *testing.T, attributeID ua.AttributeID) bool {
		t.Helper()

		respRaw, err := attrSvc.Read(t.Context(), nil, &ua.ReadRequest{
			RequestHeader: &ua.RequestHeader{
				RequestHandle:       84,
				AuthenticationToken: ua.NewNumericNodeID(1, 9003),
			},
			NodesToRead: []*ua.ReadValueID{
				{
					NodeID:      fixture.methodNode.ID(),
					AttributeID: attributeID,
				},
			},
		}, 84)
		require.NoError(t, err)

		resp, ok := respRaw.(*ua.ReadResponse)
		require.True(t, ok, "expected *ua.ReadResponse, got %T", respRaw)
		require.Len(t, resp.Results, 1)
		require.NotNil(t, resp.Results[0])
		require.NotNil(t, resp.Results[0].Value)
		value, ok := resp.Results[0].Value.Value().(bool)
		require.True(t, ok, "expected bool attribute value, got %T", resp.Results[0].Value.Value())
		return value
	}

	assert.True(t, readAttribute(t, ua.AttributeIDExecutable))
	assert.False(t, readAttribute(t, ua.AttributeIDUserExecutable))
}

func TestCallUsesIdentityMiddlewareWhenNilMiddlewareProvided(t *testing.T) {
	t.Parallel()

	var called bool
	fixture := newMethodCallFixture(1, 1, true, func(_ context.Context, _ ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
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

func TestCallDecoratesHandlerContextFromAuthenticatedUser(t *testing.T) {
	t.Parallel()

	type contextKey string

	const (
		userNameKey contextKey = "user-name"
		roleKey     contextKey = "role-id"
	)

	expectedUser := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
		Roles: []*ua.NodeID{
			ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser),
		},
		Attributes: map[string]any{
			"department": "ops",
		},
	}

	var gotUserName string
	var gotRoleID string
	fixture := newMethodCallFixture(1, 1, true, func(ctx context.Context, _ ...*ua.Variant) *types.MethodResult {
		gotUserName, _ = ctx.Value(userNameKey).(string)
		gotRoleID, _ = ctx.Value(roleKey).(string)
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.backend.session = &methodTestSession{user: expectedUser}
	fixture.backend.cfg = methodTestConfig{
		authContextDecorator: func(ctx context.Context, user *auth.AuthenticatedUser) context.Context {
			require.Same(t, expectedUser, user)
			ctx = context.WithValue(ctx, userNameKey, user.UserName)
			return context.WithValue(ctx, roleKey, user.Roles[0].String())
		},
	}

	service := NewMethodService(fixture.backend, nil)

	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       71,
			AuthenticationToken: ua.NewNumericNodeID(1, 9001),
		},
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: fixture.objectNode.ID(),
				MethodID: fixture.methodNode.ID(),
			},
		},
	}, 71)
	require.NoError(t, err)

	callResp, ok := resp.(*ua.CallResponse)
	require.True(t, ok, "expected *ua.CallResponse, got %T", resp)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
	assert.Equal(t, "alice", gotUserName)
	assert.Equal(t, ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser).String(), gotRoleID)
}

func TestCallPanicsWhenAuthorizationContextDecoratorReturnsNil(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
	})
	fixture.backend.session = &methodTestSession{
		user: &auth.AuthenticatedUser{
			UserName: "alice",
			Subject:  "user:alice",
			Roles: []*ua.NodeID{
				ua.NewNumericNodeID(0, id.WellKnownRole_AuthenticatedUser),
			},
		},
	}
	fixture.backend.cfg = methodTestConfig{
		authContextDecorator: func(context.Context, *auth.AuthenticatedUser) context.Context {
			return nil
		},
	}

	service := NewMethodService(fixture.backend, nil)

	require.PanicsWithValue(t,
		"server authorization context decorator returned nil context",
		func() {
			_, _ = service.Call(t.Context(), nil, &ua.CallRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       72,
					AuthenticationToken: ua.NewNumericNodeID(1, 9002),
				},
				MethodsToCall: []*ua.CallMethodRequest{
					{
						ObjectID: fixture.objectNode.ID(),
						MethodID: fixture.methodNode.ID(),
					},
				},
			}, 72)
		},
	)
}

func TestCallReturnsBadMethodInvalidWhenMethodNodeIsMissing(t *testing.T) {
	t.Parallel()

	fixture := newMethodCallFixture(1, 2, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
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

	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		return types.NewMethodResult(ua.StatusOK)
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
		node.WithHandler(func(context.Context, ...*ua.Variant) *types.MethodResult {
			called = true
			return types.NewMethodResult(ua.StatusOK)
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
		node.WithHandler(func(context.Context, ...*ua.Variant) *types.MethodResult {
			called = true
			return types.NewMethodResult(ua.StatusOK)
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

func TestCallValidatesInputArgumentsMetadataForMissingArguments(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
	})
	addMethodInputArgumentsProperty(t, fixture, &ua.Argument{
		Name:      "value",
		DataType:  ua.NewNumericNodeID(0, id.Int32),
		ValueRank: -1,
	})

	service := NewMethodService(fixture.backend, nil)
	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 12},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
		}},
	}, 12)
	require.NoError(t, err)

	callResp := resp.(*ua.CallResponse)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadArgumentsMissing, callResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadArgumentsMissing}, callResp.Results[0].InputArgumentResults)
	assert.False(t, called)
}

func TestCallValidatesInputArgumentsMetadataForTypeMismatch(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
	})
	addMethodInputArgumentsProperty(t, fixture, &ua.Argument{
		Name:      "value",
		DataType:  ua.NewNumericNodeID(0, id.Int32),
		ValueRank: -1,
	})

	service := NewMethodService(fixture.backend, nil)
	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 13},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
			InputArguments: []*ua.Variant{
				ua.MustVariant("wrong"),
			},
		}},
	}, 13)
	require.NoError(t, err)

	callResp := resp.(*ua.CallResponse)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadTypeMismatch, callResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch}, callResp.Results[0].InputArgumentResults)
	assert.False(t, called)
}

func TestCallValidatesInputArgumentsMetadataForTooManyArguments(t *testing.T) {
	t.Parallel()

	called := false
	fixture := newMethodCallFixture(1, 1, true, func(context.Context, ...*ua.Variant) *types.MethodResult {
		called = true
		return types.NewMethodResult(ua.StatusOK)
	})
	addMethodInputArgumentsProperty(t, fixture, &ua.Argument{
		Name:      "value",
		DataType:  ua.NewNumericNodeID(0, id.Int32),
		ValueRank: -1,
	})

	service := NewMethodService(fixture.backend, nil)
	resp, err := service.Call(t.Context(), nil, &ua.CallRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 14},
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: fixture.objectNode.ID(),
			MethodID: fixture.methodNode.ID(),
			InputArguments: []*ua.Variant{
				ua.MustVariant(int32(1)),
				ua.MustVariant(true),
			},
		}},
	}, 14)
	require.NoError(t, err)

	callResp := resp.(*ua.CallResponse)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadTooManyArguments, callResp.Results[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTooManyArguments}, callResp.Results[0].InputArgumentResults)
	assert.False(t, called)
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

func addMethodInputArgumentsProperty(t *testing.T, fixture *methodCallFixture, args ...*ua.Argument) {
	t.Helper()

	varType := node.NewVariableTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.PropertyType)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "PropertyType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("PropertyType")}),
		),
		node.WithDefaultValue(ua.NewNumericNodeID(0, id.Argument), 1, []*ua.ExtensionObject{}),
	)

	extObjs := make([]*ua.ExtensionObject, 0, len(args))
	for _, arg := range args {
		extObjs = append(extObjs, ua.NewExtensionObject(arg))
	}

	property := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(fixture.methodNode.ID().Namespace(), 3000+uint32(len(args)))),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "InputArguments"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("InputArguments")}),
		),
		node.WithVariableType(varType),
		node.WithDataType(ua.NewNumericNodeID(0, id.Argument)),
		node.WithValueRank(1),
		node.WithValue(extObjs),
	)

	fixture.methodNode.AddRef(refs.NewReferenceDescription(property, refs.HasPropertyRefTypeID, true))
	property.AddRef(refs.NewReferenceDescription(fixture.methodNode, refs.HasPropertyRefTypeID, false))

	objectNS, err := fixture.backend.Namespace(int(fixture.objectNode.ID().Namespace()))
	require.NoError(t, err)
	ns, ok := objectNS.(*methodTestNamespace)
	require.True(t, ok)
	ns.nodes[property.ID().String()] = property
}

type methodTestBackend struct {
	namespaces map[int]types.NameSpace
	session    types.Session
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

func (b *methodTestBackend) Namespaces() []types.NameSpace {
	namespaces := make([]types.NameSpace, 0, len(b.namespaces))
	for _, ns := range b.namespaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

func (b *methodTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
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

func (ns *methodTestNamespace) Attribute(ctx context.Context, id *ua.NodeID, attr ua.AttributeID) *ua.DataValue {
	node := ns.Node(id)
	if node == nil {
		return &ua.DataValue{Status: ua.StatusBadNodeIDUnknown}
	}

	value, err := node.Attribute(ctx, attr)
	if err != nil {
		if status, ok := err.(ua.StatusCode); ok {
			return &ua.DataValue{Status: status}
		}
		return &ua.DataValue{Status: ua.StatusBadAttributeIDInvalid}
	}

	return value.Value
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
	authContextDecorator       auth.AuthorizationContextDecorator
}

func (cfg methodTestConfig) Certificate() []byte { return nil }

func (cfg methodTestConfig) Endpoints() []string { return nil }

func (cfg methodTestConfig) PrivateKey() *rsa.PrivateKey { return nil }

func (cfg methodTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator { return nil }

func (cfg methodTestConfig) AuthorizationContextDecorator() auth.AuthorizationContextDecorator {
	return cfg.authContextDecorator
}

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

type methodTestSession struct {
	user *auth.AuthenticatedUser
}

func (*methodTestSession) AuthTokenID() *ua.NodeID { return nil }

func (*methodTestSession) ID() *ua.NodeID { return nil }

func (*methodTestSession) Locales() []string { return nil }

func (*methodTestSession) SetLocales([]string) {}

func (*methodTestSession) RemoteCertificate() []byte { return nil }

func (*methodTestSession) ServerNonce() []byte { return nil }

func (*methodTestSession) SetServerNonce([]byte) {}

func (*methodTestSession) TimeOutInMillis() float64 { return 0 }

func (*methodTestSession) Activated() bool { return true }

func (*methodTestSession) SetActivated(bool) {}

func (*methodTestSession) IsSameAs(types.Session) bool { return false }

func (s *methodTestSession) AuthenticatedUser() *auth.AuthenticatedUser { return s.user }

func (*methodTestSession) PublishRequestChannel() chan types.PubReq { return nil }
