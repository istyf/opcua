package services

import (
	"context"
	"testing"

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

type methodTestBackend struct{}

func (*methodTestBackend) RegisterHandler(int, Handler) {}

func (*methodTestBackend) Namespace(int) (types.NameSpace, error) {
	return nil, context.Canceled
}
