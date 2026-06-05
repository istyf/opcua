package services

import (
	"context"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSubscriptionRevisesPublishingInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		minimum   time.Duration
		requested float64
		want      float64
	}{
		{name: "negative uses default fastest supported", requested: -1, want: defaultMinSupportedPublishingIntervalMS},
		{name: "zero uses default fastest supported", requested: 0, want: defaultMinSupportedPublishingIntervalMS},
		{name: "below default minimum clamps to fastest supported", requested: 250, want: defaultMinSupportedPublishingIntervalMS},
		{name: "above default minimum is preserved", requested: 1500, want: 1500},
		{name: "configured minimum is used for zero request", minimum: 200 * time.Millisecond, requested: 0, want: 200},
		{name: "configured minimum clamps positive request", minimum: 200 * time.Millisecond, requested: 150, want: 200},
		{name: "configured minimum preserves larger request", minimum: 200 * time.Millisecond, requested: 350, want: 350},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := newSubscriptionTestSession()
			backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
				minSubscriptionPublishingInterval: tt.minimum,
			})
			service := NewSubscriptionService(backend)
			sc := newTestSecureChannel(t)

			req := newCreateSubscriptionRequest(session, 10)
			req.RequestedPublishingInterval = tt.requested

			resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
			require.NoError(t, err)

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)
			assert.Equal(t, tt.want, createResp.RevisedPublishingInterval)

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
	}
}

func TestCreateSubscriptionRevisesMaxKeepAliveCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		minimum   uint32
		requested uint32
		want      uint32
	}{
		{name: "zero uses default smallest supported", requested: 0, want: DefaultMinSubscriptionMaxKeepAliveCount},
		{name: "below default minimum clamps to default", requested: 1, want: DefaultMinSubscriptionMaxKeepAliveCount},
		{name: "configured minimum is used for zero request", minimum: 3, requested: 0, want: 3},
		{name: "configured minimum clamps smaller request", minimum: 3, requested: 1, want: 3},
		{name: "configured minimum preserves larger request", minimum: 3, requested: 5, want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := newSubscriptionTestSession()
			backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
				minSubscriptionMaxKeepAliveCount: tt.minimum,
			})
			service := NewSubscriptionService(backend)
			sc := newTestSecureChannel(t)

			req := newCreateSubscriptionRequest(session, 12)
			req.RequestedMaxKeepAliveCount = tt.requested

			resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
			require.NoError(t, err)

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)
			assert.Equal(t, tt.want, createResp.RevisedMaxKeepAliveCount)

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
	}
}

func TestCreateSubscriptionRevisesLifetimeCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		minimum       uint32
		requestedKeep uint32
		requestedLife uint32
		want          uint32
	}{
		{name: "zero uses default minimum lifetime", requestedKeep: DefaultMinSubscriptionMaxKeepAliveCount, requestedLife: 0, want: DefaultMinSubscriptionLifetimeCount},
		{name: "below three times keepalive clamps to spec minimum", requestedKeep: 12, requestedLife: 20, want: 36},
		{name: "configured minimum beats spec minimum when higher", minimum: 50, requestedKeep: 10, requestedLife: 20, want: 50},
		{name: "configured minimum is used for zero request", minimum: 45, requestedKeep: 10, requestedLife: 0, want: 45},
		{name: "larger requested lifetime is preserved", minimum: 30, requestedKeep: 10, requestedLife: 80, want: 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := newSubscriptionTestSession()
			backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
				minSubscriptionLifetimeCount: tt.minimum,
			})
			service := NewSubscriptionService(backend)
			sc := newTestSecureChannel(t)

			req := newCreateSubscriptionRequest(session, 14)
			req.RequestedMaxKeepAliveCount = tt.requestedKeep
			req.RequestedLifetimeCount = tt.requestedLife

			resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
			require.NoError(t, err)

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)
			assert.Equal(t, tt.want, createResp.RevisedLifetimeCount)

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
	}
}

func TestSubscriptionServiceShutdownStopsRunningSubscriptions(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	resp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 1), 1)
	require.NoError(t, err)

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)

	subID := types.SubscriptionID(createResp.SubscriptionID)
	sub, ok := service.Get(subID)
	require.True(t, ok, "expected subscription %d to exist", subID)
	require.NotNil(t, sub)

	require.NoError(t, service.Shutdown(t.Context()))

	select {
	case <-sub.done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for subscription goroutine to stop")
	}

	sub.Mu.Lock()
	running := sub.running
	sub.Mu.Unlock()
	assert.False(t, running)
}

func TestCreateSubscriptionIgnoresCreateRequestContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	resp, err := service.CreateSubscription(ctx, sc, newCreateSubscriptionRequest(session, 2), 1)
	require.NoError(t, err)

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)

	subID := types.SubscriptionID(createResp.SubscriptionID)
	sub, ok := service.Get(subID)
	require.True(t, ok, "expected subscription %d to exist", subID)
	require.NotNil(t, sub)

	cancel()

	time.Sleep(50 * time.Millisecond)

	sub.Mu.Lock()
	running := sub.running
	sub.Mu.Unlock()
	assert.True(t, running)

	service.DeleteSubscription(t.Context(), subID)

	select {
	case <-sub.done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for subscription goroutine to stop")
	}
}

func TestModifySubscriptionRevisesParametersAndUpdatesRuntimeState(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
		minSubscriptionPublishingInterval: 200 * time.Millisecond,
		minSubscriptionMaxKeepAliveCount:  3,
		minSubscriptionLifetimeCount:      20,
	})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 70), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       71,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionID:              created.SubscriptionID,
		RequestedPublishingInterval: 150,
		RequestedLifetimeCount:      5,
		RequestedMaxKeepAliveCount:  1,
		MaxNotificationsPerPublish:  7,
		Priority:                    9,
	}, 2)
	require.NoError(t, err)

	modified, ok := resp.(*ua.ModifySubscriptionResponse)
	require.True(t, ok, "expected ModifySubscriptionResponse, got %T", resp)
	assert.Equal(t, float64(200), modified.RevisedPublishingInterval)
	assert.Equal(t, uint32(3), modified.RevisedMaxKeepAliveCount)
	assert.Equal(t, uint32(20), modified.RevisedLifetimeCount)

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	require.True(t, ok, "expected subscription to exist")
	assert.Equal(t, modified.RevisedPublishingInterval, sub.RevisedPublishingInterval)
	assert.Equal(t, modified.RevisedMaxKeepAliveCount, sub.RevisedMaxKeepAliveCount)
	assert.Equal(t, modified.RevisedLifetimeCount, sub.RevisedLifetimeCount)
	assert.Equal(t, uint32(7), sub.MaxNotificationsPerPublish)
	assert.Equal(t, byte(9), sub.Priority)

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestModifySubscriptionRejectsMissingSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 72), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	backend.session = nil
	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       73,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionID: created.SubscriptionID,
	}, 2)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, err)

	backend.session = session
	service.DeleteSubscription(t.Context(), types.SubscriptionID(created.SubscriptionID))
}

func TestModifySubscriptionRejectsUnknownSubscription(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       74,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionID: 999,
	}, 1)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSubscriptionIDInvalid, err)
}

func TestModifySubscriptionRejectsDifferentSession(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	otherSession := newSubscriptionTestSession()
	otherSession.authToken = ua.NewNumericNodeID(1, 505)

	backend := newSubscriptionTestBackend(ownerSession)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(ownerSession, 75), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	backend.session = otherSession
	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       76,
			AuthenticationToken: otherSession.AuthTokenID(),
		},
		SubscriptionID: created.SubscriptionID,
	}, 2)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, err)

	backend.session = ownerSession
	service.DeleteSubscription(t.Context(), types.SubscriptionID(created.SubscriptionID))
}

func TestSetPublishingModeUpdatesRuntimeSubscription(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createReq := newCreateSubscriptionRequest(session, 80)
	createReq.PublishingEnabled = true

	createResp, err := service.CreateSubscription(t.Context(), sc, createReq, 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       81,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID},
	}, 2)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	require.Len(t, setResp.Results, 1)
	assert.Equal(t, ua.StatusOK, setResp.Results[0])

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	require.True(t, ok, "expected subscription to exist")
	assert.False(t, sub.PublishingEnabled)

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestSetPublishingModeRejectsMissingSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 82), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	backend.session = nil
	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       83,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID},
	}, 2)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	require.Len(t, setResp.Results, 1)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, setResp.Results[0])

	backend.session = session
	service.DeleteSubscription(t.Context(), types.SubscriptionID(created.SubscriptionID))
}

func TestSetPublishingModeRejectsUnknownSubscription(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       84,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{999},
	}, 1)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	require.Len(t, setResp.Results, 1)
	assert.Equal(t, ua.StatusBadSubscriptionIDInvalid, setResp.Results[0])
}

func TestSetPublishingModeRejectsDifferentSession(t *testing.T) {
	t.Parallel()

	owner := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(owner)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(owner, 85), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	other := newSubscriptionTestSession()
	other.authToken = ua.NewNumericNodeID(1, 303)
	backend.session = other

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       86,
			AuthenticationToken: other.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID},
	}, 2)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	require.Len(t, setResp.Results, 1)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, setResp.Results[0])

	backend.session = owner
	service.DeleteSubscription(t.Context(), types.SubscriptionID(created.SubscriptionID))
}

func TestSetPublishingModeRejectsEmptySubscriptionList(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	_, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       87,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   nil,
	}, 1)
	assert.Equal(t, ua.StatusBadNothingToDo, err)
}

func TestSetPublishingModeRejectsTooManyOperations(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
		maxSubscriptionOperationsPerCall: 1,
	})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 88), 1)
	require.NoError(t, err)
	first, ok := firstResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", firstResp)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 89), 2)
	require.NoError(t, err)
	second, ok := secondResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", secondResp)

	_, err = service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       90,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{first.SubscriptionID, second.SubscriptionID},
	}, 3)
	assert.Equal(t, ua.StatusBadTooManyOperations, err)

	service.DeleteSubscription(t.Context(), types.SubscriptionID(first.SubscriptionID))
	service.DeleteSubscription(t.Context(), types.SubscriptionID(second.SubscriptionID))
}

func TestSetPublishingModeMixedBatchResults(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 91), 1)
	require.NoError(t, err)
	first, ok := firstResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", firstResp)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 92), 2)
	require.NoError(t, err)
	second, ok := secondResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", secondResp)

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       93,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{first.SubscriptionID, 999, second.SubscriptionID},
	}, 3)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	want := []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid, ua.StatusOK}
	require.Len(t, setResp.Results, len(want))
	for i := range want {
		assert.Equal(t, want[i], setResp.Results[i], "result %d", i)
	}

	firstSub, ok := service.Get(types.SubscriptionID(first.SubscriptionID))
	require.True(t, ok, "expected first subscription to exist")
	assert.False(t, firstSub.PublishingEnabled)

	secondSub, ok := service.Get(types.SubscriptionID(second.SubscriptionID))
	require.True(t, ok, "expected second subscription to exist")
	assert.False(t, secondSub.PublishingEnabled)

	service.DeleteSubscription(t.Context(), firstSub.ID)
	service.DeleteSubscription(t.Context(), secondSub.ID)
}

func TestSetPublishingModePreservesRequestOrderWithDuplicateIDs(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 94), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       95,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID, 999, created.SubscriptionID},
	}, 2)
	require.NoError(t, err)

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	require.True(t, ok, "expected SetPublishingModeResponse, got %T", resp)
	want := []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid, ua.StatusOK}
	require.Len(t, setResp.Results, len(want))
	for i := range want {
		assert.Equal(t, want[i], setResp.Results[i], "result %d", i)
	}

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	require.True(t, ok, "expected subscription to exist")
	assert.False(t, sub.PublishingEnabled)

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestCreateSubscriptionRejectsMissingSession(t *testing.T) {
	t.Parallel()

	backend := newSubscriptionTestBackend(nil)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       11,
			AuthenticationToken: ua.NewNumericNodeID(1, 999),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, err)
	if got := len(service.subs); got != 0 {
		assert.Equal(t, 0, got)
	}
}

func TestCreateSubscriptionCreatesSubscriptionForValidSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       22,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
	require.NoError(t, err)

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)
	assert.NotZero(t, createResp.SubscriptionID)
	require.NotNil(t, createResp.ResponseHeader)
	assert.Equal(t, ua.StatusOK, createResp.ResponseHeader.ServiceResult)

	sub, ok := service.Get(types.SubscriptionID(createResp.SubscriptionID))
	require.True(t, ok, "expected subscription to be registered")
	assert.Same(t, session, sub.session)

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestCreateSubscriptionPanicsWithoutSecureChannel(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       33,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	defer func() {
		assert.NotNil(t, recover())
	}()

	_, _ = service.CreateSubscription(t.Context(), nil, req, 1)
}

func TestCreateSubscriptionDoesNotReuseDeletedIDs(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 44), 1)
	require.NoError(t, err)
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", firstResp)

	firstID := types.SubscriptionID(firstCreateResp.SubscriptionID)
	service.DeleteSubscription(t.Context(), firstID)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 45), 2)
	require.NoError(t, err)
	secondCreateResp, ok := secondResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", secondResp)

	assert.NotEqual(t, firstCreateResp.SubscriptionID, secondCreateResp.SubscriptionID)
	assert.Greater(t, secondCreateResp.SubscriptionID, firstCreateResp.SubscriptionID)

	service.DeleteSubscription(t.Context(), types.SubscriptionID(secondCreateResp.SubscriptionID))
}

func TestCreateSubscriptionStoresNegotiatedRuntimeParameters(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	req := newCreateSubscriptionRequest(session, 55)
	req.MaxNotificationsPerPublish = 42
	req.PublishingEnabled = false
	req.Priority = 7

	resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
	require.NoError(t, err)

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", resp)

	sub, ok := service.Get(types.SubscriptionID(createResp.SubscriptionID))
	require.True(t, ok, "expected subscription to be registered")
	assert.Equal(t, req.MaxNotificationsPerPublish, sub.MaxNotificationsPerPublish)
	assert.Equal(t, req.PublishingEnabled, sub.PublishingEnabled)
	assert.Equal(t, req.Priority, sub.Priority)

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestCreateSubscriptionRespectsServerSubscriptionLimit(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
		maxSubscriptions: 1,
	})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 60), 1)
	require.NoError(t, err)
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", firstResp)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 61), 2)
	assert.Nil(t, secondResp)
	assert.Equal(t, ua.StatusBadTooManySubscriptions, err)

	service.DeleteSubscription(t.Context(), types.SubscriptionID(firstCreateResp.SubscriptionID))
}

func TestCreateSubscriptionRespectsPerSessionSubscriptionLimit(t *testing.T) {
	t.Parallel()

	firstSession := newSubscriptionTestSession()
	secondSession := newSubscriptionTestSession()
	secondSession.authToken = ua.NewNumericNodeID(1, 303)

	backend := newSubscriptionTestBackend(firstSession, subscriptionTestConfigOptions{
		maxSubscriptionsPerSession: 1,
	})
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(firstSession, 62), 1)
	require.NoError(t, err)
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", firstResp)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(firstSession, 63), 2)
	assert.Nil(t, secondResp)
	assert.Equal(t, ua.StatusBadTooManySubscriptions, err)

	backend.session = secondSession
	thirdResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(secondSession, 64), 3)
	require.NoError(t, err)
	thirdCreateResp, ok := thirdResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", thirdResp)

	service.DeleteSubscription(t.Context(), types.SubscriptionID(firstCreateResp.SubscriptionID))
	service.DeleteSubscription(t.Context(), types.SubscriptionID(thirdCreateResp.SubscriptionID))
}

func TestDeleteSubscriptionsRejectsMissingSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 65), 1)
	require.NoError(t, err)
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	require.True(t, ok, "expected CreateSubscriptionResponse, got %T", createResp)

	backend.session = nil
	resp, err := service.DeleteSubscriptions(t.Context(), sc, &ua.DeleteSubscriptionsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       66,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionIDs: []uint32{created.SubscriptionID},
	}, 2)
	require.NoError(t, err)

	deleteResp, ok := resp.(*ua.DeleteSubscriptionsResponse)
	require.True(t, ok, "expected DeleteSubscriptionsResponse, got %T", resp)
	require.Len(t, deleteResp.Results, 1)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, deleteResp.Results[0])

	backend.session = session
	service.DeleteSubscription(t.Context(), types.SubscriptionID(created.SubscriptionID))
}

func TestSubscriptionCanPublishNotifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		publishingEnabled bool
		pendingCount      int
		want              bool
	}{
		{name: "disabled with pending notifications does not publish", publishingEnabled: false, pendingCount: 1, want: false},
		{name: "disabled with no notifications does not publish", publishingEnabled: false, pendingCount: 0, want: false},
		{name: "enabled with no notifications does not publish", publishingEnabled: true, pendingCount: 0, want: false},
		{name: "enabled with pending notifications publishes", publishingEnabled: true, pendingCount: 1, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sub := &Subscription{PublishingEnabled: tt.publishingEnabled}
			assert.Equal(t, tt.want, sub.canPublishNotifications(tt.pendingCount))
		})
	}
}

func TestSubscriptionNextPublishBatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		maxPerPublish uint32
		queueSize     int
		wantBatchSize int
		wantRemaining int
		wantMore      bool
	}{
		{name: "unlimited publishes everything", maxPerPublish: 0, queueSize: 3, wantBatchSize: 3, wantRemaining: 0, wantMore: false},
		{name: "limit publishes one batch and keeps the rest", maxPerPublish: 2, queueSize: 5, wantBatchSize: 2, wantRemaining: 3, wantMore: true},
		{name: "limit equal to queue drains queue", maxPerPublish: 3, queueSize: 3, wantBatchSize: 3, wantRemaining: 0, wantMore: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sub := NewSubscription()
			sub.MaxNotificationsPerPublish = tt.maxPerPublish
			for i := range tt.queueSize {
				id := uint32(i + 1)
				sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(id, id))
			}

			batch, more := sub.nextPublishBatch()
			assert.Equal(t, tt.wantBatchSize, batch.Len())
			assert.Equal(t, tt.wantRemaining, sub.publishQueue.Len())
			assert.Equal(t, tt.wantMore, more)
		})
	}
}

func TestSubscriptionNextPublishBatchGroupsNotificationKinds(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.MaxNotificationsPerPublish = 3
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	sub.publishQueue.Enqueue(subscriptionTestEventNotification(2, 22, "first"))
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(3, 33))
	sub.publishQueue.Enqueue(subscriptionTestEventNotification(4, 44, "second"))

	batch, more := sub.nextPublishBatch()

	require.Equal(t, 3, batch.Len())
	assert.True(t, more)
	assert.Len(t, batch.dataChanges, 2)
	assert.Len(t, batch.events, 1)
	assert.Equal(t, uint32(11), batch.dataChanges[0].ClientHandle)
	assert.Equal(t, uint32(33), batch.dataChanges[1].ClientHandle)
	assert.Equal(t, uint32(22), batch.events[0].ClientHandle)
	assert.Equal(t, 1, sub.publishQueue.Len())
}

func TestSubscriptionNotificationDataForPublishBatchIncludesEvents(t *testing.T) {
	t.Parallel()

	batch := subscriptionPublishBatch{
		dataChanges: []*ua.MonitoredItemNotification{
			{ClientHandle: 11, Value: &ua.DataValue{Value: ua.MustVariant("data")}},
		},
		events: []*ua.EventFieldList{
			{ClientHandle: 22, EventFields: []*ua.Variant{ua.MustVariant("event")}},
		},
	}

	notificationData := notificationDataForPublishBatch(batch)

	require.Len(t, notificationData, 2)
	dataChanges, ok := notificationData[0].Value.(*ua.DataChangeNotification)
	require.True(t, ok, "expected DataChangeNotification, got %T", notificationData[0].Value)
	require.Len(t, dataChanges.MonitoredItems, 1)
	assert.Equal(t, uint32(11), dataChanges.MonitoredItems[0].ClientHandle)

	events, ok := notificationData[1].Value.(*ua.EventNotificationList)
	require.True(t, ok, "expected EventNotificationList, got %T", notificationData[1].Value)
	require.Len(t, events.Events, 1)
	assert.Equal(t, uint32(22), events.Events[0].ClientHandle)
}

func TestSubscriptionNotificationQueueCoalescesDataChangesByMonitoredItem(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	queue.Enqueue(subscriptionTestDataChangeNotification(1, 22))

	assert.Equal(t, 1, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 1)
	require.NotNil(t, batch[0].dataChange)
	assert.Equal(t, uint32(22), batch[0].dataChange.ClientHandle)
}

func TestSubscriptionNotificationQueueRespectsEventQueueSizeDiscardOldest(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 11, "first", 2, true))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 22, "second", 2, true))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 33, "third", 2, true))

	assert.Equal(t, 2, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 2)
	assert.Equal(t, uint32(22), batch[0].event.ClientHandle)
	assert.Equal(t, uint32(33), batch[1].event.ClientHandle)
}

func TestSubscriptionNotificationQueueRespectsEventQueueSizeDiscardNewest(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 11, "first", 2, false))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 22, "second", 2, false))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 33, "third", 2, false))

	assert.Equal(t, 2, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 2)
	assert.Equal(t, uint32(11), batch[0].event.ClientHandle)
	assert.Equal(t, uint32(22), batch[1].event.ClientHandle)
}

func TestSubscriptionNotificationQueueSizeOneDiscardOldestKeepsNewestEvent(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "old", 1, true))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "new", 1, true))

	assert.Equal(t, 1, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 1)
	require.NotNil(t, batch[0].event)
	require.Len(t, batch[0].event.EventFields, 1)
	assert.Equal(t, "new", batch[0].event.EventFields[0].String())
}

func TestSubscriptionNotificationQueueSizeOneDiscardNewestKeepsOldestEvent(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "old", 1, false))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "new", 1, false))

	assert.Equal(t, 1, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 1)
	require.NotNil(t, batch[0].event)
	require.Len(t, batch[0].event.EventFields, 1)
	assert.Equal(t, "old", batch[0].event.EventFields[0].String())
}

func TestSubscriptionNotificationQueueKeepsMultipleEventsWithSameClientHandle(t *testing.T) {
	t.Parallel()

	queue := newSubscriptionNotificationQueue()
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "first", 2, true))
	queue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 55, "second", 2, true))

	assert.Equal(t, 2, queue.Len())
	batch, more := queue.Drain(0)
	require.False(t, more)
	require.Len(t, batch, 2)
	require.NotNil(t, batch[0].event)
	require.NotNil(t, batch[1].event)
	assert.Equal(t, uint32(55), batch[0].event.ClientHandle)
	assert.Equal(t, uint32(55), batch[1].event.ClientHandle)
	assert.Equal(t, "first", batch[0].event.EventFields[0].String())
	assert.Equal(t, "second", batch[1].event.EventFields[0].String())
}

func TestSubscriptionMaxNotificationsPerPublishLimitsEventsAndSetsMore(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.MaxNotificationsPerPublish = 2
	sub.publishQueue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 11, "first", 3, true))
	sub.publishQueue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 22, "second", 3, true))
	sub.publishQueue.Enqueue(subscriptionTestEventNotificationWithQueue(1, 33, "third", 3, true))

	batch, more := sub.nextPublishBatch()

	require.Equal(t, 2, batch.Len())
	assert.True(t, more)
	assert.Empty(t, batch.dataChanges)
	require.Len(t, batch.events, 2)
	assert.Equal(t, uint32(11), batch.events[0].ClientHandle)
	assert.Equal(t, uint32(22), batch.events[1].ClientHandle)
	assert.Equal(t, 1, sub.publishQueue.Len())

	batch, more = sub.nextPublishBatch()
	require.Equal(t, 1, batch.Len())
	assert.False(t, more)
	require.Len(t, batch.events, 1)
	assert.Equal(t, uint32(33), batch.events[0].ClientHandle)
}

func TestSubscriptionPublishBatchKeepsMixedDataChangeAndEventNotifications(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	sub.publishQueue.Enqueue(subscriptionTestEventNotification(2, 22, "event"))

	batch, more := sub.nextPublishBatch()
	require.False(t, more)
	require.Equal(t, 2, batch.Len())

	notificationData := notificationDataForPublishBatch(batch)
	require.Len(t, notificationData, 2)
	dataChanges, ok := notificationData[0].Value.(*ua.DataChangeNotification)
	require.True(t, ok, "expected DataChangeNotification, got %T", notificationData[0].Value)
	require.Len(t, dataChanges.MonitoredItems, 1)
	assert.Equal(t, uint32(11), dataChanges.MonitoredItems[0].ClientHandle)

	events, ok := notificationData[1].Value.(*ua.EventNotificationList)
	require.True(t, ok, "expected EventNotificationList, got %T", notificationData[1].Value)
	require.Len(t, events.Events, 1)
	assert.Equal(t, uint32(22), events.Events[0].ClientHandle)
}

func TestSubscriptionShouldSendKeepalive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		maxKeepAlive   uint32
		keepaliveCount int
		want           bool
	}{
		{name: "below threshold does not send", maxKeepAlive: 3, keepaliveCount: 2, want: false},
		{name: "at threshold sends", maxKeepAlive: 3, keepaliveCount: 3, want: true},
		{name: "above threshold sends", maxKeepAlive: 3, keepaliveCount: 4, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sub := &Subscription{RevisedMaxKeepAliveCount: tt.maxKeepAlive}
			assert.Equal(t, tt.want, sub.shouldSendKeepalive(tt.keepaliveCount))
		})
	}
}

func TestSubscriptionShouldTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		lifetimeCount uint32
		elapsedCount  int
		want          bool
	}{
		{name: "below threshold does not timeout", lifetimeCount: 5, elapsedCount: 4, want: false},
		{name: "at threshold times out", lifetimeCount: 5, elapsedCount: 5, want: true},
		{name: "above threshold times out", lifetimeCount: 5, elapsedCount: 6, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sub := &Subscription{RevisedLifetimeCount: tt.lifetimeCount}
			assert.Equal(t, tt.want, sub.shouldTimeout(tt.elapsedCount))
		})
	}
}

func TestSubscriptionNextKeepaliveSequenceNumber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sequenceID uint32
		want       uint32
	}{
		{name: "first keepalive uses sequence one", sequenceID: 0, want: 1},
		{name: "later keepalive uses next sequence number", sequenceID: 7, want: 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sub := &Subscription{SequenceID: tt.sequenceID}
			assert.Equal(t, tt.want, sub.nextKeepaliveSequenceNumber())
		})
	}
}

func TestSubscriptionApplyModifyRequestResetsTickerOnIntervalChange(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.RevisedPublishingInterval = 1000
	sub.resetTicker()
	originalTicker := sub.T
	t.Cleanup(func() {
		if sub.T != nil {
			sub.T.Stop()
		}
	})

	sub.applyModifyRequest(&ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: 500,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
		MaxNotificationsPerPublish:  3,
		Priority:                    2,
	})

	require.NotNil(t, sub.T)
	assert.NotSame(t, originalTicker, sub.T)
	assert.Equal(t, float64(500), sub.RevisedPublishingInterval)
}

func TestSubscriptionApplyModifyRequestKeepsTickerWhenIntervalIsUnchanged(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.RevisedPublishingInterval = 1000
	sub.resetTicker()
	originalTicker := sub.T
	t.Cleanup(func() {
		if sub.T != nil {
			sub.T.Stop()
		}
	})

	sub.applyModifyRequest(&ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: 1000,
		RequestedLifetimeCount:      40,
		RequestedMaxKeepAliveCount:  12,
		MaxNotificationsPerPublish:  4,
		Priority:                    3,
	})

	assert.Same(t, originalTicker, sub.T)
	assert.Equal(t, uint32(40), sub.RevisedLifetimeCount)
	assert.Equal(t, uint32(12), sub.RevisedMaxKeepAliveCount)
}

func TestSubscriptionApplySetPublishingMode(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = true

	sub.applySetPublishingMode(false)

	assert.False(t, sub.PublishingEnabled)
}

func TestSubscriptionApplySetPublishingModePreservesPendingNotifications(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = true
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(2, 22))

	sub.applySetPublishingMode(false)

	assert.False(t, sub.PublishingEnabled)
	assert.Equal(t, 2, sub.publishQueue.Len())
}

func TestSubscriptionDisabledPublishingStillFollowsKeepalivePath(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = false
	sub.RevisedMaxKeepAliveCount = 3
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))

	assert.False(t, sub.canPublishNotifications(sub.publishQueue.Len()))
	assert.True(t, sub.shouldSendKeepalive(3))
}

func TestSubscriptionReenablingPublishingResumesQueuedNotifications(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = false
	sub.MaxNotificationsPerPublish = 1
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(2, 22))

	assert.False(t, sub.canPublishNotifications(sub.publishQueue.Len()))

	sub.applySetPublishingMode(true)

	assert.True(t, sub.PublishingEnabled)
	assert.True(t, sub.canPublishNotifications(sub.publishQueue.Len()))

	batch, more := sub.nextPublishBatch()
	assert.Equal(t, 1, batch.Len())
	assert.True(t, more)
	assert.Equal(t, 1, sub.publishQueue.Len())
}

func TestSubscriptionApplyModifyRequestPreservesPendingNotificationsAndCounters(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.RevisedPublishingInterval = 1000
	sub.keepaliveCounter = 2
	sub.lifetimeCounter = 5
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(1, 11))
	sub.publishQueue.Enqueue(subscriptionTestDataChangeNotification(2, 22))
	sub.resetTicker()
	originalTicker := sub.T
	t.Cleanup(func() {
		if sub.T != nil {
			sub.T.Stop()
		}
	})

	sub.applyModifyRequest(&ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: 500,
		RequestedLifetimeCount:      40,
		RequestedMaxKeepAliveCount:  12,
		MaxNotificationsPerPublish:  4,
		Priority:                    3,
	})

	require.NotNil(t, sub.T)
	assert.NotSame(t, originalTicker, sub.T)
	assert.Equal(t, 2, sub.keepaliveCounter)
	assert.Equal(t, 5, sub.lifetimeCounter)
	assert.Equal(t, 2, sub.publishQueue.Len())
}

func subscriptionTestDataChangeNotification(monitoredID, clientHandle uint32) subscriptionNotification {
	return subscriptionNotification{
		kind:          subscriptionNotificationKindDataChange,
		monitoredID:   monitoredID,
		queueSize:     1,
		discardOldest: true,
		dataChange: &ua.MonitoredItemNotification{
			ClientHandle: clientHandle,
			Value:        &ua.DataValue{Value: ua.MustVariant(clientHandle)},
		},
	}
}

func subscriptionTestEventNotification(monitoredID, clientHandle uint32, value string) subscriptionNotification {
	return subscriptionTestEventNotificationWithQueue(monitoredID, clientHandle, value, 1, true)
}

func subscriptionTestEventNotificationWithQueue(monitoredID, clientHandle uint32, value string, queueSize uint32, discardOldest bool) subscriptionNotification {
	return subscriptionNotification{
		kind:          subscriptionNotificationKindEvent,
		monitoredID:   monitoredID,
		queueSize:     queueSize,
		discardOldest: discardOldest,
		event: &ua.EventFieldList{
			ClientHandle: clientHandle,
			EventFields:  []*ua.Variant{ua.MustVariant(value)},
		},
	}
}

type subscriptionTestBackend struct {
	handlers map[int]Handler
	session  types.Session
	cfg      types.ServerConfig
}

type subscriptionTestConfigOptions struct {
	maxSubscriptions                  uint32
	maxSubscriptionsPerSession        uint32
	maxSubscriptionOperationsPerCall  uint32
	minSubscriptionPublishingInterval time.Duration
	minSubscriptionMaxKeepAliveCount  uint32
	minSubscriptionLifetimeCount      uint32
}

func newSubscriptionTestBackend(session types.Session, options ...subscriptionTestConfigOptions) *subscriptionTestBackend {
	cfg := subscriptionTestConfig{
		maxSubscriptions:                  0,
		maxSubscriptionsPerSession:        0,
		maxSubscriptionOperationsPerCall:  0,
		minSubscriptionPublishingInterval: DefaultMinSubscriptionPublishingInterval,
		minSubscriptionMaxKeepAliveCount:  DefaultMinSubscriptionMaxKeepAliveCount,
		minSubscriptionLifetimeCount:      DefaultMinSubscriptionLifetimeCount,
	}
	if len(options) != 0 {
		cfg.maxSubscriptions = options[0].maxSubscriptions
		cfg.maxSubscriptionsPerSession = options[0].maxSubscriptionsPerSession
		cfg.maxSubscriptionOperationsPerCall = options[0].maxSubscriptionOperationsPerCall
		if options[0].minSubscriptionPublishingInterval > 0 {
			cfg.minSubscriptionPublishingInterval = options[0].minSubscriptionPublishingInterval
		}
		if options[0].minSubscriptionMaxKeepAliveCount > 0 {
			cfg.minSubscriptionMaxKeepAliveCount = options[0].minSubscriptionMaxKeepAliveCount
		}
		if options[0].minSubscriptionLifetimeCount > 0 {
			cfg.minSubscriptionLifetimeCount = options[0].minSubscriptionLifetimeCount
		}
	}

	return &subscriptionTestBackend{
		handlers: make(map[int]Handler),
		session:  session,
		cfg:      cfg,
	}
}

func (b *subscriptionTestBackend) RegisterHandler(typeID int, h Handler) {
	b.handlers[typeID] = h
}

func (b *subscriptionTestBackend) Namespace(int) (types.NameSpace, error) {
	return nil, nil
}

func (b *subscriptionTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
}

func (b *subscriptionTestBackend) DeleteSubscription(types.SubscriptionID) {}

func (b *subscriptionTestBackend) Config() types.ServerConfig {
	return b.cfg
}

type subscriptionTestSession struct {
	authToken    *ua.NodeID
	id           *ua.NodeID
	locales      []string
	remoteCert   []byte
	serverNonce  []byte
	timeoutMs    float64
	activated    bool
	publishQueue chan types.PubReq
}

func newSubscriptionTestSession() *subscriptionTestSession {
	return &subscriptionTestSession{
		authToken:    ua.NewNumericNodeID(1, 101),
		id:           ua.NewNumericNodeID(1, 202),
		timeoutMs:    60000,
		publishQueue: make(chan types.PubReq, 1),
	}
}

func (s *subscriptionTestSession) AuthTokenID() *ua.NodeID {
	return s.authToken
}

func (s *subscriptionTestSession) ID() *ua.NodeID {
	return s.id
}

func (s *subscriptionTestSession) Locales() []string {
	return s.locales
}

func (s *subscriptionTestSession) SetLocales(locales []string) {
	s.locales = locales
}

func (s *subscriptionTestSession) RemoteCertificate() []byte {
	return s.remoteCert
}

func (s *subscriptionTestSession) ServerNonce() []byte {
	return s.serverNonce
}

func (s *subscriptionTestSession) SetServerNonce(nonce []byte) {
	s.serverNonce = nonce
}

func (s *subscriptionTestSession) TimeOutInMillis() float64 {
	return s.timeoutMs
}

func (s *subscriptionTestSession) Activated() bool {
	return s.activated
}

func (s *subscriptionTestSession) SetActivated(activated bool) {
	s.activated = activated
}

func (s *subscriptionTestSession) IsSameAs(other types.Session) bool {
	return other != nil && s.authToken.String() == other.AuthTokenID().String()
}

func (s *subscriptionTestSession) AuthenticatedUser() *auth.AuthenticatedUser {
	return nil
}

func (s *subscriptionTestSession) PublishRequestChannel() chan types.PubReq {
	return s.publishQueue
}

type subscriptionTestConfig struct {
	maxSubscriptions                  uint32
	maxSubscriptionsPerSession        uint32
	maxSubscriptionOperationsPerCall  uint32
	minSubscriptionPublishingInterval time.Duration
	minSubscriptionMaxKeepAliveCount  uint32
	minSubscriptionLifetimeCount      uint32
}

func (cfg subscriptionTestConfig) Certificate() []byte {
	return nil
}

func (cfg subscriptionTestConfig) Endpoints() []string {
	return nil
}

func (cfg subscriptionTestConfig) PrivateKey() *rsa.PrivateKey {
	return nil
}

func (cfg subscriptionTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator {
	return nil
}

func (cfg subscriptionTestConfig) AuthorizationContextDecorator() auth.AuthorizationContextDecorator {
	return nil
}

func (cfg subscriptionTestConfig) ApplicationURI() string {
	return ""
}

func (cfg subscriptionTestConfig) ManufacturerName() string {
	return ""
}

func (cfg subscriptionTestConfig) ProductName() string {
	return ""
}

func (cfg subscriptionTestConfig) SoftwareVersion() string {
	return ""
}

func (cfg subscriptionTestConfig) MaxNodesPerRead() uint32 {
	return 0
}

func (cfg subscriptionTestConfig) MaxMethodOperationsPerCall() uint32 {
	return 0
}

func (cfg subscriptionTestConfig) MaxBrowseOperationsPerCall() uint32 {
	return 0
}

func (cfg subscriptionTestConfig) MaxBrowseContinuationPoints() uint32 {
	return 0
}

func (cfg subscriptionTestConfig) MaxSubscriptions() uint32 {
	return cfg.maxSubscriptions
}

func (cfg subscriptionTestConfig) MaxSubscriptionsPerSession() uint32 {
	return cfg.maxSubscriptionsPerSession
}

func (cfg subscriptionTestConfig) MaxSubscriptionOperationsPerCall() uint32 {
	return cfg.maxSubscriptionOperationsPerCall
}

func (cfg subscriptionTestConfig) MinSubscriptionPublishingInterval() time.Duration {
	return cfg.minSubscriptionPublishingInterval
}

func (cfg subscriptionTestConfig) MinSubscriptionMaxKeepAliveCount() uint32 {
	return cfg.minSubscriptionMaxKeepAliveCount
}

func (cfg subscriptionTestConfig) MinSubscriptionLifetimeCount() uint32 {
	return cfg.minSubscriptionLifetimeCount
}

func (cfg subscriptionTestConfig) MethodCallMiddleware() types.MethodMiddleware {
	return func(fn types.MethodFunc) types.MethodFunc {
		return fn
	}
}

func newCreateSubscriptionRequest(session *subscriptionTestSession, handle uint32) *ua.CreateSubscriptionRequest {
	return &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       handle,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}
}

func newTestSecureChannel(t *testing.T) *uasc.SecureChannel {
	t.Helper()

	sc, err := uasc.NewSecureChannel(
		"opc.tcp://127.0.0.1:4840",
		&uacp.Conn{TCPConn: new(net.TCPConn)},
		&uasc.Config{
			SecurityPolicyURI: ua.SecurityPolicyURINone,
			SecurityMode:      ua.MessageSecurityModeNone,
		},
		make(chan error, 1),
	)
	require.NoError(t, err)

	return sc
}
