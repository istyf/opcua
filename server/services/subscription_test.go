package services

import (
	"context"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
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
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			if !ok {
				t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
			}
			if createResp.RevisedPublishingInterval != tt.want {
				t.Fatalf("expected revised publishing interval %v, got %v", tt.want, createResp.RevisedPublishingInterval)
			}

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
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			if !ok {
				t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
			}
			if createResp.RevisedMaxKeepAliveCount != tt.want {
				t.Fatalf("expected revised max keepalive count %d, got %d", tt.want, createResp.RevisedMaxKeepAliveCount)
			}

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
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			if !ok {
				t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
			}
			if createResp.RevisedLifetimeCount != tt.want {
				t.Fatalf("expected revised lifetime count %d, got %d", tt.want, createResp.RevisedLifetimeCount)
			}

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

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
	if err != nil {
		t.Fatalf("modify subscription: %v", err)
	}

	modified, ok := resp.(*ua.ModifySubscriptionResponse)
	if !ok {
		t.Fatalf("expected ModifySubscriptionResponse, got %T", resp)
	}
	if modified.RevisedPublishingInterval != 200 {
		t.Fatalf("expected revised publishing interval 200, got %v", modified.RevisedPublishingInterval)
	}
	if modified.RevisedMaxKeepAliveCount != 3 {
		t.Fatalf("expected revised max keepalive count 3, got %d", modified.RevisedMaxKeepAliveCount)
	}
	if modified.RevisedLifetimeCount != 20 {
		t.Fatalf("expected revised lifetime count 20, got %d", modified.RevisedLifetimeCount)
	}

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to exist")
	}
	if sub.RevisedPublishingInterval != modified.RevisedPublishingInterval {
		t.Fatalf("expected runtime revised publishing interval %v, got %v", modified.RevisedPublishingInterval, sub.RevisedPublishingInterval)
	}
	if sub.RevisedMaxKeepAliveCount != modified.RevisedMaxKeepAliveCount {
		t.Fatalf("expected runtime revised max keepalive count %d, got %d", modified.RevisedMaxKeepAliveCount, sub.RevisedMaxKeepAliveCount)
	}
	if sub.RevisedLifetimeCount != modified.RevisedLifetimeCount {
		t.Fatalf("expected runtime revised lifetime count %d, got %d", modified.RevisedLifetimeCount, sub.RevisedLifetimeCount)
	}
	if sub.MaxNotificationsPerPublish != 7 {
		t.Fatalf("expected runtime max notifications per publish 7, got %d", sub.MaxNotificationsPerPublish)
	}
	if sub.Priority != 9 {
		t.Fatalf("expected runtime priority 9, got %d", sub.Priority)
	}

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestModifySubscriptionRejectsMissingSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 72), 1)
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	backend.session = nil
	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       73,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionID: created.SubscriptionID,
	}, 2)
	if resp != nil {
		t.Fatalf("expected nil response, got %T", resp)
	}
	if err != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected %v, got %v", ua.StatusBadSessionIDInvalid, err)
	}

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
	if resp != nil {
		t.Fatalf("expected nil response, got %T", resp)
	}
	if err != ua.StatusBadSubscriptionIDInvalid {
		t.Fatalf("expected %v, got %v", ua.StatusBadSubscriptionIDInvalid, err)
	}
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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	backend.session = otherSession
	resp, err := service.ModifySubscription(t.Context(), sc, &ua.ModifySubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       76,
			AuthenticationToken: otherSession.AuthTokenID(),
		},
		SubscriptionID: created.SubscriptionID,
	}, 2)
	if resp != nil {
		t.Fatalf("expected nil response, got %T", resp)
	}
	if err != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected %v, got %v", ua.StatusBadSessionIDInvalid, err)
	}

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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       81,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID},
	}, 2)
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	if len(setResp.Results) != 1 || setResp.Results[0] != ua.StatusOK {
		t.Fatalf("expected single ok result, got %#v", setResp.Results)
	}

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to exist")
	}
	if sub.PublishingEnabled {
		t.Fatal("expected publishing to be disabled on the runtime subscription")
	}

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestSetPublishingModeRejectsMissingSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 82), 1)
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	backend.session = nil
	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       83,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID},
	}, 2)
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	if len(setResp.Results) != 1 || setResp.Results[0] != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected single bad session result, got %#v", setResp.Results)
	}

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
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	if len(setResp.Results) != 1 || setResp.Results[0] != ua.StatusBadSubscriptionIDInvalid {
		t.Fatalf("expected single bad subscription result, got %#v", setResp.Results)
	}
}

func TestSetPublishingModeRejectsDifferentSession(t *testing.T) {
	t.Parallel()

	owner := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(owner)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	createResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(owner, 85), 1)
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

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
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	if len(setResp.Results) != 1 || setResp.Results[0] != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected single bad session result, got %#v", setResp.Results)
	}

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
	if err != ua.StatusBadNothingToDo {
		t.Fatalf("expected %s, got %v", ua.StatusBadNothingToDo, err)
	}
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
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	first, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 89), 2)
	if err != nil {
		t.Fatalf("create second subscription: %v", err)
	}
	second, ok := secondResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", secondResp)
	}

	_, err = service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       90,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{first.SubscriptionID, second.SubscriptionID},
	}, 3)
	if err != ua.StatusBadTooManyOperations {
		t.Fatalf("expected %s, got %v", ua.StatusBadTooManyOperations, err)
	}

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
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	first, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 92), 2)
	if err != nil {
		t.Fatalf("create second subscription: %v", err)
	}
	second, ok := secondResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", secondResp)
	}

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       93,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{first.SubscriptionID, 999, second.SubscriptionID},
	}, 3)
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	want := []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid, ua.StatusOK}
	if len(setResp.Results) != len(want) {
		t.Fatalf("expected %d results, got %d", len(want), len(setResp.Results))
	}
	for i := range want {
		if setResp.Results[i] != want[i] {
			t.Fatalf("expected result %d to be %s, got %s", i, want[i], setResp.Results[i])
		}
	}

	firstSub, ok := service.Get(types.SubscriptionID(first.SubscriptionID))
	if !ok {
		t.Fatal("expected first subscription to exist")
	}
	if firstSub.PublishingEnabled {
		t.Fatal("expected first subscription publishing to be disabled")
	}

	secondSub, ok := service.Get(types.SubscriptionID(second.SubscriptionID))
	if !ok {
		t.Fatal("expected second subscription to exist")
	}
	if secondSub.PublishingEnabled {
		t.Fatal("expected second subscription publishing to be disabled")
	}

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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	resp, err := service.SetPublishingMode(t.Context(), sc, &ua.SetPublishingModeRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       95,
			AuthenticationToken: session.AuthTokenID(),
		},
		PublishingEnabled: false,
		SubscriptionIDs:   []uint32{created.SubscriptionID, 999, created.SubscriptionID},
	}, 2)
	if err != nil {
		t.Fatalf("set publishing mode: %v", err)
	}

	setResp, ok := resp.(*ua.SetPublishingModeResponse)
	if !ok {
		t.Fatalf("expected SetPublishingModeResponse, got %T", resp)
	}
	want := []ua.StatusCode{ua.StatusOK, ua.StatusBadSubscriptionIDInvalid, ua.StatusOK}
	if len(setResp.Results) != len(want) {
		t.Fatalf("expected %d results, got %d", len(want), len(setResp.Results))
	}
	for i := range want {
		if setResp.Results[i] != want[i] {
			t.Fatalf("expected result %d to be %s, got %s", i, want[i], setResp.Results[i])
		}
	}

	sub, ok := service.Get(types.SubscriptionID(created.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to exist")
	}
	if sub.PublishingEnabled {
		t.Fatal("expected publishing to be disabled after duplicate-id batch")
	}

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
	if resp != nil {
		t.Fatalf("expected nil response, got %T", resp)
	}
	if err != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected %v, got %v", ua.StatusBadSessionIDInvalid, err)
	}
	if got := len(service.subs); got != 0 {
		t.Fatalf("expected no subscriptions to be created, got %d", got)
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
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
	}
	if createResp.SubscriptionID == 0 {
		t.Fatal("expected non-zero subscription ID")
	}
	if createResp.ResponseHeader == nil || createResp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("expected status %v, got %#v", ua.StatusOK, createResp.ResponseHeader)
	}

	sub, ok := service.Get(types.SubscriptionID(createResp.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to be registered")
	}
	if sub.session != session {
		t.Fatal("expected created subscription to keep the resolved session")
	}

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
		if recover() == nil {
			t.Fatal("expected CreateSubscription to panic when secure channel is nil")
		}
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
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	firstID := types.SubscriptionID(firstCreateResp.SubscriptionID)
	service.DeleteSubscription(t.Context(), firstID)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 45), 2)
	if err != nil {
		t.Fatalf("create second subscription: %v", err)
	}
	secondCreateResp, ok := secondResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", secondResp)
	}

	if secondCreateResp.SubscriptionID == firstCreateResp.SubscriptionID {
		t.Fatalf("expected a new subscription id, got reused id %d", secondCreateResp.SubscriptionID)
	}
	if secondCreateResp.SubscriptionID <= firstCreateResp.SubscriptionID {
		t.Fatalf("expected monotonic subscription ids, got first=%d second=%d", firstCreateResp.SubscriptionID, secondCreateResp.SubscriptionID)
	}

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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
	}

	sub, ok := service.Get(types.SubscriptionID(createResp.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to be registered")
	}
	if sub.MaxNotificationsPerPublish != req.MaxNotificationsPerPublish {
		t.Fatalf("expected max notifications per publish %d, got %d", req.MaxNotificationsPerPublish, sub.MaxNotificationsPerPublish)
	}
	if sub.PublishingEnabled != req.PublishingEnabled {
		t.Fatalf("expected publishing enabled %t, got %t", req.PublishingEnabled, sub.PublishingEnabled)
	}
	if sub.Priority != req.Priority {
		t.Fatalf("expected priority %d, got %d", req.Priority, sub.Priority)
	}

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
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 61), 2)
	if secondResp != nil {
		t.Fatalf("expected nil response, got %T", secondResp)
	}
	if err != ua.StatusBadTooManySubscriptions {
		t.Fatalf("expected %v, got %v", ua.StatusBadTooManySubscriptions, err)
	}

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
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(firstSession, 63), 2)
	if secondResp != nil {
		t.Fatalf("expected nil response, got %T", secondResp)
	}
	if err != ua.StatusBadTooManySubscriptions {
		t.Fatalf("expected %v, got %v", ua.StatusBadTooManySubscriptions, err)
	}

	backend.session = secondSession
	thirdResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(secondSession, 64), 3)
	if err != nil {
		t.Fatalf("create subscription for different session: %v", err)
	}
	thirdCreateResp, ok := thirdResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", thirdResp)
	}

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
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	created, ok := createResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", createResp)
	}

	backend.session = nil
	resp, err := service.DeleteSubscriptions(t.Context(), sc, &ua.DeleteSubscriptionsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       66,
			AuthenticationToken: session.AuthTokenID(),
		},
		SubscriptionIDs: []uint32{created.SubscriptionID},
	}, 2)
	if err != nil {
		t.Fatalf("expected no handler error, got %v", err)
	}

	deleteResp, ok := resp.(*ua.DeleteSubscriptionsResponse)
	if !ok {
		t.Fatalf("expected DeleteSubscriptionsResponse, got %T", resp)
	}
	if len(deleteResp.Results) != 1 || deleteResp.Results[0] != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected bad session result, got %#v", deleteResp.Results)
	}

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
			if got := sub.canPublishNotifications(tt.pendingCount); got != tt.want {
				t.Fatalf("expected %t, got %t", tt.want, got)
			}
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

			sub := &Subscription{MaxNotificationsPerPublish: tt.maxPerPublish}
			publishQueue := make(map[uint32]*ua.MonitoredItemNotification, tt.queueSize)
			for i := range tt.queueSize {
				handle := uint32(i + 1)
				publishQueue[handle] = &ua.MonitoredItemNotification{ClientHandle: handle}
			}

			batch, more := sub.nextPublishBatch(publishQueue)
			if len(batch) != tt.wantBatchSize {
				t.Fatalf("expected batch size %d, got %d", tt.wantBatchSize, len(batch))
			}
			if len(publishQueue) != tt.wantRemaining {
				t.Fatalf("expected remaining queue size %d, got %d", tt.wantRemaining, len(publishQueue))
			}
			if more != tt.wantMore {
				t.Fatalf("expected more notifications %t, got %t", tt.wantMore, more)
			}
		})
	}
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
			if got := sub.shouldSendKeepalive(tt.keepaliveCount); got != tt.want {
				t.Fatalf("expected %t, got %t", tt.want, got)
			}
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
			if got := sub.shouldTimeout(tt.elapsedCount); got != tt.want {
				t.Fatalf("expected %t, got %t", tt.want, got)
			}
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
			if got := sub.nextKeepaliveSequenceNumber(); got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
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

	if sub.T == nil {
		t.Fatal("expected ticker to be initialized")
	}
	if sub.T == originalTicker {
		t.Fatal("expected ticker to be replaced when publishing interval changes")
	}
	if sub.RevisedPublishingInterval != 500 {
		t.Fatalf("expected revised publishing interval 500, got %v", sub.RevisedPublishingInterval)
	}
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

	if sub.T != originalTicker {
		t.Fatal("expected ticker to stay the same when publishing interval is unchanged")
	}
	if sub.RevisedLifetimeCount != 40 {
		t.Fatalf("expected revised lifetime count 40, got %d", sub.RevisedLifetimeCount)
	}
	if sub.RevisedMaxKeepAliveCount != 12 {
		t.Fatalf("expected revised max keepalive count 12, got %d", sub.RevisedMaxKeepAliveCount)
	}
}

func TestSubscriptionApplySetPublishingMode(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = true

	sub.applySetPublishingMode(false)

	if sub.PublishingEnabled {
		t.Fatal("expected publishing to be disabled")
	}
}

func TestSubscriptionApplySetPublishingModePreservesPendingNotifications(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = true
	sub.publishQueue[11] = &ua.MonitoredItemNotification{ClientHandle: 11}
	sub.publishQueue[22] = &ua.MonitoredItemNotification{ClientHandle: 22}

	sub.applySetPublishingMode(false)

	if sub.PublishingEnabled {
		t.Fatal("expected publishing to be disabled")
	}
	if len(sub.publishQueue) != 2 {
		t.Fatalf("expected two queued notifications to be preserved, got %d", len(sub.publishQueue))
	}
	if _, ok := sub.publishQueue[11]; !ok {
		t.Fatal("expected queued notification for client handle 11 to be preserved")
	}
	if _, ok := sub.publishQueue[22]; !ok {
		t.Fatal("expected queued notification for client handle 22 to be preserved")
	}
}

func TestSubscriptionDisabledPublishingStillFollowsKeepalivePath(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = false
	sub.RevisedMaxKeepAliveCount = 3
	sub.publishQueue[11] = &ua.MonitoredItemNotification{ClientHandle: 11}

	if sub.canPublishNotifications(len(sub.publishQueue)) {
		t.Fatal("expected disabled subscription not to publish notifications")
	}
	if !sub.shouldSendKeepalive(3) {
		t.Fatal("expected keepalive threshold to still apply while publishing is disabled")
	}
}

func TestSubscriptionReenablingPublishingResumesQueuedNotifications(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.PublishingEnabled = false
	sub.MaxNotificationsPerPublish = 1
	sub.publishQueue[11] = &ua.MonitoredItemNotification{ClientHandle: 11}
	sub.publishQueue[22] = &ua.MonitoredItemNotification{ClientHandle: 22}

	if sub.canPublishNotifications(len(sub.publishQueue)) {
		t.Fatal("expected disabled subscription not to publish notifications")
	}

	sub.applySetPublishingMode(true)

	if !sub.PublishingEnabled {
		t.Fatal("expected publishing to be re-enabled")
	}
	if !sub.canPublishNotifications(len(sub.publishQueue)) {
		t.Fatal("expected queued notifications to become publishable after re-enabling")
	}

	batch, more := sub.nextPublishBatch(sub.publishQueue)
	if len(batch) != 1 {
		t.Fatalf("expected batch size 1 after re-enabling, got %d", len(batch))
	}
	if !more {
		t.Fatal("expected more notifications to remain after the first resumed publish batch")
	}
	if len(sub.publishQueue) != 1 {
		t.Fatalf("expected one queued notification to remain, got %d", len(sub.publishQueue))
	}
}

func TestSubscriptionApplyModifyRequestPreservesPendingNotificationsAndCounters(t *testing.T) {
	t.Parallel()

	sub := NewSubscription()
	sub.RevisedPublishingInterval = 1000
	sub.keepaliveCounter = 2
	sub.lifetimeCounter = 5
	sub.publishQueue[11] = &ua.MonitoredItemNotification{ClientHandle: 11}
	sub.publishQueue[22] = &ua.MonitoredItemNotification{ClientHandle: 22}
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

	if sub.T == nil {
		t.Fatal("expected ticker to be initialized")
	}
	if sub.T == originalTicker {
		t.Fatal("expected ticker to be replaced when publishing interval changes")
	}
	if sub.keepaliveCounter != 2 {
		t.Fatalf("expected keepalive counter 2, got %d", sub.keepaliveCounter)
	}
	if sub.lifetimeCounter != 5 {
		t.Fatalf("expected lifetime counter 5, got %d", sub.lifetimeCounter)
	}
	if len(sub.publishQueue) != 2 {
		t.Fatalf("expected two queued notifications to be preserved, got %d", len(sub.publishQueue))
	}
	if _, ok := sub.publishQueue[11]; !ok {
		t.Fatal("expected queued notification for client handle 11 to be preserved")
	}
	if _, ok := sub.publishQueue[22]; !ok {
		t.Fatal("expected queued notification for client handle 22 to be preserved")
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

func (s *subscriptionTestSession) IsSameAs(other types.Session) bool {
	return other != nil && s.authToken.String() == other.AuthTokenID().String()
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
	if err != nil {
		t.Fatalf("new secure channel: %v", err)
	}

	return sc
}
