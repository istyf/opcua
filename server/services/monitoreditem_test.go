package services

import (
	"context"
	"testing"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateMonitoredItemsChecksSessionOwnership(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	otherSession := newSubscriptionTestSession()
	otherSession.authToken = ua.NewNumericNodeID(1, 404)

	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
	}
	service := NewMonitoredItemService(backend)

	req := &ua.CreateMonitoredItemsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       1,
			AuthenticationToken: ownerSession.AuthTokenID(),
		},
		SubscriptionID: uint32(sub.ID),
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor: &ua.ReadValueID{
					NodeID:      ua.NewNumericNodeID(1, 1234),
					AttributeID: ua.AttributeIDValue,
				},
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     99,
					SamplingInterval: 1000,
					QueueSize:        1,
				},
			},
		},
	}

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	require.IsType(t, &ua.CreateMonitoredItemsResponse{}, resp)

	backend.session = otherSession
	req.RequestHeader.AuthenticationToken = otherSession.AuthTokenID()

	resp, err = service.CreateMonitoredItems(t.Context(), nil, req, 2)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestCreateMonitoredItemsRejectsMissingSession(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000

	backend := &monitoredItemTestBackend{
		session:      nil,
		subscription: sub,
	}
	service := NewMonitoredItemService(backend)

	req := &ua.CreateMonitoredItemsRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       2,
			AuthenticationToken: ownerSession.AuthTokenID(),
		},
		SubscriptionID: uint32(sub.ID),
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor: &ua.ReadValueID{
					NodeID:      ua.NewNumericNodeID(1, 4321),
					AttributeID: ua.AttributeIDValue,
				},
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     100,
					SamplingInterval: 1000,
					QueueSize:        1,
				},
			},
		},
	}

	resp, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	assert.Nil(t, resp)
	assert.Equal(t, ua.StatusBadSessionIDInvalid, err)
}

type monitoredItemTestBackend struct {
	session      types.Session
	subscription *Subscription
}

func (b *monitoredItemTestBackend) RegisterHandler(int, Handler) {}

func (b *monitoredItemTestBackend) Namespace(int) (types.NameSpace, error) {
	return nil, context.Canceled
}

func (b *monitoredItemTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
}

func (b *monitoredItemTestBackend) Subscription(id types.SubscriptionID) (*Subscription, bool) {
	if b.subscription == nil || b.subscription.ID != id {
		return nil, false
	}
	return b.subscription, true
}
