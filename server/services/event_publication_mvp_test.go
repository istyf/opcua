package services

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMVPEmitEventProducesEventNotificationListPublishResponse(t *testing.T) {
	t.Parallel()

	ownerSession := newSubscriptionTestSession()
	sub := NewSubscription()
	sub.ID = 1
	sub.session = ownerSession
	sub.RevisedPublishingInterval = 1000
	sub.PublishingEnabled = true

	sourceNodeID := ua.NewNumericNodeID(1, 7001)
	objectType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(1, 7000)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "EventSourceType"}),
		),
	)
	source := node.NewObjectNode(
		node.WithBase(
			node.WithID(sourceNodeID),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "EventSource"}),
		),
		node.WithType(objectType),
		node.WithEventNotifierTypes(ua.EventNotifierTypeSubscribeToEvents),
	)
	namespace := newMonitoredItemTestNamespace(source)

	backend := &monitoredItemTestBackend{
		session:      ownerSession,
		subscription: sub,
		namespace:    namespace,
	}
	service := NewMonitoredItemService(backend)
	filterObject := monitoredItemTestEventFilter("Message", "Severity", "SourceNode")
	req := monitoredItemTestCreateEventRequest(ownerSession, sub, sourceNodeID, filterObject)

	createRespRaw, err := service.CreateMonitoredItems(t.Context(), nil, req, 1)
	require.NoError(t, err)
	createResp, ok := createRespRaw.(*ua.CreateMonitoredItemsResponse)
	require.True(t, ok, "expected CreateMonitoredItemsResponse, got %T", createRespRaw)
	require.Len(t, createResp.Results, 1)
	require.Equal(t, ua.StatusOK, createResp.Results[0].StatusCode)

	require.NoError(t, service.EmitEvent(t.Context(), sourceNodeID, &types.Event{
		SourceNode: sourceNodeID,
		Message:    ua.NewLocalizedText("mvp event"),
		Severity:   725,
	}))

	select {
	case notification := <-sub.NotifyChannel:
		sub.publishQueue.Enqueue(notification)
	default:
		t.Fatal("expected emitted event notification")
	}

	batch, moreNotifications := sub.nextPublishBatch()
	require.False(t, moreNotifications)
	require.Equal(t, 1, batch.Len())

	notificationMessage := &ua.NotificationMessage{
		SequenceNumber:   1,
		PublishTime:      time.Now(),
		NotificationData: notificationDataForPublishBatch(batch),
	}
	publishResp := sub.publishResponse(types.PubReq{
		Req: &ua.PublishRequest{
			RequestHeader: &ua.RequestHeader{RequestHandle: 99},
		},
		ID: 2,
	}, notificationMessage, moreNotifications)

	require.NotNil(t, publishResp.NotificationMessage)
	require.Len(t, publishResp.NotificationMessage.NotificationData, 1)
	events, ok := publishResp.NotificationMessage.NotificationData[0].Value.(*ua.EventNotificationList)
	require.True(t, ok, "expected EventNotificationList, got %T", publishResp.NotificationMessage.NotificationData[0].Value)
	require.Len(t, events.Events, 1)
	eventFields := events.Events[0]
	assert.Equal(t, uint32(55), eventFields.ClientHandle)
	require.Len(t, eventFields.EventFields, 3)
	assert.Equal(t, "mvp event", eventFields.EventFields[0].String())
	assert.Equal(t, uint64(725), eventFields.EventFields[1].Uint())
	assert.Same(t, sourceNodeID, eventFields.EventFields[2].Value())
}
