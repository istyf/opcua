package server

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

const generatedEventIDLength = 16

// EmitEvent publishes an OPC UA event from sourceNodeID.
//
// The event payload is normalized before it is handed to the monitored item
// service. For this first event path, sourceNodeID is also the event notifier
// node clients subscribe to.
func (s *serverImpl) EmitEvent(ctx context.Context, sourceNodeID *ua.NodeID, event *types.Event) error {
	if sourceNodeID == nil {
		return ua.StatusBadSourceNodeIDInvalid
	}
	if event == nil {
		return ua.StatusBadInvalidArgument
	}

	if event.SourceNode == nil {
		event.SourceNode = sourceNodeID
	}
	if event.EventType == nil {
		event.EventType = ua.NewNumericNodeID(0, id.BaseEventType)
	}
	if event.SourceName == "" {
		event.SourceName = s.eventSourceName(ctx, sourceNodeID)
	}
	if event.Time.IsZero() || event.ReceiveTime.IsZero() {
		now := time.Now()
		if event.Time.IsZero() {
			event.Time = now
		}
		if event.ReceiveTime.IsZero() {
			event.ReceiveTime = now
		}
	}
	if event.Message == nil {
		event.Message = ua.NewLocalizedText("")
	}
	if len(event.EventID) == 0 {
		eventID := make([]byte, generatedEventIDLength)
		if _, err := rand.Read(eventID); err != nil {
			return err
		}
		event.EventID = eventID
	}

	if s.MonitoredItemService != nil {
		return s.MonitoredItemService.EmitEvent(ctx, sourceNodeID, event)
	}

	return nil
}

func (s *serverImpl) eventSourceName(ctx context.Context, sourceNodeID *ua.NodeID) string {
	if s != nil {
		if sourceNode := s.Node(sourceNodeID); sourceNode != nil {
			if displayName := sourceNode.DisplayName(ctx); displayName != nil && displayName.Text != "" {
				return displayName.Text
			}
			if browseName := sourceNode.BrowseName(); browseName != nil && browseName.Name != "" {
				return browseName.Name
			}
		}
	}
	return sourceNodeID.String()
}
