package server

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmitEventAppliesBaseEventDefaults(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{}
	sourceNodeID := ua.NewNumericNodeID(2, 1001)
	event := &types.Event{}

	before := time.Now()
	require.NoError(t, srv.EmitEvent(t.Context(), sourceNodeID, event))
	after := time.Now()

	require.NotNil(t, event.SourceNode)
	assert.True(t, event.SourceNode.Equal(sourceNodeID))
	require.NotNil(t, event.EventType)
	assert.True(t, event.EventType.Equal(ua.NewNumericNodeID(0, id.BaseEventType)))
	assert.Equal(t, sourceNodeID.String(), event.SourceName)
	assert.WithinRange(t, event.Time, before, after)
	assert.WithinRange(t, event.ReceiveTime, before, after)
	require.NotNil(t, event.Message)
	assert.Equal(t, "", event.Message.Text)
	assert.Len(t, event.EventID, generatedEventIDLength)
}

func TestEmitEventPreservesExplicitBaseEventFields(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{}
	sourceNodeID := ua.NewNumericNodeID(2, 1001)
	explicitSourceNode := ua.NewNumericNodeID(2, 1002)
	explicitEventType := ua.NewNumericNodeID(0, id.SystemEventType)
	explicitEventID := []byte{1, 2, 3}
	explicitTime := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	explicitReceiveTime := time.Date(2026, 6, 4, 12, 0, 1, 0, time.UTC)
	explicitMessage := ua.NewLocalizedText("ready")
	fieldValue := ua.MustVariant("custom")
	event := &types.Event{
		EventID:     explicitEventID,
		EventType:   explicitEventType,
		SourceNode:  explicitSourceNode,
		SourceName:  "source",
		Time:        explicitTime,
		ReceiveTime: explicitReceiveTime,
		Message:     explicitMessage,
		Severity:    500,
		Fields:      map[string]*ua.Variant{"Custom": fieldValue},
	}

	require.NoError(t, srv.EmitEvent(t.Context(), sourceNodeID, event))

	assert.Equal(t, explicitEventID, event.EventID)
	assert.Same(t, explicitEventType, event.EventType)
	assert.Same(t, explicitSourceNode, event.SourceNode)
	assert.Equal(t, "source", event.SourceName)
	assert.Equal(t, explicitTime, event.Time)
	assert.Equal(t, explicitReceiveTime, event.ReceiveTime)
	assert.Same(t, explicitMessage, event.Message)
	assert.Equal(t, uint16(500), event.Severity)
	assert.Same(t, fieldValue, event.Fields["Custom"])
}

func TestEmitEventRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{}
	sourceNodeID := ua.NewNumericNodeID(2, 1001)

	assert.Equal(t, ua.StatusBadSourceNodeIDInvalid, srv.EmitEvent(t.Context(), nil, &types.Event{}))
	assert.Equal(t, ua.StatusBadInvalidArgument, srv.EmitEvent(t.Context(), sourceNodeID, nil))
}
