package services

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventFilterSelectFieldsReturnsRequestedOrder(t *testing.T) {
	t.Parallel()

	eventTime := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	event := &types.Event{
		EventID:     []byte{1, 2, 3},
		EventType:   ua.NewNumericNodeID(0, id.SystemEventType),
		SourceNode:  ua.NewNumericNodeID(2, 1001),
		SourceName:  "source",
		Time:        eventTime,
		ReceiveTime: eventTime.Add(time.Second),
		Message:     ua.NewLocalizedText("message"),
		Severity:    900,
	}
	filter := monitoredItemTestEventFilter("Severity", "EventId", "Message", "SourceNode", "ReceiveTime")

	fields := eventFilterSelectFields(filter.Value.(*ua.EventFilter), event)

	require.Len(t, fields, 5)
	assert.Equal(t, uint64(900), fields[0].Uint())
	assert.Equal(t, []byte{1, 2, 3}, fields[1].Value())
	assert.Equal(t, "message", fields[2].String())
	assert.Same(t, event.SourceNode, fields[3].Value())
	assert.Equal(t, event.ReceiveTime, fields[4].Value())
}

func TestEventFilterSelectFieldsUsesCustomFieldsAndNullForMissing(t *testing.T) {
	t.Parallel()

	customValue := ua.MustVariant("custom")
	event := &types.Event{
		Fields: map[string]*ua.Variant{
			"EnabledState/Id": customValue,
		},
	}
	filter := &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{
			monitoredItemTestSelectClause("EnabledState", "Id"),
			monitoredItemTestSelectClause("Missing"),
		},
	}

	fields := eventFilterSelectFields(filter, event)

	require.Len(t, fields, 2)
	assert.Same(t, customValue, fields[0])
	assert.Equal(t, ua.TypeIDNull, fields[1].Type())
}

func TestEventFilterSelectFieldsSupportsBaseEventTypeFields(t *testing.T) {
	t.Parallel()

	eventTime := time.Date(2026, 6, 5, 11, 0, 0, 0, time.UTC)
	receiveTime := eventTime.Add(2 * time.Second)
	eventID := []byte{9, 8, 7}
	eventType := ua.NewNumericNodeID(0, id.SystemEventType)
	sourceNode := ua.NewNumericNodeID(2, 2001)
	message := ua.NewLocalizedText("standard fields")
	event := &types.Event{
		EventID:     eventID,
		EventType:   eventType,
		SourceNode:  sourceNode,
		SourceName:  "source name",
		Time:        eventTime,
		ReceiveTime: receiveTime,
		Message:     message,
		Severity:    321,
	}

	tests := []struct {
		name string
		path string
		want any
	}{
		{name: "EventId", path: "EventId", want: eventID},
		{name: "EventID alias", path: "EventID", want: eventID},
		{name: "EventType", path: "EventType", want: eventType},
		{name: "SourceNode", path: "SourceNode", want: sourceNode},
		{name: "SourceName", path: "SourceName", want: "source name"},
		{name: "Time", path: "Time", want: eventTime},
		{name: "ReceiveTime", path: "ReceiveTime", want: receiveTime},
		{name: "Message", path: "Message", want: message},
		{name: "Severity", path: "Severity", want: uint16(321)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fields := eventFilterSelectFields(&ua.EventFilter{
				SelectClauses: []*ua.SimpleAttributeOperand{
					monitoredItemTestSelectClause(tt.path),
				},
			}, event)

			require.Len(t, fields, 1)
			assert.Equal(t, tt.want, fields[0].Value())
		})
	}
}

func TestEventFilterMatchesSeverityComparison(t *testing.T) {
	t.Parallel()

	filter := &ua.EventFilter{
		WhereClause: monitoredItemTestSeverityWhereClause(ua.FilterOperatorGreaterThanOrEqual, uint16(500)),
	}

	assert.True(t, eventFilterMatches(filter, &types.Event{Severity: 500}))
	assert.True(t, eventFilterMatches(filter, &types.Event{Severity: 700}))
	assert.False(t, eventFilterMatches(filter, &types.Event{Severity: 499}))
}

func TestValidateEventFilterAcceptsSupportedSeverityWhereClause(t *testing.T) {
	t.Parallel()

	filter := &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{
			monitoredItemTestSelectClause("Severity"),
		},
		WhereClause: monitoredItemTestSeverityWhereClause(ua.FilterOperatorGreaterThanOrEqual, uint16(500)),
	}
	resultObj := newEventFilterResult(filter)

	status := validateEventFilter(filter, resultObj)

	require.Equal(t, ua.StatusOK, status)
	result, ok := resultObj.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected EventFilterResult, got %T", resultObj.Value)
	require.NotNil(t, result.WhereClauseResult)
	require.Len(t, result.WhereClauseResult.ElementResults, 1)
	assert.Equal(t, ua.StatusOK, result.WhereClauseResult.ElementResults[0].StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, result.WhereClauseResult.ElementResults[0].OperandStatusCodes)
}

func TestValidateEventFilterRejectsUnsupportedWhereClause(t *testing.T) {
	t.Parallel()

	filter := &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{
			monitoredItemTestSelectClause("Severity"),
		},
		WhereClause: &ua.ContentFilter{
			Elements: []*ua.ContentFilterElement{
				{
					FilterOperator: ua.FilterOperatorLike,
					FilterOperands: []*ua.ExtensionObject{
						ua.NewExtensionObject(monitoredItemTestSelectClause("Severity")),
						ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(500))}),
					},
				},
			},
		},
	}
	resultObj := newEventFilterResult(filter)

	status := validateEventFilter(filter, resultObj)

	require.Equal(t, ua.StatusBadMonitoredItemFilterUnsupported, status)
	result, ok := resultObj.Value.(*ua.EventFilterResult)
	require.True(t, ok, "expected EventFilterResult, got %T", resultObj.Value)
	require.NotNil(t, result.WhereClauseResult)
	require.Len(t, result.WhereClauseResult.ElementResults, 1)
	assert.Equal(t, ua.StatusBadFilterOperatorUnsupported, result.WhereClauseResult.ElementResults[0].StatusCode)
}

func monitoredItemTestSelectClause(path ...string) *ua.SimpleAttributeOperand {
	browsePath := make([]*ua.QualifiedName, len(path))
	for i, name := range path {
		browsePath[i] = &ua.QualifiedName{NamespaceIndex: 0, Name: name}
	}
	return &ua.SimpleAttributeOperand{
		TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
		BrowsePath:       browsePath,
		AttributeID:      ua.AttributeIDValue,
	}
}

func monitoredItemTestSeverityWhereClause(operator ua.FilterOperator, threshold uint16) *ua.ContentFilter {
	return &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: operator,
				FilterOperands: []*ua.ExtensionObject{
					ua.NewExtensionObject(monitoredItemTestSelectClause("Severity")),
					ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(threshold)}),
				},
			},
		},
	}
}
