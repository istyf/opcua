package node

import (
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectNodeWithEventNotifierTypesExposesSubscribeToEvents(t *testing.T) {
	t.Parallel()

	objectType := NewObjectTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 1001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "ObjectType"}),
		),
	)
	object := NewObjectNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 1002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "EventSource"}),
		),
		WithType(objectType),
		WithEventNotifierTypes(ua.EventNotifierTypeSubscribeToEvents),
	)

	attr, err := object.Attribute(t.Context(), ua.AttributeIDEventNotifier)
	require.NoError(t, err)
	require.NotNil(t, attr)
	require.NotNil(t, attr.Value)
	require.NotNil(t, attr.Value.Value)

	notifier, ok := attr.Value.Value.Value().(uint8)
	require.True(t, ok, "expected EventNotifier as uint8, got %T", attr.Value.Value.Value())
	assert.NotZero(t, notifier&uint8(ua.EventNotifierTypeSubscribeToEvents))
}
