package node

import (
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVariableNodeMutableValueBindingUpdatesValue(t *testing.T) {
	t.Parallel()

	binding := NewValueBinding(int32(42))
	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2101)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newBindingTestVariableTypeNode()),
		WithValueBinding(binding),
	)

	attr, err := variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	assert.Equal(t, int32(42), attr.Value.Value.Value())

	binding.Set(int32(99))

	attr, err = variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	assert.Equal(t, int32(99), attr.Value.Value.Value())
}

func TestVariableNodeMutableDataValueBindingUpdatesDataValue(t *testing.T) {
	t.Parallel()

	binding := NewDataValueBinding(&ua.DataValue{
		EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
		Value:        ua.MustVariant(int32(1)),
		Status:       ua.StatusOK,
	})
	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2102)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newBindingTestVariableTypeNode()),
		WithDataValueBinding(binding),
	)

	attr, err := variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	assert.Equal(t, int32(1), attr.Value.Value.Value())

	binding.SetDataValue(&ua.DataValue{
		EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
		Value:        ua.MustVariant(int32(2)),
		Status:       ua.StatusBadOutOfService,
	})

	attr, err = variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	assert.Equal(t, int32(2), attr.Value.Value.Value())
	assert.Equal(t, ua.StatusBadOutOfService, attr.Value.Status)
}

func TestVariableNodeDataValueBindingCanReturnNonOKStatus(t *testing.T) {
	t.Parallel()

	binding := NewDataValueBinding(&ua.DataValue{
		EncodingMask: ua.DataValueStatusCode,
		Status:       ua.StatusBadStateNotActive,
	})
	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2103)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newBindingTestVariableTypeNode()),
		WithDataValueBinding(binding),
	)

	attr, err := variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	assert.Equal(t, ua.StatusBadStateNotActive, attr.Value.Status)
	assert.Nil(t, attr.Value.Value)
}

func TestVariableNodeValueAndDataValueCallbacksRemainCompatible(t *testing.T) {
	t.Parallel()

	valueVariable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2104)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "ValueVariable"}),
		),
		WithVariableType(newBindingTestVariableTypeNode()),
		WithValueFunc(func() any { return int32(55) }),
	)

	valueAttr, err := valueVariable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, valueAttr)
	assert.Equal(t, int32(55), valueAttr.Value.Value.Value())

	dataValueVariable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2105)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "DataValueVariable"}),
		),
		WithVariableType(newBindingTestVariableTypeNode()),
		WithDataValueFunc(func() *ua.DataValue {
			return &ua.DataValue{
				EncodingMask: ua.DataValueStatusCode,
				Status:       ua.StatusBadStateNotActive,
			}
		}),
	)

	dataValueAttr, err := dataValueVariable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, dataValueAttr)
	assert.Equal(t, ua.StatusBadStateNotActive, dataValueAttr.Value.Status)
}

func newBindingTestVariableTypeNode() *variableTypeNode {
	return NewVariableTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.BaseDataVariableType)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BaseDataVariableType"}),
		),
		WithDefaultValue(ua.NewNumericNodeID(0, id.Int32), -1, int32(0)),
	).(*variableTypeNode)
}
