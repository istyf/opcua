package node

import (
	"context"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodNodeUserExecutableDefaultsToStaticExecutable(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 1001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
		Executable(true),
	)

	assert.True(t, method.IsExecutable(t.Context()))
	assert.True(t, method.UserExecutable(t.Context()))
}

func TestMethodNodeUserExecutableUsesHandlerAndNarrowsStaticExecutable(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 1002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
		Executable(true),
	)

	method.SetUserExecutableHandler(func(context.Context) bool {
		return false
	})
	assert.False(t, method.UserExecutable(t.Context()))

	method.SetExecutable(false)
	method.SetUserExecutableHandler(func(context.Context) bool {
		return true
	})
	assert.False(t, method.UserExecutable(t.Context()))
}

func TestMethodNodeSeparatesExecutableAndUserExecutable(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 1003)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
		Executable(true),
		UserExecutable(false),
	)

	assert.True(t, method.IsExecutable(t.Context()))
	assert.False(t, method.UserExecutable(t.Context()))

	executable, err := method.Attribute(t.Context(), ua.AttributeIDExecutable)
	require.NoError(t, err)
	require.NotNil(t, executable)
	assert.Equal(t, true, executable.Value.Value.Value())

	userExecutable, err := method.Attribute(t.Context(), ua.AttributeIDUserExecutable)
	require.NoError(t, err)
	require.NotNil(t, userExecutable)
	assert.Equal(t, false, userExecutable.Value.Value.Value())

	method.SetExecutable(false)

	executable, err = method.Attribute(t.Context(), ua.AttributeIDExecutable)
	require.NoError(t, err)
	require.NotNil(t, executable)
	assert.Equal(t, false, executable.Value.Value.Value())

	userExecutable, err = method.Attribute(t.Context(), ua.AttributeIDUserExecutable)
	require.NoError(t, err)
	require.NotNil(t, userExecutable)
	assert.Equal(t, false, userExecutable.Value.Value.Value())

	method.SetExecutable(true)
	method.SetUserExecutable(true)

	assert.True(t, method.IsExecutable(t.Context()))
	assert.True(t, method.UserExecutable(t.Context()))
}

func TestVariableNodeUserAccessLevelDefaultsToStaticAccessLevel(t *testing.T) {
	t.Parallel()

	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newAuthzTestVariableTypeNode()),
		WithAccessLevel(uint8(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite)),
		WithValue(int32(42)),
	)

	assert.Equal(t,
		ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite,
		variable.UserAccessLevel(t.Context()),
	)
}

func TestVariableNodeUserAccessLevelCallbackOverridesStaticAccessLevelBaseline(t *testing.T) {
	t.Parallel()

	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2003)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newAuthzTestVariableTypeNode()),
		WithAccessLevel(uint8(ua.AccessLevelTypeCurrentRead)),
		WithValue(int32(42)),
	)

	assert.Equal(t, ua.AccessLevelTypeCurrentRead, variable.UserAccessLevel(t.Context()))

	variable.SetUserAccessLevelHandler(func(context.Context, ua.AccessLevelType) ua.AccessLevelType {
		return ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite
	})
	assert.Equal(t,
		ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite,
		variable.UserAccessLevel(t.Context()),
	)
}

func TestVariableNodeUserAccessLevelUsesHandlerAndNarrowsStaticAccessLevel(t *testing.T) {
	t.Parallel()

	variable := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 2002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Variable"}),
		),
		WithVariableType(newAuthzTestVariableTypeNode()),
		WithAccessLevel(uint8(ua.AccessLevelTypeCurrentRead)),
		WithValue(int32(42)),
	)

	variable.SetUserAccessLevelHandler(func(context.Context, ua.AccessLevelType) ua.AccessLevelType {
		return ua.AccessLevelTypeCurrentRead
	})

	assert.Equal(t, ua.AccessLevelTypeCurrentRead, variable.UserAccessLevel(t.Context()))
}

func newAuthzTestVariableTypeNode() *variableTypeNode {
	return NewVariableTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.BaseDataVariableType)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BaseDataVariableType"}),
		),
		WithDefaultValue(ua.NewNumericNodeID(0, id.Int32), -1, int32(0)),
	).(*variableTypeNode)
}
