package node

import (
	"context"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetMethod3UsesThirdArgumentIndex(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	var gotInt int32
	var gotString string
	var gotBool bool
	SetMethod3(method, func(_ context.Context, a int32, b string, c bool) error {
		gotInt = a
		gotString = b
		gotBool = c
		return nil
	})

	result := method.CallMethod(
		t.Context(),
		ua.MustVariant(int32(7)),
		ua.MustVariant("hello"),
		ua.MustVariant(true),
	)
	require.NotNil(t, result)
	assert.Equal(t, ua.StatusOK, result.StatusCode)
	assert.Equal(t, int32(7), gotInt)
	assert.Equal(t, "hello", gotString)
	assert.True(t, gotBool)
}

func TestSetMethodCallsZeroArgumentHandler(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3005)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	called := false
	SetMethod(method, func(_ context.Context) error {
		called = true
		return nil
	})

	result := method.CallMethod(t.Context())
	require.NotNil(t, result)
	assert.Equal(t, ua.StatusOK, result.StatusCode)
	assert.True(t, called)
}

func TestSetMethod1SDecodesSliceArgument(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3006)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	var got []int32
	SetMethod1S(method, func(_ context.Context, values []int32) error {
		got = append([]int32(nil), values...)
		return nil
	})

	result := method.CallMethod(t.Context(), ua.MustVariant([]int32{1, 2, 3}))
	require.NotNil(t, result)
	assert.Equal(t, ua.StatusOK, result.StatusCode)
	assert.Equal(t, []int32{1, 2, 3}, got)
}

func TestSetMethod1ReturnsTypeMismatchForWrongArgumentType(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	SetMethod1(method, func(_ context.Context, _ int32) error {
		t.Fatal("handler should not be called")
		return nil
	})

	result := method.CallMethod(t.Context(), ua.MustVariant("wrong"))
	require.NotNil(t, result)
	assert.Equal(t, ua.StatusBadTypeMismatch, result.StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch}, result.InputArgumentResults)
}

func TestSetMethod2ReturnsArgumentCountErrors(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3003)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	SetMethod2(method, func(_ context.Context, _ int32, _ string) error {
		t.Fatal("handler should not be called")
		return nil
	})

	missing := method.CallMethod(t.Context(), ua.MustVariant(int32(1)))
	require.NotNil(t, missing)
	assert.Equal(t, ua.StatusBadArgumentsMissing, missing.StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadArgumentsMissing}, missing.InputArgumentResults)

	tooMany := method.CallMethod(
		t.Context(),
		ua.MustVariant(int32(1)),
		ua.MustVariant("two"),
		ua.MustVariant(true),
	)
	require.NotNil(t, tooMany)
	assert.Equal(t, ua.StatusBadTooManyArguments, tooMany.StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusBadTooManyArguments}, tooMany.InputArgumentResults)
}

func TestSetMethod2ReportsWhichArgumentHasTypeMismatch(t *testing.T) {
	t.Parallel()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3004)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	SetMethod2(method, func(_ context.Context, _ int32, _ string) error {
		t.Fatal("handler should not be called")
		return nil
	})

	result := method.CallMethod(t.Context(), ua.MustVariant(int32(1)), ua.MustVariant(true))
	require.NotNil(t, result)
	assert.Equal(t, ua.StatusBadTypeMismatch, result.StatusCode)
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTypeMismatch}, result.InputArgumentResults)
}

func TestSetMethod2PanicsWhenInputArgumentMetadataDeclaresThreeArguments(t *testing.T) {
	t.Parallel()

	method := newMethodNodeWithInputArguments(
		t,
		&ua.Argument{Name: "a", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1},
		&ua.Argument{Name: "b", DataType: ua.NewNumericNodeID(0, id.String), ValueRank: -1},
		&ua.Argument{Name: "c", DataType: ua.NewNumericNodeID(0, id.Boolean), ValueRank: -1},
	)

	require.Panics(t, func() {
		SetMethod2(method, func(_ context.Context, _ int32, _ string) error { return nil })
	})
}

func TestSetMethod1PanicsWhenInputArgumentMetadataShapeDoesNotMatch(t *testing.T) {
	t.Parallel()

	method := newMethodNodeWithInputArguments(
		t,
		&ua.Argument{Name: "values", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: 1},
	)

	require.Panics(t, func() {
		SetMethod1(method, func(_ context.Context, _ int32) error { return nil })
	})
}

func TestSetMethod1AcceptsCompatibleInputArgumentMetadata(t *testing.T) {
	t.Parallel()

	method := newMethodNodeWithInputArguments(
		t,
		&ua.Argument{Name: "value", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1},
	)

	require.NotPanics(t, func() {
		SetMethod1(method, func(_ context.Context, _ int32) error { return nil })
	})
}

func newMethodNodeWithInputArguments(t *testing.T, args ...*ua.Argument) *methodNode {
	t.Helper()

	method := NewMethodNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3100+uint32(len(args)))),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Method"}),
		),
	).(*methodNode)

	extObjs := make([]*ua.ExtensionObject, 0, len(args))
	for _, arg := range args {
		extObjs = append(extObjs, ua.NewExtensionObject(arg))
	}

	inputArgs := NewVariableNode(
		WithBase(
			WithID(ua.NewNumericNodeID(1, 3200+uint32(len(args)))),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "InputArguments"}),
		),
		WithVariableType(newAuthzTestVariableTypeNode()),
		WithDataType(ua.NewNumericNodeID(0, id.Argument)),
		WithValueRank(1),
		WithValue(extObjs),
	)

	method.AddRef(refs.NewReferenceDescription(inputArgs, refs.HasPropertyRefTypeID, true))
	inputArgs.AddRef(refs.NewReferenceDescription(method, refs.HasPropertyRefTypeID, false))

	return method
}
