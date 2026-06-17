package node

import (
	"context"
	"fmt"
	"reflect"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type methodNode struct {
	baseNode

	executable            bool
	userExecutable        bool
	userExecutableHandler types.MethodUserExecutableHandler
	call                  types.MethodFunc
}

type methodCallSetter interface {
	setMethodCall(types.MethodFunc)
}

type methodConfig struct {
	executable            bool
	userExecutable        *bool
	userExecutableHandler types.MethodUserExecutableHandler
	handler               types.MethodFunc
}

type methodOption func(*methodConfig)

func Executable(executable bool) methodOption {
	return func(cfg *methodConfig) {
		cfg.executable = executable
	}
}

func UserExecutable(executable bool) methodOption {
	return func(cfg *methodConfig) {
		cfg.userExecutable = new(bool)
		*cfg.userExecutable = executable
	}
}

func WithHandler(handler types.MethodFunc) methodOption {
	return func(cfg *methodConfig) {
		cfg.handler = handler
	}
}

func WithUserExecutableHandler(handler types.MethodUserExecutableHandler) methodOption {
	return func(cfg *methodConfig) {
		cfg.userExecutableHandler = handler
	}
}

func NewMethodNode(base func(ua.NodeClass) *baseConfig, opts ...methodOption) types.MethodNode {

	cfg := &methodConfig{}
	for _, applyOption := range opts {
		applyOption(cfg)
	}
	userExecutable := cfg.executable
	if cfg.userExecutable != nil {
		userExecutable = *cfg.userExecutable
	}

	n := &methodNode{
		baseNode:              *newBaseNode(base(ua.NodeClassMethod)),
		call:                  cfg.handler,
		executable:            cfg.executable,
		userExecutable:        userExecutable,
		userExecutableHandler: cfg.userExecutableHandler,
	}

	n.baseNode.attr[ua.AttributeIDExecutable] = values.DataValueFromValue(n.executable)
	n.baseNode.attr[ua.AttributeIDUserExecutable] = values.DataValueFromValue(n.userExecutable)

	return n
}

func (n *methodNode) CallMethod(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
	if n.call == nil {
		return types.NewMethodResult(ua.StatusBadNotImplemented)
	}

	return n.call(ctx, args...)
}

func (n *methodNode) Attribute(ctx context.Context, id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDUserExecutable {
		return NewAttrValue(values.DataValueFromValue(n.UserExecutable(ctx))), nil
	}

	return n.baseNode.Attribute(ctx, id)
}

func (n *methodNode) IsExecutable(context.Context) bool {
	return n.executable
}

func (n *methodNode) UserExecutable(ctx context.Context) bool {
	if !n.executable {
		return false
	}
	if !n.userExecutable {
		return false
	}
	if n.userExecutableHandler == nil {
		return true
	}
	return n.userExecutableHandler(ctx)
}

func (n *methodNode) SetExecutable(executable bool) {
	if n.executable != executable {
		n.executable = executable

		n.baseNode.attr[ua.AttributeIDExecutable] = values.DataValueFromValue(executable)
	}
}

func (n *methodNode) SetUserExecutable(executable bool) {
	if n.userExecutable != executable {
		n.userExecutable = executable
		n.baseNode.attr[ua.AttributeIDUserExecutable] = values.DataValueFromValue(executable)
	}
}

func (n *methodNode) SetUserExecutableHandler(handler types.MethodUserExecutableHandler) {
	n.userExecutableHandler = handler
}

func (n *methodNode) setMethodCall(call types.MethodFunc) {
	n.call = call
}

func resultForExactArgumentCount(args []*ua.Variant, expected int) *types.MethodResult {
	switch {
	case len(args) < expected:
		results := make([]ua.StatusCode, expected)
		for idx := range expected {
			if idx < len(args) {
				results[idx] = ua.StatusOK
				continue
			}
			results[idx] = ua.StatusBadArgumentsMissing
		}
		return &types.MethodResult{
			StatusCode:           ua.StatusBadArgumentsMissing,
			InputArgumentResults: results,
		}
	case len(args) > expected:
		results := make([]ua.StatusCode, len(args))
		for idx := range results {
			if idx < expected {
				results[idx] = ua.StatusOK
				continue
			}
			results[idx] = ua.StatusBadTooManyArguments
		}
		return &types.MethodResult{
			StatusCode:           ua.StatusBadTooManyArguments,
			InputArgumentResults: results,
		}
	default:
		return nil
	}
}

func decodeRequiredArgument[T any](args []*ua.Variant, idx int) (T, *types.MethodResult) {
	val, ok := decodeInputParameter[T](args[idx])
	if !ok {
		var zero T
		return zero, resultForArgumentTypeMismatch(len(args), idx)
	}
	return val, nil
}

func decodeRequiredArgumentSlice[T any](args []*ua.Variant, idx int) ([]T, *types.MethodResult) {
	val, ok := decodeInputParameterSlice[T](args[idx])
	if !ok {
		return nil, resultForArgumentTypeMismatch(len(args), idx)
	}
	return val, nil
}

func resultForArgumentTypeMismatch(argumentCount, failedIdx int) *types.MethodResult {
	results := make([]ua.StatusCode, argumentCount)
	for idx := range results {
		results[idx] = ua.StatusOK
	}
	if failedIdx >= 0 && failedIdx < len(results) {
		results[failedIdx] = ua.StatusBadTypeMismatch
	}
	return &types.MethodResult{
		StatusCode:           ua.StatusBadTypeMismatch,
		InputArgumentResults: results,
	}
}

func validateMethodWrapperSignature(n types.MethodNode, expected []expectedMethodArgument) {
	args, ok := MethodInputArguments(n)
	if !ok {
		return
	}

	if len(args) != len(expected) {
		panic(fmt.Sprintf(
			"method wrapper signature mismatch for %s: metadata declares %d input arguments, wrapper expects %d",
			n.BrowseName().String(),
			len(args),
			len(expected),
		))
	}

	for idx, exp := range expected {
		arg := args[idx]
		if arg == nil {
			continue
		}

		if !ValueRankMatches(exp.valueRank, arg.ValueRank) {
			panic(fmt.Sprintf(
				"method wrapper signature mismatch for %s argument %d (%s): metadata value rank %d is incompatible with wrapper rank %d",
				n.BrowseName().String(),
				idx,
				arg.Name,
				arg.ValueRank,
				exp.valueRank,
			))
		}

		if !methodDataTypeCompatible(exp.dataType, arg.DataType) {
			panic(fmt.Sprintf(
				"method wrapper signature mismatch for %s argument %d (%s): metadata data type %s is incompatible with wrapper data type %s",
				n.BrowseName().String(), idx, arg.Name, arg.DataType.String(), exp.dataType.String(),
			))
		}
	}
}

func methodDataTypeCompatible(wrapperDataType, metadataDataType *ua.NodeID) bool {
	if wrapperDataType == nil || metadataDataType == nil {
		return true
	}

	if wrapperDataType.Equal(metadataDataType) {
		return true
	}

	wrapperDataType = canonicalMethodDataType(wrapperDataType)
	metadataDataType = canonicalMethodDataType(metadataDataType)

	return wrapperDataType.Equal(metadataDataType)
}

func canonicalMethodDataType(nodeID *ua.NodeID) *ua.NodeID {
	if nodeID == nil || nodeID.Namespace() != 0 {
		return nodeID
	}

	switch nodeID.IntID() {
	case id.IntegerID: // OPC UA IntegerId simple type, encoded as UInt32
		return ua.NewNumericNodeID(0, id.UInt32)
	default:
		return nodeID
	}
}

type expectedMethodArgument struct {
	dataType  *ua.NodeID
	valueRank int32
}

func expectedScalarArgument[T any]() expectedMethodArgument {
	return expectedMethodArgument{
		dataType:  expectedArgumentDataType[T](),
		valueRank: expectedArgumentValueRank[T](),
	}
}

func expectedSliceArgument[T any]() expectedMethodArgument {
	return expectedMethodArgument{
		dataType:  expectedArgumentDataType[[]T](),
		valueRank: 1,
	}
}

func expectedArgumentDataType[T any]() *ua.NodeID {
	typ := reflect.TypeFor[T]()
	var zero any
	switch typ.Kind() {
	case reflect.Slice:
		zero = reflect.Zero(typ).Interface()
	case reflect.Pointer:
		zero = reflect.Zero(typ).Interface()
	default:
		zero = reflect.Zero(typ).Interface()
	}

	dataType, _ := LookupTypeNodeIDFromValue(zero)
	return dataType
}

func expectedArgumentValueRank[T any]() int32 {
	typ := reflect.TypeFor[T]()
	if typ.Kind() == reflect.Slice {
		return 1
	}
	return -1
}

func methodCallSetterFor(n types.MethodNode) methodCallSetter {
	setter, ok := n.(methodCallSetter)
	if !ok {
		panic("method node does not support wrapped handlers")
	}
	return setter
}

func SetMethod(n types.MethodNode, fn func(context.Context) error) {
	validateMethodWrapperSignature(n, nil)
	methodCallSetterFor(n).setMethodCall(func(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
		if result := resultForExactArgumentCount(args, 0); result != nil {
			return result
		}

		return types.NewMethodResult(mapError(fn(ctx)))
	})
}

func SetMethod1S[T any](n types.MethodNode, fn func(context.Context, []T) error) {
	validateMethodWrapperSignature(n, []expectedMethodArgument{expectedSliceArgument[T]()})
	methodCallSetterFor(n).setMethodCall(func(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
		if result := resultForExactArgumentCount(args, 1); result != nil {
			return result
		}

		argVal, result := decodeRequiredArgumentSlice[T](args, 0)
		if result != nil {
			return result
		}

		return types.NewMethodResult(mapError(fn(ctx, argVal)))
	})
}

func SetMethod1[T any](n types.MethodNode, fn func(context.Context, T) error) {
	validateMethodWrapperSignature(n, []expectedMethodArgument{expectedScalarArgument[T]()})
	methodCallSetterFor(n).setMethodCall(func(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
		if result := resultForExactArgumentCount(args, 1); result != nil {
			return result
		}

		argVal, result := decodeRequiredArgument[T](args, 0)
		if result != nil {
			return result
		}

		return types.NewMethodResult(mapError(fn(ctx, argVal)))
	})
}

func SetMethod2[T, U any](n types.MethodNode, fn func(context.Context, T, U) error) {
	validateMethodWrapperSignature(n, []expectedMethodArgument{
		expectedScalarArgument[T](),
		expectedScalarArgument[U](),
	})
	methodCallSetterFor(n).setMethodCall(func(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
		if result := resultForExactArgumentCount(args, 2); result != nil {
			return result
		}

		arg0Val, result := decodeRequiredArgument[T](args, 0)
		if result != nil {
			return result
		}

		arg1Val, result := decodeRequiredArgument[U](args, 1)
		if result != nil {
			return result
		}

		return types.NewMethodResult(mapError(fn(ctx, arg0Val, arg1Val)))
	})
}

func SetMethod3[T, U, V any](n types.MethodNode, fn func(context.Context, T, U, V) error) {
	validateMethodWrapperSignature(n, []expectedMethodArgument{
		expectedScalarArgument[T](),
		expectedScalarArgument[U](),
		expectedScalarArgument[V](),
	})
	methodCallSetterFor(n).setMethodCall(func(ctx context.Context, args ...*ua.Variant) *types.MethodResult {
		if result := resultForExactArgumentCount(args, 3); result != nil {
			return result
		}

		arg0Val, result := decodeRequiredArgument[T](args, 0)
		if result != nil {
			return result
		}

		arg1Val, result := decodeRequiredArgument[U](args, 1)
		if result != nil {
			return result
		}

		arg2Val, result := decodeRequiredArgument[V](args, 2)
		if result != nil {
			return result
		}

		return types.NewMethodResult(mapError(fn(ctx, arg0Val, arg1Val, arg2Val)))
	})
}

func decodeInputParameter[T any](v *ua.Variant) (val T, ok bool) {
	if val, ok = v.Value().(T); ok {
		return
	}

	if extObj := v.ExtensionObject(); extObj != nil {
		if val, ok = extObj.Value.(T); ok {
			return
		}

		var ptr *T
		if ptr, ok = extObj.Value.(*T); ok {
			if ptr != nil {
				val = *ptr
			}
		}
	}

	return
}

func decodeInputParameterSlice[T any](v *ua.Variant) (val []T, ok bool) {
	if val, ok = v.Value().([]T); ok {
		return
	}

	if extObj := v.ExtensionObject(); extObj != nil {
		if val, ok = extObj.Value.([]T); ok {
			return
		}
	}

	if v.ArrayLength() > 0 {
		var eos []*ua.ExtensionObject
		if eos, ok = v.Value().([]*ua.ExtensionObject); ok {
			val = make([]T, 0, v.ArrayLength())
			for idx := range eos {
				if t, ok := eos[idx].Value.(T); ok {
					val = append(val, t)
				}
			}
			ok = len(val) == int(v.ArrayLength())
		}
	}

	return
}

func mapError(err error) ua.StatusCode {
	if err == nil {
		return ua.StatusOK
	}

	if code, ok := err.(ua.StatusCode); ok {
		return code
	}

	return ua.StatusBadUnexpectedError
}
