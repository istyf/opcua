package node

import (
	"context"

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

func (n *methodNode) CallMethod(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if n.call == nil {
		return nil, ua.StatusBadNotImplemented
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

func SetMethod(n *methodNode, fn func(context.Context) error) {
	n.call = func(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) > 0 {
			return nil, ua.StatusBadTooManyArguments
		}

		return nil, mapError(fn(ctx))
	}
}

func SetMethod1S[T any](n *methodNode, fn func(context.Context, []T) error) {
	n.call = func(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) == 0 {
			return nil, ua.StatusBadArgumentsMissing
		}

		if len(args) > 1 {
			return nil, ua.StatusBadTooManyArguments
		}

		argVal, ok := decodeInputParameterSlice[T](args[0])
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}

		return nil, mapError(fn(ctx, argVal))
	}
}

func SetMethod1[T any](n *methodNode, fn func(context.Context, T) error) {
	n.call = func(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) == 0 {
			return nil, ua.StatusBadArgumentsMissing
		}

		if len(args) > 1 {
			return nil, ua.StatusBadTooManyArguments
		}

		argVal, ok := decodeInputParameter[T](args[0])
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}

		return nil, mapError(fn(ctx, argVal))
	}
}

func SetMethod2[T, U any](n *methodNode, fn func(context.Context, T, U) error) {
	n.call = func(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) < 2 {
			return nil, ua.StatusBadArgumentsMissing
		}

		if len(args) > 2 {
			return nil, ua.StatusBadTooManyArguments
		}

		arg0Val, ok0 := decodeInputParameter[T](args[0])
		arg1Val, ok1 := decodeInputParameter[U](args[1])
		if !ok0 || !ok1 {
			return nil, ua.StatusBadTypeMismatch
		}

		return nil, mapError(fn(ctx, arg0Val, arg1Val))
	}
}

func SetMethod3[T, U, V any](n *methodNode, fn func(context.Context, T, U, V) error) {
	n.call = func(ctx context.Context, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) < 3 {
			return nil, ua.StatusBadArgumentsMissing
		}

		if len(args) > 3 {
			return nil, ua.StatusBadTooManyArguments
		}

		arg0Val, ok0 := decodeInputParameter[T](args[0])
		arg1Val, ok1 := decodeInputParameter[U](args[1])
		arg2Val, ok2 := decodeInputParameter[V](args[1])
		if !ok0 || !ok1 || !ok2 {
			return nil, ua.StatusBadTypeMismatch
		}

		return nil, mapError(fn(ctx, arg0Val, arg1Val, arg2Val))
	}
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
