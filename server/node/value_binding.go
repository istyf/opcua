package node

import (
	"sync"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

type valueBinding struct {
	mu        sync.RWMutex
	value     any
	listeners []func()
}

type Binding[T any] interface {
	Snapshot() T
	OnChange(func())
}

type MutableBinding[T any] interface {
	Binding[T]
	Set(T)
}

type typedBinding[T any] struct {
	mu        sync.RWMutex
	value     T
	listeners []func()
}

// NewBinding returns an in-memory mutable typed binding that can be projected
// into one or more dynamic variable values.
func NewBinding[T any](initial T) MutableBinding[T] {
	return &typedBinding[T]{value: initial}
}

type callbackBinding[T any] struct {
	snapshot func() T
	onChange func(func())
}

// NewCallbackBinding adapts snapshot and change-notification callbacks to a
// typed binding source.
func NewCallbackBinding[T any](snapshot func() T, onChange func(func())) Binding[T] {
	return &callbackBinding[T]{snapshot: snapshot, onChange: onChange}
}

func (b *typedBinding[T]) Snapshot() T {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.value
}

func (b *typedBinding[T]) OnChange(fn func()) {
	if fn == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, fn)
}

func (b *typedBinding[T]) Set(value T) {
	b.mu.Lock()
	b.value = value
	listeners := append([]func(){}, b.listeners...)
	b.mu.Unlock()

	for _, listener := range listeners {
		listener()
	}
}

func (b *callbackBinding[T]) Snapshot() T {
	return b.snapshot()
}

func (b *callbackBinding[T]) OnChange(fn func()) {
	if b.onChange != nil {
		b.onChange(fn)
	}
}

// NewValueBinding returns an in-memory mutable binding for simple dynamic
// variable values.
func NewValueBinding(initial any) types.MutableValueBinding {
	return &valueBinding{value: initial}
}

func (b *valueBinding) Snapshot() any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.value
}

func (b *valueBinding) OnChange(fn func()) {
	if fn == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, fn)
}

func (b *valueBinding) Set(value any) {
	b.mu.Lock()
	b.value = value
	listeners := append([]func(){}, b.listeners...)
	b.mu.Unlock()

	for _, listener := range listeners {
		listener()
	}
}

type dataValueBinding struct {
	mu        sync.RWMutex
	value     *ua.DataValue
	listeners []func()
}

// NewDataValueBinding returns an in-memory mutable binding for dynamic
// variables that need full OPC UA DataValue semantics.
func NewDataValueBinding(initial *ua.DataValue) types.MutableDataValueBinding {
	return &dataValueBinding{value: cloneDataValue(initial)}
}

func (b *dataValueBinding) SnapshotDataValue() *ua.DataValue {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return cloneDataValue(b.value)
}

func (b *dataValueBinding) OnChange(fn func()) {
	if fn == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, fn)
}

func (b *dataValueBinding) SetDataValue(value *ua.DataValue) {
	b.mu.Lock()
	b.value = cloneDataValue(value)
	listeners := append([]func(){}, b.listeners...)
	b.mu.Unlock()

	for _, listener := range listeners {
		listener()
	}
}
