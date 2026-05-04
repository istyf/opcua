package node

import (
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

// ProjectedVariableInstance is a variable node together with synchronized
// property child variables that are all projected from the same source.
type ProjectedVariableInstance struct {
	Main       types.VariableNode
	Properties map[string]types.VariableNode
}

// ProjectedVariableSpec describes one projected output variable created from a
// shared source binding.
type ProjectedVariableSpec[T any] struct {
	Base          func(ua.NodeClass) *baseConfig
	VariableType  types.VariableTypeNode
	DataType      *ua.NodeID
	ValueRank     int32
	Historizing   bool
	AccessLevel   *uint8
	AccessLevelEx *uint32
	Value         func(T) any
	DataValue     func(T) *ua.DataValue
}

// ProjectedPropertySpec describes one synchronized property child variable
// created from the same source binding as the main variable.
type ProjectedPropertySpec[T any] struct {
	ProjectedVariableSpec[T]
}

// NewProjectedVariableInstance creates a main variable and synchronized
// property child variables from one shared typed source binding.
func NewProjectedVariableInstance[T any](
	source Binding[T],
	main ProjectedVariableSpec[T],
	properties ...ProjectedPropertySpec[T],
) *ProjectedVariableInstance {
	mainNode := newProjectedVariableNode(source, main)
	propertyNodes := make(map[string]types.VariableNode, len(properties))

	for _, property := range properties {
		propertyNode := newProjectedVariableNode(source, property.ProjectedVariableSpec)
		refs.LinkWithHasPropertyReferenceDescriptions(mainNode, propertyNode)
		if browseName := propertyNode.BrowseName(); browseName != nil {
			propertyNodes[browseName.Name] = propertyNode
		}
	}

	return &ProjectedVariableInstance{
		Main:       mainNode,
		Properties: propertyNodes,
	}
}

func newProjectedVariableNode[T any](source Binding[T], spec ProjectedVariableSpec[T]) types.VariableNode {
	opts := []variableOption{
		WithVariableType(spec.VariableType),
		WithHistorization(spec.Historizing),
	}

	if spec.AccessLevel != nil {
		opts = append(opts, WithAccessLevel(*spec.AccessLevel))
	}
	if spec.AccessLevelEx != nil {
		opts = append(opts, WithAccessLevelEx(*spec.AccessLevelEx))
	}
	if spec.DataType != nil {
		opts = append(opts, WithDataType(spec.DataType))
	}
	if spec.ValueRank != 0 {
		opts = append(opts, WithValueRank(spec.ValueRank))
	}

	switch {
	case spec.DataValue != nil:
		opts = append(opts, WithDataValueBinding(projectedDataValueBinding(source, spec.DataValue)))
	case spec.Value != nil:
		opts = append(opts, WithValueBinding(projectedValueBinding(source, spec.Value)))
	default:
		panic("projected variable spec requires either a Value or DataValue projector")
	}

	return NewVariableNode(spec.Base, opts...)
}

type projectedValueBindingImpl[T any] struct {
	source  Binding[T]
	project func(T) any
}

func projectedValueBinding[T any](source Binding[T], project func(T) any) types.ValueBinding {
	return &projectedValueBindingImpl[T]{source: source, project: project}
}

func (b *projectedValueBindingImpl[T]) Snapshot() any {
	return b.project(b.source.Snapshot())
}

func (b *projectedValueBindingImpl[T]) OnChange(fn func()) {
	b.source.OnChange(fn)
}

type projectedDataValueBindingImpl[T any] struct {
	source  Binding[T]
	project func(T) *ua.DataValue
}

func projectedDataValueBinding[T any](source Binding[T], project func(T) *ua.DataValue) types.DataValueBinding {
	return &projectedDataValueBindingImpl[T]{source: source, project: project}
}

func (b *projectedDataValueBindingImpl[T]) SnapshotDataValue() *ua.DataValue {
	return cloneDataValue(b.project(b.source.Snapshot()))
}

func (b *projectedDataValueBindingImpl[T]) OnChange(fn func()) {
	b.source.OnChange(fn)
}
