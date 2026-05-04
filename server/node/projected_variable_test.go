package node

import (
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectedVariableInstanceSynchronizesMainAndProperties(t *testing.T) {
	t.Parallel()

	source := NewBinding(projectedStateSnapshot{
		DisplayName: ua.NewLocalizedText("Idle"),
		ID:          int32(11),
		Name:        "Idle",
		Number:      uint32(3),
	})

	instance := NewProjectedVariableInstance(
		source,
		ProjectedVariableSpec[projectedStateSnapshot]{
			Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3001)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "CurrentState"})),
			VariableType: newProjectedMainVariableTypeNode(),
			Value: func(s projectedStateSnapshot) any {
				return s.DisplayName
			},
		},
		ProjectedPropertySpec[projectedStateSnapshot]{
			ProjectedVariableSpec: ProjectedVariableSpec[projectedStateSnapshot]{
				Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3002)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Id"})),
				VariableType: newProjectedPropertyVariableTypeNode(),
				Value: func(s projectedStateSnapshot) any {
					return s.ID
				},
			},
		},
		ProjectedPropertySpec[projectedStateSnapshot]{
			ProjectedVariableSpec: ProjectedVariableSpec[projectedStateSnapshot]{
				Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3003)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Name"})),
				VariableType: newProjectedPropertyVariableTypeNode(),
				Value: func(s projectedStateSnapshot) any {
					return s.Name
				},
			},
		},
	)

	assertProjectedVariableValue(t, instance.Main, "Idle")
	assertProjectedVariableValue(t, instance.Properties["Id"], int32(11))
	assertProjectedVariableValue(t, instance.Properties["Name"], "Idle")

	source.Set(projectedStateSnapshot{
		DisplayName: ua.NewLocalizedText("Running"),
		ID:          int32(12),
		Name:        "Running",
		Number:      uint32(4),
	})

	assertProjectedVariableValue(t, instance.Main, "Running")
	assertProjectedVariableValue(t, instance.Properties["Id"], int32(12))
	assertProjectedVariableValue(t, instance.Properties["Name"], "Running")
}

func TestProjectedVariableInstanceSupportsDataValueProjection(t *testing.T) {
	t.Parallel()

	source := NewBinding(projectedStateSnapshot{
		DisplayName: ua.NewLocalizedText("Hidden"),
		ID:          int32(17),
		Name:        "Hidden",
		Number:      uint32(9),
		Active:      false,
	})

	instance := NewProjectedVariableInstance(
		source,
		ProjectedVariableSpec[projectedStateSnapshot]{
			Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3101)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "CurrentState"})),
			VariableType: newProjectedMainVariableTypeNode(),
			DataValue: func(s projectedStateSnapshot) *ua.DataValue {
				if !s.Active {
					return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadStateNotActive}
				}
				return &ua.DataValue{
					EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
					Value:        ua.MustVariant(s.DisplayName),
					Status:       ua.StatusOK,
				}
			},
		},
		ProjectedPropertySpec[projectedStateSnapshot]{
			ProjectedVariableSpec: ProjectedVariableSpec[projectedStateSnapshot]{
				Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3102)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "Number"})),
				VariableType: newProjectedPropertyVariableTypeNode(),
				DataValue: func(s projectedStateSnapshot) *ua.DataValue {
					if !s.Active {
						return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadStateNotActive}
					}
					return &ua.DataValue{
						EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
						Value:        ua.MustVariant(s.Number),
						Status:       ua.StatusOK,
					}
				},
			},
		},
	)

	mainAttr, err := instance.Main.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, mainAttr)
	assert.Equal(t, ua.StatusBadStateNotActive, mainAttr.Value.Status)

	numberAttr, err := instance.Properties["Number"].Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, numberAttr)
	assert.Equal(t, ua.StatusBadStateNotActive, numberAttr.Value.Status)

	source.Set(projectedStateSnapshot{
		DisplayName: ua.NewLocalizedText("Ready"),
		ID:          int32(18),
		Name:        "Ready",
		Number:      uint32(10),
		Active:      true,
	})

	assertProjectedVariableValue(t, instance.Main, "Ready")
	assertProjectedVariableValue(t, instance.Properties["Number"], uint32(10))
}

func TestProjectedVariableInstanceFiniteStateStyleExample(t *testing.T) {
	t.Parallel()

	source := NewBinding(projectedStateSnapshot{
		DisplayName: ua.NewLocalizedText("Executing"),
		ID:          int32(99),
		Name:        "Executing",
		Number:      uint32(7),
		Active:      true,
	})

	instance := NewProjectedVariableInstance(
		source,
		ProjectedVariableSpec[projectedStateSnapshot]{
			Base:         WithBase(WithID(ua.NewNumericNodeID(1, 3201)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: "CurrentState"})),
			VariableType: newProjectedMainVariableTypeNode(),
			Value: func(s projectedStateSnapshot) any {
				return s.DisplayName
			},
		},
		projectedStateProperty("Id", 3202, func(s projectedStateSnapshot) any { return s.ID }),
		projectedStateProperty("Name", 3203, func(s projectedStateSnapshot) any { return s.Name }),
		projectedStateProperty("Number", 3204, func(s projectedStateSnapshot) any { return s.Number }),
	)

	assertProjectedVariableValue(t, instance.Main, "Executing")
	assertProjectedVariableValue(t, instance.Properties["Id"], int32(99))
	assertProjectedVariableValue(t, instance.Properties["Name"], "Executing")
	assertProjectedVariableValue(t, instance.Properties["Number"], uint32(7))
}

func projectedStateProperty(name string, idVal uint32, projector func(projectedStateSnapshot) any) ProjectedPropertySpec[projectedStateSnapshot] {
	return ProjectedPropertySpec[projectedStateSnapshot]{
		ProjectedVariableSpec: ProjectedVariableSpec[projectedStateSnapshot]{
			Base:         WithBase(WithID(ua.NewNumericNodeID(1, idVal)), WithBrowseName(&ua.QualifiedName{NamespaceIndex: 1, Name: name})),
			VariableType: newProjectedPropertyVariableTypeNode(),
			Value:        projector,
		},
	}
}

func assertProjectedVariableValue(t *testing.T, variable types.VariableNode, want any) {
	t.Helper()

	attr, err := variable.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)
	require.NotNil(t, attr)
	require.NotNil(t, attr.Value)
	require.NotNil(t, attr.Value.Value)

	got := attr.Value.Value.Value()
	switch wantVal := want.(type) {
	case string:
		switch typed := got.(type) {
		case *ua.LocalizedText:
			assert.Equal(t, wantVal, typed.Text)
		default:
			assert.Equal(t, wantVal, got)
		}
	default:
		assert.Equal(t, want, got)
	}
}

type projectedStateSnapshot struct {
	DisplayName *ua.LocalizedText
	ID          int32
	Name        string
	Number      uint32
	Active      bool
}

func newProjectedMainVariableTypeNode() types.VariableTypeNode {
	return NewVariableTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.BaseDataVariableType)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "BaseDataVariableType"}),
		),
		WithDefaultValue(ua.NewNumericNodeID(0, id.LocalizedText), -1, ua.NewLocalizedText("")),
	)
}

func newProjectedPropertyVariableTypeNode() types.VariableTypeNode {
	return NewVariableTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.PropertyType)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "PropertyType"}),
		),
		WithDefaultValue(ua.NewNumericNodeID(0, id.BaseDataType), -1, int32(0)),
	)
}
