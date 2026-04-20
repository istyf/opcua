package server

import (
	"testing"

	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSchemaDataTypeDefinitionStructure(t *testing.T) {
	t.Parallel()

	definition := &schema.DataTypeDefinition{
		NameAttr: "CustomStruct",
		Field: []*schema.DataTypeField{
			{
				NameAttr:            "Temperature",
				SymbolicNameAttr:    "Temp",
				DataTypeAttr:        "ns=1;i=3001",
				ValueRankAttr:       -1,
				ArrayDimensionsAttr: "2, 4",
				MaxStringLengthAttr: 64,
				IsOptionalAttr:      true,
				AllowSubTypesAttr:   true,
				Description: []*schema.LocalizedText{
					{Value: "Temperature field", LocaleAttr: "en"},
				},
			},
		},
	}

	resolvedNodeID := ua.NewNumericNodeID(1, 3001)
	got, err := convertSchemaDataTypeDefinition(definition, importedDataTypeClassification{
		kind:          importedDataTypeDefinitionStructure,
		structureType: ua.StructureTypeStructureWithOptionalFields,
	}, func(fieldType string) (*ua.NodeID, error) {
		assert.Equal(t, "ns=1;i=3001", fieldType)
		return resolvedNodeID, nil
	})
	require.NoError(t, err)

	structure, ok := got.(*ua.StructureDefinition)
	require.True(t, ok, "expected *ua.StructureDefinition, got %T", got)
	assert.Nil(t, structure.BaseDataType)
	assert.Equal(t, ua.StructureTypeStructureWithOptionalFields, structure.StructureType)
	require.Len(t, structure.Fields, 1)

	field := structure.Fields[0]
	assert.Equal(t, "Temperature", field.Name)
	require.NotNil(t, field.DataType)
	assert.True(t, field.DataType.Equal(resolvedNodeID))
	assert.Equal(t, int32(-1), field.ValueRank)
	assert.Equal(t, []uint32{2, 4}, field.ArrayDimensions)
	assert.Equal(t, uint32(64), field.MaxStringLength)
	assert.True(t, field.IsOptional)
	require.NotNil(t, field.Description)
	assert.Equal(t, "Temperature field", field.Description.Text)
}

func TestConvertSchemaStructureFieldUsesDisplayNameAsDescriptionFallback(t *testing.T) {
	t.Parallel()

	field, err := convertSchemaStructureField(&schema.DataTypeField{
		NameAttr:      "Status",
		DataTypeAttr:  "ns=1;i=3002",
		ValueRankAttr: -1,
		DisplayName: []*schema.LocalizedText{
			{Value: "Status field", LocaleAttr: "en"},
		},
	}, func(string) (*ua.NodeID, error) {
		return ua.NewNumericNodeID(1, 3002), nil
	})
	require.NoError(t, err)

	require.NotNil(t, field.Description)
	assert.Equal(t, "Status field", field.Description.Text)
}

func TestConvertSchemaDataTypeDefinitionEnum(t *testing.T) {
	t.Parallel()

	definition := &schema.DataTypeDefinition{
		NameAttr: "CustomEnum",
		Field: []*schema.DataTypeField{
			{
				NameAttr:  "Idle",
				ValueAttr: 1,
				DisplayName: []*schema.LocalizedText{
					{Value: "Idle", LocaleAttr: "en"},
				},
				Description: []*schema.LocalizedText{
					{Value: "Idle state", LocaleAttr: "en"},
				},
			},
		},
	}

	got, err := convertSchemaDataTypeDefinition(definition, importedDataTypeClassification{kind: importedDataTypeDefinitionEnum}, nil)
	require.NoError(t, err)

	enumDefinition, ok := got.(*ua.EnumDefinition)
	require.True(t, ok, "expected *ua.EnumDefinition, got %T", got)
	require.Len(t, enumDefinition.Fields, 1)

	field := enumDefinition.Fields[0]
	assert.Equal(t, "Idle", field.Name)
	assert.Equal(t, int64(1), field.Value)
	require.NotNil(t, field.DisplayName)
	assert.Equal(t, "Idle", field.DisplayName.Text)
	require.NotNil(t, field.Description)
	assert.Equal(t, "Idle state", field.Description.Text)
}

func TestConvertSchemaDataTypeDefinitionOptionSet(t *testing.T) {
	t.Parallel()

	definition := &schema.DataTypeDefinition{
		NameAttr:        "AlarmMask",
		IsOptionSetAttr: true,
		Field: []*schema.DataTypeField{
			{
				NameAttr:         "HighHigh",
				SymbolicNameAttr: "HH",
				ValueAttr:        1,
				DisplayName: []*schema.LocalizedText{
					{Value: "HighHigh", LocaleAttr: "en"},
				},
			},
			{
				NameAttr:  "LowLow",
				ValueAttr: 8,
				Description: []*schema.LocalizedText{
					{Value: "Low low alarm bit", LocaleAttr: "en"},
				},
			},
		},
	}

	got, err := convertSchemaDataTypeDefinition(definition, importedDataTypeClassification{kind: importedDataTypeDefinitionEnum}, nil)
	require.NoError(t, err)

	enumDefinition, ok := got.(*ua.EnumDefinition)
	require.True(t, ok, "expected *ua.EnumDefinition, got %T", got)
	require.Len(t, enumDefinition.Fields, 2)

	assert.Equal(t, "HighHigh", enumDefinition.Fields[0].Name)
	assert.Equal(t, int64(1), enumDefinition.Fields[0].Value)
	require.NotNil(t, enumDefinition.Fields[0].DisplayName)
	assert.Equal(t, "HighHigh", enumDefinition.Fields[0].DisplayName.Text)
	assert.Equal(t, "LowLow", enumDefinition.Fields[1].Name)
	assert.Equal(t, int64(8), enumDefinition.Fields[1].Value)
	require.NotNil(t, enumDefinition.Fields[1].Description)
	assert.Equal(t, "Low low alarm bit", enumDefinition.Fields[1].Description.Text)
}

func TestConvertSchemaDataTypeDefinitionRejectsInvalidKind(t *testing.T) {
	t.Parallel()

	_, err := convertSchemaDataTypeDefinition(&schema.DataTypeDefinition{}, importedDataTypeClassification{}, nil)
	assert.Error(t, err)
}

func TestResolveSchemaStructureBaseDataType(t *testing.T) {
	t.Parallel()

	falseValue := false

	tests := []struct {
		name     string
		dataType *schema.UADataType
		wantID   *ua.NodeID
		wantErr  bool
	}{
		{
			name: "definition base type takes precedence",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{
					BaseTypeAttr: "ns=1;i=5001",
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{{
								ReferenceTypeAttr: "i=45",
								IsForwardAttr:     &falseValue,
								Value:             "ns=1;i=22",
							}},
						},
					},
				},
			},
			wantID: ua.NewNumericNodeID(1, 5001),
		},
		{
			name: "supertype is used when base type attr is absent",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{{
								ReferenceTypeAttr: "i=45",
								IsForwardAttr:     &falseValue,
								Value:             "ns=1;i=22",
							}},
						},
					},
				},
			},
			wantID: ua.NewNumericNodeID(1, 22),
		},
		{
			name: "missing supertype returns nil",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{},
			},
			wantID: nil,
		},
		{
			name:     "missing definition is rejected",
			dataType: &schema.UADataType{},
			wantErr:  true,
		},
	}

	resolver := func(nodeID string) (*ua.NodeID, error) {
		return ua.ParseNodeID(nodeID)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveSchemaStructureBaseDataType(tt.dataType, resolver)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantID == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.True(t, got.Equal(tt.wantID))
		})
	}
}

func TestConvertSchemaStructureDefinitionRejectsInvalidArrayDimensions(t *testing.T) {
	t.Parallel()

	_, err := convertSchemaDataTypeDefinition(&schema.DataTypeDefinition{
		Field: []*schema.DataTypeField{
			{
				NameAttr:            "Broken",
				DataTypeAttr:        "ns=1;i=3001",
				ArrayDimensionsAttr: "2, nope",
			},
		},
	}, importedDataTypeClassification{kind: importedDataTypeDefinitionStructure}, func(string) (*ua.NodeID, error) {
		return ua.NewNumericNodeID(1, 3001), nil
	})
	assert.Error(t, err)
}

func TestClassifySchemaDataTypeDefinition(t *testing.T) {
	t.Parallel()

	falseValue := false

	tests := []struct {
		name     string
		dataType *schema.UADataType
		want     importedDataTypeClassification
		wantErr  bool
	}{
		{
			name: "enumeration supertype becomes enum",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{{
								ReferenceTypeAttr: "i=45",
								IsForwardAttr:     &falseValue,
								Value:             "i=29",
							}},
						},
					},
				},
			},
			want: importedDataTypeClassification{kind: importedDataTypeDefinitionEnum},
		},
		{
			name: "option set flag becomes enum",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{IsOptionSetAttr: true},
			},
			want: importedDataTypeClassification{kind: importedDataTypeDefinitionEnum},
		},
		{
			name: "union with subtyped fields becomes union with subtyped values",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{
					IsUnionAttr: true,
					Field: []*schema.DataTypeField{{
						AllowSubTypesAttr: true,
					}},
				},
			},
			want: importedDataTypeClassification{
				kind:          importedDataTypeDefinitionStructure,
				structureType: ua.StructureTypeUnionWithSubtypedValues,
			},
		},
		{
			name: "optional fields become optional structure",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{
					Field: []*schema.DataTypeField{{
						IsOptionalAttr: true,
					}},
				},
			},
			want: importedDataTypeClassification{
				kind:          importedDataTypeDefinitionStructure,
				structureType: ua.StructureTypeStructureWithOptionalFields,
			},
		},
		{
			name: "plain structure defaults to structure",
			dataType: &schema.UADataType{
				Definition: &schema.DataTypeDefinition{},
			},
			want: importedDataTypeClassification{
				kind:          importedDataTypeDefinitionStructure,
				structureType: ua.StructureTypeStructure,
			},
		},
		{
			name:     "missing definition is rejected",
			dataType: &schema.UADataType{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := classifySchemaDataTypeDefinition(tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewImportedNodeIDResolver(t *testing.T) {
	t.Parallel()

	nsMap := nsIDLookup{2: 7}
	resolver := newImportedNodeIDResolver(map[string]string{
		"TemperatureType": "ns=2;i=3001",
	}, &nsMap)

	got, err := resolver("TemperatureType")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint16(7), got.Namespace())
	assert.Equal(t, uint32(3001), got.IntID())
}

func TestNewImportedNodeIDResolverWithoutAlias(t *testing.T) {
	t.Parallel()

	nsMap := nsIDLookup{1: 5}
	resolver := newImportedNodeIDResolver(nil, &nsMap)

	got, err := resolver("ns=1;i=42")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint16(5), got.Namespace())
	assert.Equal(t, uint32(42), got.IntID())
}

func TestNewImportedNodeIDResolverRejectsInvalidNodeID(t *testing.T) {
	t.Parallel()

	resolver := newImportedNodeIDResolver(nil, nil)

	_, err := resolver("abc=0;i=2")
	assert.Error(t, err)
}
