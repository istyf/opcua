package server

import (
	"testing"

	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/ua"
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
		if fieldType != "ns=1;i=3001" {
			t.Fatalf("expected resolver input %q, got %q", "ns=1;i=3001", fieldType)
		}
		return resolvedNodeID, nil
	})
	if err != nil {
		t.Fatalf("convert schema structure definition: %v", err)
	}

	structure, ok := got.(*ua.StructureDefinition)
	if !ok {
		t.Fatalf("expected *ua.StructureDefinition, got %T", got)
	}
	if structure.BaseDataType != nil {
		t.Fatalf("expected structure base datatype to be unset in direct conversion helper, got %#v", structure.BaseDataType)
	}
	if structure.StructureType != ua.StructureTypeStructureWithOptionalFields {
		t.Fatalf("expected structure type %v, got %v", ua.StructureTypeStructureWithOptionalFields, structure.StructureType)
	}
	if len(structure.Fields) != 1 {
		t.Fatalf("expected 1 structure field, got %d", len(structure.Fields))
	}

	field := structure.Fields[0]
	if field.Name != "Temperature" {
		t.Fatalf("expected field name %q, got %q", "Temperature", field.Name)
	}
	if field.DataType == nil || !field.DataType.Equal(resolvedNodeID) {
		t.Fatalf("expected field datatype %#v, got %#v", resolvedNodeID, field.DataType)
	}
	if field.ValueRank != -1 {
		t.Fatalf("expected value rank -1, got %d", field.ValueRank)
	}
	if len(field.ArrayDimensions) != 2 || field.ArrayDimensions[0] != 2 || field.ArrayDimensions[1] != 4 {
		t.Fatalf("expected array dimensions [2 4], got %#v", field.ArrayDimensions)
	}
	if field.MaxStringLength != 64 {
		t.Fatalf("expected max string length 64, got %d", field.MaxStringLength)
	}
	if !field.IsOptional {
		t.Fatal("expected field to be optional")
	}
	if field.Description == nil || field.Description.Text != "Temperature field" {
		t.Fatalf("expected description %q, got %#v", "Temperature field", field.Description)
	}
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
	if err != nil {
		t.Fatalf("convert schema structure field: %v", err)
	}

	if field.Description == nil || field.Description.Text != "Status field" {
		t.Fatalf("expected display name fallback %q, got %#v", "Status field", field.Description)
	}
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
	if err != nil {
		t.Fatalf("convert schema enum definition: %v", err)
	}

	enumDefinition, ok := got.(*ua.EnumDefinition)
	if !ok {
		t.Fatalf("expected *ua.EnumDefinition, got %T", got)
	}
	if len(enumDefinition.Fields) != 1 {
		t.Fatalf("expected 1 enum field, got %d", len(enumDefinition.Fields))
	}

	field := enumDefinition.Fields[0]
	if field.Name != "Idle" {
		t.Fatalf("expected field name %q, got %q", "Idle", field.Name)
	}
	if field.Value != 1 {
		t.Fatalf("expected field value 1, got %d", field.Value)
	}
	if field.DisplayName == nil || field.DisplayName.Text != "Idle" {
		t.Fatalf("expected display name %q, got %#v", "Idle", field.DisplayName)
	}
	if field.Description == nil || field.Description.Text != "Idle state" {
		t.Fatalf("expected description %q, got %#v", "Idle state", field.Description)
	}
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
	if err != nil {
		t.Fatalf("convert schema option set definition: %v", err)
	}

	enumDefinition, ok := got.(*ua.EnumDefinition)
	if !ok {
		t.Fatalf("expected *ua.EnumDefinition, got %T", got)
	}
	if len(enumDefinition.Fields) != 2 {
		t.Fatalf("expected 2 enum fields, got %d", len(enumDefinition.Fields))
	}

	if enumDefinition.Fields[0].Name != "HighHigh" || enumDefinition.Fields[0].Value != 1 {
		t.Fatalf("expected first option set field to preserve name/value, got %#v", enumDefinition.Fields[0])
	}
	if enumDefinition.Fields[0].DisplayName == nil || enumDefinition.Fields[0].DisplayName.Text != "HighHigh" {
		t.Fatalf("expected first option set display name %q, got %#v", "HighHigh", enumDefinition.Fields[0].DisplayName)
	}
	if enumDefinition.Fields[1].Name != "LowLow" || enumDefinition.Fields[1].Value != 8 {
		t.Fatalf("expected second option set field to preserve bit value 8, got %#v", enumDefinition.Fields[1])
	}
	if enumDefinition.Fields[1].Description == nil || enumDefinition.Fields[1].Description.Text != "Low low alarm bit" {
		t.Fatalf("expected second option set description %q, got %#v", "Low low alarm bit", enumDefinition.Fields[1].Description)
	}
}

func TestConvertSchemaDataTypeDefinitionRejectsInvalidKind(t *testing.T) {
	t.Parallel()

	_, err := convertSchemaDataTypeDefinition(&schema.DataTypeDefinition{}, importedDataTypeClassification{}, nil)
	if err == nil {
		t.Fatal("expected unsupported kind to return an error")
	}
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
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve schema structure base datatype: %v", err)
			}
			if tt.wantID == nil {
				if got != nil {
					t.Fatalf("expected nil base datatype, got %#v", got)
				}
				return
			}
			if got == nil || !got.Equal(tt.wantID) {
				t.Fatalf("expected base datatype %#v, got %#v", tt.wantID, got)
			}
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
	if err == nil {
		t.Fatal("expected invalid array dimensions to return an error")
	}
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
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("classify schema datatype definition: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected classification %#v, got %#v", tt.want, got)
			}
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
	if err != nil {
		t.Fatalf("resolve aliased node id: %v", err)
	}
	if got == nil {
		t.Fatal("expected resolved node id, got nil")
	}
	if got.Namespace() != 7 {
		t.Fatalf("expected remapped namespace 7, got %d", got.Namespace())
	}
	if got.IntID() != 3001 {
		t.Fatalf("expected numeric id 3001, got %d", got.IntID())
	}
}

func TestNewImportedNodeIDResolverWithoutAlias(t *testing.T) {
	t.Parallel()

	nsMap := nsIDLookup{1: 5}
	resolver := newImportedNodeIDResolver(nil, &nsMap)

	got, err := resolver("ns=1;i=42")
	if err != nil {
		t.Fatalf("resolve direct node id: %v", err)
	}
	if got == nil {
		t.Fatal("expected resolved node id, got nil")
	}
	if got.Namespace() != 5 {
		t.Fatalf("expected remapped namespace 5, got %d", got.Namespace())
	}
	if got.IntID() != 42 {
		t.Fatalf("expected numeric id 42, got %d", got.IntID())
	}
}

func TestNewImportedNodeIDResolverRejectsInvalidNodeID(t *testing.T) {
	t.Parallel()

	resolver := newImportedNodeIDResolver(nil, nil)

	if _, err := resolver("abc=0;i=2"); err == nil {
		t.Fatal("expected invalid node id to return an error")
	}
}
