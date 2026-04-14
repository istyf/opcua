package server

import (
	"testing"

	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

func TestImportNodeSetLoadsDataTypeDefinitionAttribute(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:types"},
		},
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "MyBaseType", Value: "i=22"},
				{AliasAttr: "MyFieldType", Value: "i=6"},
			},
		},
		UADataType: []*schema.UADataType{
			{
				Definition: &schema.DataTypeDefinition{
					NameAttr:     "CustomStruct",
					BaseTypeAttr: "MyBaseType",
					Field: []*schema.DataTypeField{
						{
							NameAttr:     "Temperature",
							DataTypeAttr: "MyFieldType",
						},
					},
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3001",
						BrowseNameAttr: "1:CustomStruct",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomStruct"}},
					},
				},
			},
		},
	}

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset: %v", err)
	}

	imported := srv.Node(ua.NewNumericNodeID(1, 3001))
	if imported == nil {
		t.Fatal("expected imported datatype node, got nil")
	}

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	if err != nil {
		t.Fatalf("read datatype definition attribute: %v", err)
	}

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	if !ok {
		t.Fatalf("expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	}
	structure, ok := extObj.Value.(*ua.StructureDefinition)
	if !ok {
		t.Fatalf("expected datatype definition payload *ua.StructureDefinition, got %T", extObj.Value)
	}
	if structure.BaseDataType == nil || !structure.BaseDataType.Equal(ua.NewNumericNodeID(0, 22)) {
		t.Fatalf("expected base datatype i=22, got %#v", structure.BaseDataType)
	}
	if len(structure.Fields) != 1 {
		t.Fatalf("expected 1 structure field, got %d", len(structure.Fields))
	}
	if structure.Fields[0].DataType == nil || !structure.Fields[0].DataType.Equal(ua.NewNumericNodeID(0, 6)) {
		t.Fatalf("expected field datatype i=6, got %#v", structure.Fields[0].DataType)
	}
}

func TestImportNodeSetSkipsDeprecatedNodesByDefault(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:deprecated"},
		},
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "Organizes", Value: "i=35"},
			},
		},
		UAObject: []*schema.UAObject{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3100",
						BrowseNameAttr: "1:CurrentNode",
						DisplayName:    []*schema.LocalizedText{{Value: "CurrentNode"}},
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{
								{
									ReferenceTypeAttr: "Organizes",
									Value:             "ns=1;i=3101",
								},
							},
						},
					},
				},
			},
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:        "ns=1;i=3101",
						BrowseNameAttr:    "1:DeprecatedNode",
						DisplayName:       []*schema.LocalizedText{{Value: "DeprecatedNode"}},
						ReleaseStatusAttr: "Deprecated",
					},
				},
			},
		},
	}

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset with deprecated node: %v", err)
	}

	current := srv.Node(ua.NewNumericNodeID(1, 3100))
	if current == nil {
		t.Fatal("expected non-deprecated node to be imported")
	}

	deprecated := srv.Node(ua.NewNumericNodeID(1, 3101))
	if deprecated != nil {
		t.Fatal("expected deprecated node to be skipped by default")
	}

	if current.References().Contains(func(ref types.ReferenceWrapper) bool {
		target := ref.TargetNodeID()
		return target != nil && target.NodeID != nil && target.NodeID.Equal(ua.NewNumericNodeID(1, 3101))
	}) {
		t.Fatal("expected no reference targeting skipped deprecated node")
	}
}

func TestImportNodeSetSkipsMalformedDataTypeDefinition(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:types"},
		},
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "HasSubtype", Value: "i=45"},
			},
		},
		UADataType: []*schema.UADataType{
			{
				Definition: &schema.DataTypeDefinition{
					NameAttr: "BrokenStruct",
					Field: []*schema.DataTypeField{
						{
							NameAttr:     "Broken",
							DataTypeAttr: "abc=0;i=2",
						},
					},
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3002",
						BrowseNameAttr: "1:BrokenStruct",
						DisplayName:    []*schema.LocalizedText{{Value: "BrokenStruct"}},
					},
				},
			},
		},
	}

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset with malformed datatype definition: %v", err)
	}

	imported := srv.Node(ua.NewNumericNodeID(1, 3002))
	if imported == nil {
		t.Fatal("expected imported datatype node, got nil")
	}

	if _, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition); err == nil {
		t.Fatal("expected malformed datatype definition to leave attribute unset")
	}
}

func TestImportNodeSetLoadsEnumDataTypeDefinitionAttribute(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:types"},
		},
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "HasSubtype", Value: "i=45"},
			},
		},
		UADataType: []*schema.UADataType{
			{
				Definition: &schema.DataTypeDefinition{
					NameAttr: "PumpState",
					Field: []*schema.DataTypeField{
						{
							NameAttr:    "Stopped",
							ValueAttr:   0,
							DisplayName: []*schema.LocalizedText{{Value: "Stopped"}},
							Description: []*schema.LocalizedText{{Value: "Pump stopped"}},
						},
						{
							NameAttr:    "Running",
							ValueAttr:   1,
							DisplayName: []*schema.LocalizedText{{Value: "Running"}},
							Description: []*schema.LocalizedText{{Value: "Pump running"}},
						},
					},
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3010",
						BrowseNameAttr: "1:PumpState",
						DisplayName:    []*schema.LocalizedText{{Value: "PumpState"}},
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{
								{
									ReferenceTypeAttr: "HasSubtype",
									IsForwardAttr:     new(false),
									Value:             "i=29",
								},
							},
						},
					},
				},
			},
		},
	}

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset: %v", err)
	}

	imported := srv.Node(ua.NewNumericNodeID(1, 3010))
	if imported == nil {
		t.Fatal("expected imported enum datatype node, got nil")
	}

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	if err != nil {
		t.Fatalf("read datatype definition attribute: %v", err)
	}

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	if !ok {
		t.Fatalf("expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	}
	enumDefinition, ok := extObj.Value.(*ua.EnumDefinition)
	if !ok {
		t.Fatalf("expected datatype definition payload *ua.EnumDefinition, got %T", extObj.Value)
	}
	if len(enumDefinition.Fields) != 2 {
		t.Fatalf("expected 2 enum fields, got %d", len(enumDefinition.Fields))
	}
	if enumDefinition.Fields[0].Value != 0 || enumDefinition.Fields[1].Value != 1 {
		t.Fatalf("expected enum values [0 1], got [%d %d]", enumDefinition.Fields[0].Value, enumDefinition.Fields[1].Value)
	}
	if enumDefinition.Fields[1].DisplayName == nil || enumDefinition.Fields[1].DisplayName.Text != "Running" {
		t.Fatalf("expected second enum display name Running, got %#v", enumDefinition.Fields[1].DisplayName)
	}
}

func TestImportNodeSetLoadsOptionSetDataTypeDefinitionAttribute(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:types"},
		},
		UADataType: []*schema.UADataType{
			{
				Definition: &schema.DataTypeDefinition{
					NameAttr:        "AlarmMask",
					IsOptionSetAttr: true,
					Field: []*schema.DataTypeField{
						{
							NameAttr:    "High",
							ValueAttr:   1,
							DisplayName: []*schema.LocalizedText{{Value: "High"}},
						},
						{
							NameAttr:    "Low",
							ValueAttr:   4,
							DisplayName: []*schema.LocalizedText{{Value: "Low"}},
						},
					},
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3011",
						BrowseNameAttr: "1:AlarmMask",
						DisplayName:    []*schema.LocalizedText{{Value: "AlarmMask"}},
					},
				},
			},
		},
	}

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset: %v", err)
	}

	imported := srv.Node(ua.NewNumericNodeID(1, 3011))
	if imported == nil {
		t.Fatal("expected imported option-set datatype node, got nil")
	}

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	if err != nil {
		t.Fatalf("read datatype definition attribute: %v", err)
	}

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	if !ok {
		t.Fatalf("expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	}
	enumDefinition, ok := extObj.Value.(*ua.EnumDefinition)
	if !ok {
		t.Fatalf("expected datatype definition payload *ua.EnumDefinition, got %T", extObj.Value)
	}
	if len(enumDefinition.Fields) != 2 {
		t.Fatalf("expected 2 option-set fields, got %d", len(enumDefinition.Fields))
	}
	if enumDefinition.Fields[0].Value != 1 || enumDefinition.Fields[1].Value != 4 {
		t.Fatalf("expected option-set bit values [1 4], got [%d %d]", enumDefinition.Fields[0].Value, enumDefinition.Fields[1].Value)
	}
}
