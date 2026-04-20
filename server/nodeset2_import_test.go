package server

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 3001))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	require.NoError(t, err)

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	structure, ok := extObj.Value.(*ua.StructureDefinition)
	require.True(t, ok, "expected datatype definition payload *ua.StructureDefinition, got %T", extObj.Value)
	require.NotNil(t, structure.BaseDataType)
	assert.True(t, structure.BaseDataType.Equal(ua.NewNumericNodeID(0, 22)))
	require.Len(t, structure.Fields, 1)
	require.NotNil(t, structure.Fields[0].DataType)
	assert.True(t, structure.Fields[0].DataType.Equal(ua.NewNumericNodeID(0, 6)))
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

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	current := srv.Node(ua.NewNumericNodeID(1, 3100))
	require.NotNil(t, current)

	deprecated := srv.Node(ua.NewNumericNodeID(1, 3101))
	assert.Nil(t, deprecated)

	assert.False(t, current.References().Contains(func(ref types.ReferenceWrapper) bool {
		target := ref.TargetNodeID()
		return target != nil && target.NodeID != nil && target.NodeID.Equal(ua.NewNumericNodeID(1, 3101))
	}))
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

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 3002))
	require.NotNil(t, imported)

	_, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	assert.Error(t, err)
}

func TestImportNodeSetVariableWithoutExplicitDataTypeInheritsVariableTypeDataType(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:variables"},
		},
		UADataType: []*schema.UADataType{
			{
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4100",
						BrowseNameAttr: "1:CustomDataType",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomDataType"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
		UAVariableType: []*schema.UAVariableType{
			{
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4200",
						BrowseNameAttr: "1:CustomVariableType",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomVariableType"}},
						References:     &schema.ListOfReferences{},
					},
				},
				DataTypeAttr: "ns=1;i=4100",
			},
		},
		UAObject: []*schema.UAObject{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4300",
						BrowseNameAttr: "1:Parent",
						DisplayName:    []*schema.LocalizedText{{Value: "Parent"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
		UAVariable: []*schema.UAVariable{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4301",
						BrowseNameAttr: "1:Child",
						DisplayName:    []*schema.LocalizedText{{Value: "Child"}},
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{
								{
									ReferenceTypeAttr: "i=40",
									Value:             "ns=1;i=4200",
								},
							},
						},
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 4301))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataType)
	require.NoError(t, err)

	got, ok := attr.Value.Value.Value().(*ua.NodeID)
	require.True(t, ok, "expected datatype as *ua.NodeID, got %T", attr.Value.Value.Value())
	assert.True(t, got.Equal(ua.NewNumericNodeID(1, 4100)))
}

func TestImportNodeSetVariableWithoutExplicitDataTypeFallsBackToBaseDataType(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:variables"},
		},
		UAVariableType: []*schema.UAVariableType{
			{
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4400",
						BrowseNameAttr: "1:CustomVariableType",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomVariableType"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
		UAObject: []*schema.UAObject{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4500",
						BrowseNameAttr: "1:Parent",
						DisplayName:    []*schema.LocalizedText{{Value: "Parent"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
		UAVariable: []*schema.UAVariable{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4501",
						BrowseNameAttr: "1:Child",
						DisplayName:    []*schema.LocalizedText{{Value: "Child"}},
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{
								{
									ReferenceTypeAttr: "i=40",
									Value:             "ns=1;i=4400",
								},
							},
						},
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 4501))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataType)
	require.NoError(t, err)

	got, ok := attr.Value.Value.Value().(*ua.NodeID)
	require.True(t, ok, "expected datatype as *ua.NodeID, got %T", attr.Value.Value.Value())
	assert.True(t, got.Equal(ua.NewNumericNodeID(0, id.BaseDataType)))
}

func TestImportNodeSetRemapsBrowseNameNamespaceIndexIndependentlyOfNodeID(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)
	NewNodeNameSpace(srv, "urn:test:existing")

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:imported"},
		},
		UAObject: []*schema.UAObject{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4600",
						BrowseNameAttr: "0:ImportedObject",
						DisplayName:    []*schema.LocalizedText{{Value: "ImportedObject"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(2, 4600))
	require.NotNil(t, imported)

	browseName := imported.BrowseName()
	require.NotNil(t, browseName)
	assert.Equal(t, uint16(0), browseName.NamespaceIndex)
	assert.Equal(t, "ImportedObject", browseName.Name)
}

func TestImportNodeSetRemapsQualifiedNameValues(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)
	NewNodeNameSpace(srv, "urn:test:existing")

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:value"},
		},
		UAVariable: []*schema.UAVariable{
			{
				UAInstance: &schema.UAInstance{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=4700",
						BrowseNameAttr: "1:QualifiedNameValue",
						DisplayName:    []*schema.LocalizedText{{Value: "QualifiedNameValue"}},
						References:     &schema.ListOfReferences{},
					},
				},
				Value: &schema.Value{
					QualifiedNameAttr: &schema.ValueQualifiedName{
						NamespaceIndex: 1,
						Name:           "ImportedName",
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(2, 4700))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDValue)
	require.NoError(t, err)

	got, ok := attr.Value.Value.Value().(*ua.QualifiedName)
	require.True(t, ok, "expected value as *ua.QualifiedName, got %T", attr.Value.Value.Value())
	assert.Equal(t, uint16(2), got.NamespaceIndex)
	assert.Equal(t, "ImportedName", got.Name)
}

func TestRefsImportNodeSetDuplicateReferenceTypeAliasLogging(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	testCtx := func(t *testing.T) (context.Context, *bytes.Buffer) {
		t.Helper()

		var out bytes.Buffer
		handler := slog.NewTextHandler(&out, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})

		return ualog.New(t.Context(), ualog.WithHandler(handler)), &out
	}

	sameTarget := &schema.UANodeSet{
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "HasComponent", Value: "i=47"},
			},
		},
		UAReferenceType: []*schema.UAReferenceType{
			{
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "i=47",
						BrowseNameAttr: "HasComponent",
						DisplayName:    []*schema.LocalizedText{{Value: "HasComponent"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
	}

	ctx, out := testCtx(t)
	require.NoError(t, srv.refsImportNodeSet(ctx, sameTarget, &nsIDLookup{}))
	assert.NotContains(t, out.String(), "duplicate reference type alias points to different target")

	differentTarget := &schema.UANodeSet{
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "HasComponent", Value: "i=35"},
			},
		},
		UAReferenceType: []*schema.UAReferenceType{
			{
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "i=47",
						BrowseNameAttr: "HasComponent",
						DisplayName:    []*schema.LocalizedText{{Value: "HasComponent"}},
						References:     &schema.ListOfReferences{},
					},
				},
			},
		},
	}

	ctx, out = testCtx(t)
	require.NoError(t, srv.refsImportNodeSet(ctx, differentTarget, &nsIDLookup{}))
	assert.Contains(t, out.String(), "duplicate reference type alias points to different target")
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

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 3010))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	require.NoError(t, err)

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	enumDefinition, ok := extObj.Value.(*ua.EnumDefinition)
	require.True(t, ok, "expected datatype definition payload *ua.EnumDefinition, got %T", extObj.Value)
	require.Len(t, enumDefinition.Fields, 2)
	assert.Equal(t, int64(0), enumDefinition.Fields[0].Value)
	assert.Equal(t, int64(1), enumDefinition.Fields[1].Value)
	require.NotNil(t, enumDefinition.Fields[1].DisplayName)
	assert.Equal(t, "Running", enumDefinition.Fields[1].DisplayName.Text)
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

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	imported := srv.Node(ua.NewNumericNodeID(1, 3011))
	require.NotNil(t, imported)

	attr, err := imported.Attribute(t.Context(), ua.AttributeIDDataTypeDefinition)
	require.NoError(t, err)

	extObj, ok := attr.Value.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected datatype definition as *ua.ExtensionObject, got %T", attr.Value.Value.Value())
	enumDefinition, ok := extObj.Value.(*ua.EnumDefinition)
	require.True(t, ok, "expected datatype definition payload *ua.EnumDefinition, got %T", extObj.Value)
	require.Len(t, enumDefinition.Fields, 2)
	assert.Equal(t, int64(1), enumDefinition.Fields[0].Value)
	assert.Equal(t, int64(4), enumDefinition.Fields[1].Value)
}
