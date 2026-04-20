package services_test

import (
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadReturnsImportedDataTypeDefinitionAttribute(t *testing.T) {
	t.Parallel()

	srv := server.New(t.Context())

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
						NodeIdAttr:     "ns=1;i=3101",
						BrowseNameAttr: "1:CustomStruct",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomStruct"}},
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	svc := services.NewAttributeService(&attributeTestBackend{srv: srv})
	resp, err := svc.Read(t.Context(), nil, &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle: 7,
		},
		NodesToRead: []*ua.ReadValueID{
			{
				NodeID:      ua.NewNumericNodeID(1, 3101),
				AttributeID: ua.AttributeIDDataTypeDefinition,
			},
		},
	}, 7)
	require.NoError(t, err)

	readResp, ok := resp.(*ua.ReadResponse)
	require.True(t, ok, "expected *ua.ReadResponse, got %T", resp)
	require.Len(t, readResp.Results, 1)

	got := readResp.Results[0]
	require.NotNil(t, got)
	require.NotNil(t, got.Value)

	extObj, ok := got.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected datatype definition as *ua.ExtensionObject, got %T", got.Value.Value())
	structure, ok := extObj.Value.(*ua.StructureDefinition)
	require.True(t, ok, "expected datatype definition payload *ua.StructureDefinition, got %T", extObj.Value)
	require.NotNil(t, structure.BaseDataType)
	assert.True(t, structure.BaseDataType.Equal(ua.NewNumericNodeID(0, 22)))
	require.Len(t, structure.Fields, 1)
	require.NotNil(t, structure.Fields[0].DataType)
	assert.True(t, structure.Fields[0].DataType.Equal(ua.NewNumericNodeID(0, 6)))
}

func TestBrowseAndReadImportedDataTypeDefinition(t *testing.T) {
	t.Parallel()

	srv := server.New(t.Context())

	nodes := &schema.UANodeSet{
		NamespaceUris: &schema.UriTable{
			Uri: []string{"urn:test:types"},
		},
		Aliases: &schema.AliasTable{
			Alias: []*schema.NodeIdAlias{
				{AliasAttr: "HasSubtype", Value: "i=45"},
				{AliasAttr: "MyFieldType", Value: "i=6"},
			},
		},
		UADataType: []*schema.UADataType{
			{
				Definition: &schema.DataTypeDefinition{
					NameAttr: "CustomStruct",
					Field: []*schema.DataTypeField{
						{
							NameAttr:     "Temperature",
							DataTypeAttr: "MyFieldType",
						},
					},
				},
				UAType: &schema.UAType{
					UANode: &schema.UANode{
						NodeIdAttr:     "ns=1;i=3102",
						BrowseNameAttr: "1:CustomStruct",
						DisplayName:    []*schema.LocalizedText{{Value: "CustomStruct"}},
						References: &schema.ListOfReferences{
							Reference: []*schema.Reference{
								{
									ReferenceTypeAttr: "HasSubtype",
									IsForwardAttr:     new(false),
									Value:             "i=22",
								},
							},
						},
					},
				},
			},
		},
	}

	require.NoError(t, srv.ImportNodeSet(t.Context(), nodes))

	backend := &attributeTestBackend{srv: srv}
	viewSvc := services.NewViewService(backend)
	browseRespRaw, err := viewSvc.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle: 11,
		},
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          ua.NewNumericNodeID(0, id.Structure),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HasSubtype),
				IncludeSubtypes: false,
				ResultMask: uint32(
					ua.BrowseResultMaskBrowseName |
						ua.BrowseResultMaskNodeClass,
				),
			},
		},
	}, 11)
	require.NoError(t, err)

	browseResp, ok := browseRespRaw.(*ua.BrowseResponse)
	require.True(t, ok, "expected *ua.BrowseResponse, got %T", browseRespRaw)
	require.Len(t, browseResp.Results, 1)

	var importedRef *ua.ReferenceDescription
	for _, ref := range browseResp.Results[0].References {
		if ref != nil && ref.BrowseName != nil && ref.BrowseName.Name == "CustomStruct" {
			importedRef = ref
			break
		}
	}
	require.NotNil(t, importedRef, "expected browse to return imported custom datatype, got %#v", browseResp.Results[0].References)
	require.NotNil(t, importedRef.NodeID)
	require.NotNil(t, importedRef.NodeID.NodeID)

	attrSvc := services.NewAttributeService(backend)
	readRespRaw, err := attrSvc.Read(t.Context(), nil, &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle: 12,
		},
		NodesToRead: []*ua.ReadValueID{
			{
				NodeID:      importedRef.NodeID.NodeID,
				AttributeID: ua.AttributeIDDataTypeDefinition,
			},
		},
	}, 12)
	require.NoError(t, err)

	readResp, ok := readRespRaw.(*ua.ReadResponse)
	require.True(t, ok, "expected *ua.ReadResponse, got %T", readRespRaw)
	require.Len(t, readResp.Results, 1)

	got := readResp.Results[0]
	require.NotNil(t, got)
	require.NotNil(t, got.Value)

	extObj, ok := got.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected datatype definition as *ua.ExtensionObject, got %T", got.Value.Value())
	structure, ok := extObj.Value.(*ua.StructureDefinition)
	require.True(t, ok, "expected datatype definition payload *ua.StructureDefinition, got %T", extObj.Value)
	require.Len(t, structure.Fields, 1)
	assert.Equal(t, "Temperature", structure.Fields[0].Name)
}

type attributeTestBackend struct {
	srv types.Server
}

func (*attributeTestBackend) RegisterHandler(int, services.Handler) {}

func (b *attributeTestBackend) Namespace(id int) (types.NameSpace, error) {
	return b.srv.Namespace(id)
}

func (b *attributeTestBackend) Node(id *ua.NodeID) types.Node {
	return b.srv.Node(id)
}

func (b *attributeTestBackend) Config() types.ServerConfig {
	return b.srv.Config()
}
