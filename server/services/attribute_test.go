package services_test

import (
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
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

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset: %v", err)
	}

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
	if err != nil {
		t.Fatalf("read datatype definition attribute: %v", err)
	}

	readResp, ok := resp.(*ua.ReadResponse)
	if !ok {
		t.Fatalf("expected *ua.ReadResponse, got %T", resp)
	}
	if len(readResp.Results) != 1 {
		t.Fatalf("expected 1 read result, got %d", len(readResp.Results))
	}

	got := readResp.Results[0]
	if got == nil || got.Value == nil {
		t.Fatalf("expected datatype definition value, got %#v", got)
	}

	extObj, ok := got.Value.Value().(*ua.ExtensionObject)
	if !ok {
		t.Fatalf("expected datatype definition as *ua.ExtensionObject, got %T", got.Value.Value())
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

	if err := srv.ImportNodeSet(t.Context(), nodes); err != nil {
		t.Fatalf("import nodeset: %v", err)
	}

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
	if err != nil {
		t.Fatalf("browse structure subtypes: %v", err)
	}

	browseResp, ok := browseRespRaw.(*ua.BrowseResponse)
	if !ok {
		t.Fatalf("expected *ua.BrowseResponse, got %T", browseRespRaw)
	}
	if len(browseResp.Results) != 1 {
		t.Fatalf("expected 1 browse result, got %d", len(browseResp.Results))
	}

	var importedRef *ua.ReferenceDescription
	for _, ref := range browseResp.Results[0].References {
		if ref != nil && ref.BrowseName != nil && ref.BrowseName.Name == "1:CustomStruct" {
			importedRef = ref
			break
		}
	}
	if importedRef == nil {
		t.Fatalf("expected browse to return imported custom datatype, got %#v", browseResp.Results[0].References)
	}
	if importedRef.NodeID == nil || importedRef.NodeID.NodeID == nil {
		t.Fatalf("expected imported browse result to include a local node id, got %#v", importedRef.NodeID)
	}

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
	if err != nil {
		t.Fatalf("read datatype definition attribute: %v", err)
	}

	readResp, ok := readRespRaw.(*ua.ReadResponse)
	if !ok {
		t.Fatalf("expected *ua.ReadResponse, got %T", readRespRaw)
	}
	if len(readResp.Results) != 1 {
		t.Fatalf("expected 1 read result, got %d", len(readResp.Results))
	}

	got := readResp.Results[0]
	if got == nil || got.Value == nil {
		t.Fatalf("expected datatype definition value, got %#v", got)
	}

	extObj, ok := got.Value.Value().(*ua.ExtensionObject)
	if !ok {
		t.Fatalf("expected datatype definition as *ua.ExtensionObject, got %T", got.Value.Value())
	}
	structure, ok := extObj.Value.(*ua.StructureDefinition)
	if !ok {
		t.Fatalf("expected datatype definition payload *ua.StructureDefinition, got %T", extObj.Value)
	}
	if len(structure.Fields) != 1 {
		t.Fatalf("expected 1 structure field, got %d", len(structure.Fields))
	}
	if structure.Fields[0].Name != "Temperature" {
		t.Fatalf("expected field name Temperature, got %q", structure.Fields[0].Name)
	}
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
