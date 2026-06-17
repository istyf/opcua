package node

import (
	"context"
	"fmt"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
)

func TestMethodInputArgumentMatchesAcceptsExtensionObjectEncodingForDeclaredDataType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       &ua.ExpandedNodeID{NodeID: ids.binaryEncodingType},
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        &ua.Argument{},
	})

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: -1,
	}, value))
}

func TestMethodInputArgumentMatchesAcceptsXMLExtensionObjectEncodingForDeclaredDataType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       &ua.ExpandedNodeID{NodeID: ids.xmlEncodingType},
		EncodingMask: ua.ExtensionObjectXML,
		Value:        new(ua.XMLElement),
	})

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: -1,
	}, value))
}

func TestMethodInputArgumentMatchesAcceptsExtensionObjectEncodingWithNamespaceURI(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       ua.NewExpandedNodeID(ua.NewNumericNodeID(0, ids.binaryEncodingType.IntID()), "urn:test:method-metadata", 0),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        &ua.Argument{},
	})

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: -1,
	}, value))
}

func TestMethodInputArgumentMatchesRejectsExtensionObjectEncodingForOtherDataType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       &ua.ExpandedNodeID{NodeID: ids.otherBinaryEncodingType},
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        &ua.Argument{},
	})

	assert.False(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: -1,
	}, value))
}

func TestMethodInputArgumentMatchesBuiltinScalarStillMatches(t *testing.T) {
	t.Parallel()

	assert.True(t, MethodInputArgumentMatches(nil, &ua.Argument{
		DataType:  ua.NewNumericNodeID(0, id.Int32),
		ValueRank: -1,
	}, ua.MustVariant(int32(42))))
}

func TestMethodInputArgumentMatchesAcceptsInt32ForDeclaredEnumType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.enumType,
		ValueRank: -1,
	}, ua.MustVariant(int32(2))))
}

func TestMethodInputArgumentMatchesAcceptsBuiltinForDeclaredSimpleSubtype(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.integerIDType,
		ValueRank: -1,
	}, ua.MustVariant(uint32(1))))
}

func TestMethodInputArgumentMatchesRejectsInt32ForNonEnumDeclaredType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)

	assert.False(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: -1,
	}, ua.MustVariant(int32(2))))
}

func TestMethodInputArgumentMatchesArrayStillMatches(t *testing.T) {
	t.Parallel()

	assert.True(t, MethodInputArgumentMatches(nil, &ua.Argument{
		DataType:  ua.NewNumericNodeID(0, id.String),
		ValueRank: 1,
	}, ua.MustVariant([]string{"a", "b"})))
}

func TestMethodInputArgumentMatchesAcceptsInt32ArrayForDeclaredEnumType(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.enumType,
		ValueRank: 1,
	}, ua.MustVariant([]int32{1, 2})))
}

func TestMethodInputArgumentMatchesExtensionObjectArrayStillMatches(t *testing.T) {
	t.Parallel()

	resolver, ids := newMethodMetadataResolver(t)
	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  ids.declaredType,
		ValueRank: 1,
	}, ua.MustVariant([]*ua.ExtensionObject{
		{
			TypeID:       &ua.ExpandedNodeID{NodeID: ids.binaryEncodingType},
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        &ua.Argument{},
		},
	})))
}

type methodMetadataIDs struct {
	declaredType            *ua.NodeID
	enumType                *ua.NodeID
	integerIDType           *ua.NodeID
	binaryEncodingType      *ua.NodeID
	xmlEncodingType         *ua.NodeID
	otherBinaryEncodingType *ua.NodeID
}

func newMethodMetadataResolver(t *testing.T) (*methodMetadataTestResolver, methodMetadataIDs) {
	t.Helper()

	objectType := NewObjectTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7100)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "ObjectType"}),
		),
	)
	enumerationType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.Enumeration)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "Enumeration"}),
		),
	)
	uint32Type := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.UInt32)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "UInt32"}),
		),
	)
	integerIDType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(0, id.IntegerID)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "IntegerId"}),
		),
	)
	integerIDType.AddRef(refs.NewReferenceDescription(uint32Type, ua.NewNumericNodeID(0, id.HasSubtype), false))
	declaredType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "StructuredType"}),
		),
	)
	enumType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7006)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "CustomEnum"}),
		),
	)
	enumType.AddRef(refs.NewReferenceDescription(enumerationType, ua.NewNumericNodeID(0, id.HasSubtype), false))

	binaryEncodingNode := NewObjectNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "StructuredType_Encoding_DefaultBinary"}),
		),
		WithType(objectType),
	)
	binaryEncodingNode.AddRef(refs.NewReferenceDescription(declaredType, ua.NewNumericNodeID(0, id.HasEncoding), false))
	declaredType.AddRef(refs.NewReferenceDescription(binaryEncodingNode, ua.NewNumericNodeID(0, id.HasEncoding), true))

	xmlEncodingNode := NewObjectNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7003)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "StructuredType_Encoding_DefaultXML"}),
		),
		WithType(objectType),
	)
	xmlEncodingNode.AddRef(refs.NewReferenceDescription(declaredType, ua.NewNumericNodeID(0, id.HasEncoding), false))
	declaredType.AddRef(refs.NewReferenceDescription(xmlEncodingNode, ua.NewNumericNodeID(0, id.HasEncoding), true))

	otherType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7004)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "OtherStructuredType"}),
		),
	)
	otherBinaryEncodingNode := NewObjectNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7005)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "OtherStructuredType_Encoding_DefaultBinary"}),
		),
		WithType(objectType),
	)
	otherBinaryEncodingNode.AddRef(refs.NewReferenceDescription(otherType, ua.NewNumericNodeID(0, id.HasEncoding), false))
	otherType.AddRef(refs.NewReferenceDescription(otherBinaryEncodingNode, ua.NewNumericNodeID(0, id.HasEncoding), true))

	ns0 := &methodMetadataTestNamespace{
		id:   0,
		name: "http://opcfoundation.org/UA/",
		nodes: map[string]types.Node{
			enumerationType.ID().String(): enumerationType,
			uint32Type.ID().String():      uint32Type,
			integerIDType.ID().String():   integerIDType,
		},
	}
	ns := &methodMetadataTestNamespace{
		id:   2,
		name: "urn:test:method-metadata",
		nodes: map[string]types.Node{
			declaredType.ID().String():            declaredType,
			enumType.ID().String():                enumType,
			binaryEncodingNode.ID().String():      binaryEncodingNode,
			xmlEncodingNode.ID().String():         xmlEncodingNode,
			otherType.ID().String():               otherType,
			otherBinaryEncodingNode.ID().String(): otherBinaryEncodingNode,
			objectType.ID().String():              objectType,
		},
	}

	resolver := &methodMetadataTestResolver{
		namespaces: map[int]types.NameSpace{
			0: ns0,
			2: ns,
		},
	}

	return resolver, methodMetadataIDs{
		declaredType:            declaredType.ID(),
		enumType:                enumType.ID(),
		integerIDType:           integerIDType.ID(),
		binaryEncodingType:      binaryEncodingNode.ID(),
		xmlEncodingType:         xmlEncodingNode.ID(),
		otherBinaryEncodingType: otherBinaryEncodingNode.ID(),
	}
}

type methodMetadataTestResolver struct {
	namespaces map[int]types.NameSpace
}

func (r *methodMetadataTestResolver) Namespace(id int) (types.NameSpace, error) {
	ns, ok := r.namespaces[id]
	if !ok {
		return nil, fmt.Errorf("namespace %d not found", id)
	}
	return ns, nil
}

func (r *methodMetadataTestResolver) Namespaces() []types.NameSpace {
	namespaces := make([]types.NameSpace, 0, len(r.namespaces))
	for _, ns := range r.namespaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

type methodMetadataTestNamespace struct {
	id    uint16
	name  string
	nodes map[string]types.Node
}

func (ns *methodMetadataTestNamespace) Name() string                 { return ns.name }
func (*methodMetadataTestNamespace) AddNode(n types.Node) types.Node { return n }
func (ns *methodMetadataTestNamespace) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	return ns.nodes[id.String()]
}
func (*methodMetadataTestNamespace) Browse(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
	return nil
}
func (ns *methodMetadataTestNamespace) ID() uint16 { return ns.id }
func (*methodMetadataTestNamespace) SetID(uint16)  {}
func (*methodMetadataTestNamespace) Attribute(context.Context, *ua.NodeID, ua.AttributeID) *ua.DataValue {
	return nil
}
func (*methodMetadataTestNamespace) SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode {
	return ua.StatusOK
}
func (ns *methodMetadataTestNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: ns.id, Name: name}
}
func (*methodMetadataTestNamespace) NextAvailableID() *ua.NodeID {
	panic("NextAvailableID should not be called in method metadata tests")
}
