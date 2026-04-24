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

	resolver, declaredType, encodingType := newMethodMetadataResolver(t)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       &ua.ExpandedNodeID{NodeID: encodingType},
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        &ua.Argument{},
	})

	assert.True(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  declaredType,
		ValueRank: -1,
	}, value))
}

func TestMethodInputArgumentMatchesRejectsExtensionObjectEncodingForOtherDataType(t *testing.T) {
	t.Parallel()

	resolver, _, encodingType := newMethodMetadataResolver(t)
	otherType := ua.NewNumericNodeID(2, 7003)
	value := ua.MustVariant(&ua.ExtensionObject{
		TypeID:       &ua.ExpandedNodeID{NodeID: encodingType},
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        &ua.Argument{},
	})

	assert.False(t, MethodInputArgumentMatches(resolver, &ua.Argument{
		DataType:  otherType,
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

func TestMethodInputArgumentMatchesArrayStillMatches(t *testing.T) {
	t.Parallel()

	assert.True(t, MethodInputArgumentMatches(nil, &ua.Argument{
		DataType:  ua.NewNumericNodeID(0, id.String),
		ValueRank: 1,
	}, ua.MustVariant([]string{"a", "b"})))
}

func newMethodMetadataResolver(t *testing.T) (*methodMetadataTestResolver, *ua.NodeID, *ua.NodeID) {
	t.Helper()

	objectType := NewObjectTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7100)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "ObjectType"}),
		),
	)
	declaredType := NewDataTypeNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7001)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "StructuredType"}),
		),
	)
	encodingNode := NewObjectNode(
		WithBase(
			WithID(ua.NewNumericNodeID(2, 7002)),
			WithBrowseName(&ua.QualifiedName{NamespaceIndex: 2, Name: "StructuredType_Encoding_DefaultBinary"}),
		),
		WithType(objectType),
	)
	encodingNode.AddRef(refs.NewReferenceDescription(declaredType, ua.NewNumericNodeID(0, id.HasEncoding), false))

	ns := &methodMetadataTestNamespace{
		nodes: map[string]types.Node{
			declaredType.ID().String(): declaredType,
			encodingNode.ID().String(): encodingNode,
			objectType.ID().String():   objectType,
		},
	}

	resolver := &methodMetadataTestResolver{
		namespaces: map[int]types.NameSpace{2: ns},
	}

	return resolver, declaredType.ID(), encodingNode.ID()
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

type methodMetadataTestNamespace struct {
	nodes map[string]types.Node
}

func (*methodMetadataTestNamespace) Name() string                    { return "urn:test:method-metadata" }
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
func (*methodMetadataTestNamespace) ID() uint16   { return 2 }
func (*methodMetadataTestNamespace) SetID(uint16) {}
func (*methodMetadataTestNamespace) Attribute(context.Context, *ua.NodeID, ua.AttributeID) *ua.DataValue {
	return nil
}
func (*methodMetadataTestNamespace) SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode {
	return ua.StatusOK
}
func (*methodMetadataTestNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: 2, Name: name}
}
func (*methodMetadataTestNamespace) NextAvailableID() *ua.NodeID {
	panic("NextAvailableID should not be called in method metadata tests")
}
