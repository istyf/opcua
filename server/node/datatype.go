package node

import (
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type dataTypeNode struct {
	typeNode
}

type typeOption func(*typeConfig)

func WithAbstractType(abstract bool) typeOption {
	return func(cfg *typeConfig) {
		cfg.abstract = abstract
	}
}

func NewDataTypeNode(base func(ua.NodeClass) *baseConfig, opts ...typeOption) types.DataTypeNode {

	cfg := &typeConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	n := &dataTypeNode{
		typeNode: typeNode{
			baseNode: *newBaseNode(base(ua.NodeClassDataType)),
			abstract: cfg.abstract,
		},
	}

	n.baseNode.attr[ua.AttributeIDIsAbstract] = values.DataValueFromValue(cfg.abstract)

	return n
}

func (n *dataTypeNode) IsAbstract() bool {
	return n.abstract
}
