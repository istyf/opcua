package node

import (
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type variableTypeConfig struct {
	typeConfig

	dataTypeNodeId  *ua.NodeID
	rank            int32
	arrayDimensions []uint32
	value           any
}

type variableTypeNode struct {
	typeNode
}

type variableTypeOption func(*variableTypeConfig)

func WithAbstractVariableType(abstract bool) variableTypeOption {
	return func(cfg *variableTypeConfig) {
		cfg.abstract = abstract
	}
}

func WithArrayDimensions(dimensions []uint32) variableTypeOption {
	return func(cfg *variableTypeConfig) {
		cfg.arrayDimensions = dimensions
	}
}

func WithDefaultValue(dataTypeNodeId *ua.NodeID, rank int32, value any) variableTypeOption {
	return func(cfg *variableTypeConfig) {
		cfg.dataTypeNodeId = dataTypeNodeId
		cfg.rank = rank
		cfg.value = value
	}
}

func NewVariableTypeNode(base func(ua.NodeClass) *baseConfig, opts ...variableTypeOption) types.VariableTypeNode {

	cfg := &variableTypeConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	if cfg.dataTypeNodeId == nil {
		panic("missing mandatory datatype node id")
	}

	n := &variableTypeNode{
		typeNode: typeNode{
			baseNode: *newBaseNodeFromCfg(base(ua.NodeClassVariableType)),
			abstract: cfg.abstract,
		},
	}

	n.baseNode.attr[ua.AttributeIDIsAbstract] = values.DataValueFromValue(cfg.abstract)

	n.baseNode.attr[ua.AttributeIDDataType] = values.DataValueFromValue(cfg.dataTypeNodeId)
	n.baseNode.attr[ua.AttributeIDValue] = values.DataValueFromValue(cfg.value)

	if cfg.rank != 0 {
		n.baseNode.attr[ua.AttributeIDValueRank] = values.DataValueFromValue(cfg.rank)
	}

	if cfg.rank > 0 {
		n.baseNode.attr[ua.AttributeIDArrayDimensions] = values.DataValueFromValue(cfg.arrayDimensions)
	}

	return n
}

func (n *variableTypeNode) IsAbstract() bool {
	return n.abstract
}
