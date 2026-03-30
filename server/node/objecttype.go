package node

import (
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type typeNode struct {
	baseNode

	abstract bool
}

type typeConfig struct {
	abstract bool
}

type objTypeNode struct {
	typeNode
}

func NewObjectTypeNode(base func(ua.NodeClass) *baseConfig, opts ...typeOption) types.ObjectTypeNode {

	cfg := &typeConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	n := &objTypeNode{
		typeNode: typeNode{
			baseNode: *newBaseNodeFromCfg(base(ua.NodeClassObjectType)),
			abstract: cfg.abstract,
		},
	}

	n.baseNode.attr[ua.AttributeIDIsAbstract] = values.DataValueFromValue(cfg.abstract)

	return n
}

func (n *objTypeNode) IsAbstract() bool {
	return n.abstract
}
