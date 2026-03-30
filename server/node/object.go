package node

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type objectNode struct {
	baseNode
}

type objectConfig struct {
	eventNotifier    ua.EventNotifierType
	objectTypeNodeId *ua.NodeID
}

type objectOption func(*objectConfig)

func WithEventNotifier(notifier ua.EventNotifierType) objectOption {
	return func(cfg *objectConfig) {
		cfg.eventNotifier = notifier
	}
}

func WithEventNotifierTypes(types ...ua.EventNotifierType) objectOption {
	var value ua.EventNotifierType

	for _, t := range types {
		if t == ua.EventNotifierTypeNone && len(types) > 0 {
			panic("ua.EventNotifierTypeNone can not be combined with other types")
		}
		value |= t
	}

	return func(cfg *objectConfig) {
		cfg.eventNotifier = value
	}
}

func WithType(typeNode types.ObjectTypeNode) objectOption {

	if typeNode == nil {
		panic("creating objects with nil object type is not allowed")
	}

	return func(cfg *objectConfig) {
		cfg.objectTypeNodeId = typeNode.ID()
	}
}

func NewObjectNode(base func(ua.NodeClass) *baseConfig, opts ...objectOption) types.ObjectNode {

	cfg := &objectConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	if cfg.objectTypeNodeId == nil {
		cfg.objectTypeNodeId = ua.NewNumericNodeID(0, id.BaseObjectType)
	}

	n := &objectNode{
		baseNode: *newBaseNode(base(ua.NodeClassObject)),
	}

	n.baseNode.attr[ua.AttributeIDEventNotifier] = values.DataValueFromValue(cfg.eventNotifier)

	n.AddRef(refs.NewHasTypeDefinitionRefDesc(&ua.ExpandedNodeID{NodeID: cfg.objectTypeNodeId}))

	return n
}
