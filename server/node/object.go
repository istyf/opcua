package node

import (
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type objectNode struct {
	baseNode
}

type objectConfig struct {
	eventNotifier ua.EventNotifierType
	objectType    types.ObjectTypeNode
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
		cfg.objectType = typeNode
	}
}

func NewObjectNode(base func(ua.NodeClass) *baseConfig, opts ...objectOption) types.ObjectNode {

	cfg := &objectConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	if cfg.objectType == nil {
		panic("creating object nodes without an object type is not allowed")
	}

	n := &objectNode{
		baseNode: *newBaseNode(base(ua.NodeClassObject)),
	}

	n.baseNode.attr[ua.AttributeIDEventNotifier] = values.DataValueFromValue(cfg.eventNotifier)

	n.AddRef(refs.NewHasComponentRefDesc(cfg.objectType))

	return n
}
