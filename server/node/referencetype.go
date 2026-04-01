package node

import (
	"context"

	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type refTypeNode struct {
	baseNode

	abstract     bool
	symetric     bool
	inverseNames []*ua.LocalizedText
}

type refTypeConfig struct {
	abstract     bool
	symetric     bool
	inverseNames []*ua.LocalizedText
}

type refTypeOption func(*refTypeConfig)

func WithAbstract(abstract bool) refTypeOption {
	return func(cfg *refTypeConfig) {
		cfg.abstract = abstract
	}
}

func WithInverseNames(names []*ua.LocalizedText) refTypeOption {
	return func(cfg *refTypeConfig) {
		if len(names) > 0 {
			cfg.symetric = false
			cfg.inverseNames = names
		}
	}
}

func NewReferenceTypeNode(base func(ua.NodeClass) *baseConfig, opts ...refTypeOption) types.ReferenceTypeNode {

	cfg := &refTypeConfig{
		symetric: true,
	}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	n := &refTypeNode{
		baseNode: *newBaseNode(base(ua.NodeClassReferenceType)),
		abstract: cfg.abstract,
		symetric: cfg.symetric,
	}

	// only non symetric reference types have inverse names
	if !cfg.symetric {
		n.inverseNames = cfg.inverseNames
	}

	n.baseNode.attr[ua.AttributeIDIsAbstract] = values.DataValueFromValue(cfg.abstract)
	n.baseNode.attr[ua.AttributeIDSymmetric] = values.DataValueFromValue(cfg.symetric)

	return n
}

func (n *refTypeNode) IsAbstract() bool {
	return n.abstract
}

func (n *refTypeNode) IsSymetrical() bool {
	return n.symetric
}

func (n *refTypeNode) Attribute(ctx context.Context, id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDInverseName {
		if n.symetric || len(n.inverseNames) == 0 {
			return nil, ua.StatusBadAttributeIDInvalid
		}

		inverseName := ua.LocalizedTextFromLocale(
			n.inverseNames,
			srvctx.PreferedLocalesFromContext(ctx),
		)
		return NewAttrValue(values.DataValueFromValue(inverseName)), nil
	}

	return n.baseNode.Attribute(ctx, id)
}

func (n *refTypeNode) SetAttribute(ctx context.Context, id ua.AttributeID, val *ua.DataValue) error {
	return n.baseNode.SetAttribute(ctx, id, val)
}
