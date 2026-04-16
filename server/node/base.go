package node

import (
	"context"
	"errors"
	"iter"
	"slices"
	"time"

	"github.com/gopcua/opcua/id"
	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type Attributes map[ua.AttributeID]*ua.DataValue

type References []types.ReferenceWrapper

func NewAttrValue(v *ua.DataValue) *types.AttrValue {
	return &types.AttrValue{Value: v, SourceTimestamp: time.Now()}
}

type baseConfig struct {
	nodeClass    ua.NodeClass
	nodeID       *ua.NodeID
	browseName   *ua.QualifiedName
	displayNames []*ua.LocalizedText
	descriptions []*ua.LocalizedText
}

func newDefaultBaseConfig(class ua.NodeClass) *baseConfig {
	return &baseConfig{
		nodeClass: class,
	}
}

type baseOption func(*baseConfig)

func WithBrowseName(name *ua.QualifiedName) baseOption {
	return func(cfg *baseConfig) {
		cfg.browseName = name
	}
}

func WithDescriptions(descriptions []*ua.LocalizedText) baseOption {
	return func(cfg *baseConfig) {
		cfg.descriptions = descriptions
	}
}

func WithDisplayNames(names []*ua.LocalizedText) baseOption {
	return func(cfg *baseConfig) {
		cfg.displayNames = names
	}
}

func WithID(id *ua.NodeID) baseOption {
	return func(cfg *baseConfig) {
		cfg.nodeID = id
	}
}

func WithBase(opts ...baseOption) func(ua.NodeClass) *baseConfig {
	return func(class ua.NodeClass) *baseConfig {
		cfg := newDefaultBaseConfig(class)

		for _, applyOption := range opts {
			applyOption(cfg)
		}

		if len(cfg.descriptions) == 0 {
			cfg.descriptions = []*ua.LocalizedText{ua.NewLocalizedText("")}
		}

		if len(cfg.displayNames) == 0 {
			cfg.displayNames = []*ua.LocalizedText{ua.NewLocalizedText(cfg.browseName.Name)}
		}

		return cfg
	}
}

type baseNode struct {
	id   *ua.NodeID
	attr Attributes
	refs References

	displayNames []*ua.LocalizedText
	descriptions []*ua.LocalizedText
}

func newBaseNode(cfg *baseConfig) *baseNode {
	if cfg.nodeID == nil {
		panic("creating nodes with no id is not allowed")
	}

	if cfg.browseName == nil {
		panic("creating nodes with no browse name is not allowed")
	}

	n := &baseNode{
		id:           cfg.nodeID,
		descriptions: cfg.descriptions,
		displayNames: cfg.displayNames,
		attr: map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(cfg.browseName),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(cfg.nodeClass)),
		},
	}

	return n
}

func (n *baseNode) ID() *ua.NodeID {
	return n.id
}

func (n *variableNode) Value() *ua.DataValue {
	return n.valueFunc()
}

func (n *baseNode) Attribute(ctx context.Context, id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDValue {
		return nil, errors.New("value attribute only supported on variable nodes")
	}

	if id == ua.AttributeIDDisplayName && len(n.displayNames) > 0 {
		displayName := ua.LocalizedTextFromLocale(
			n.displayNames,
			srvctx.PreferedLocalesFromContext(ctx),
		)
		return NewAttrValue(values.DataValueFromValue(displayName)), nil
	}

	if id == ua.AttributeIDDescription && len(n.descriptions) > 0 {
		description := ua.LocalizedTextFromLocale(
			n.descriptions,
			srvctx.PreferedLocalesFromContext(ctx),
		)
		return NewAttrValue(values.DataValueFromValue(description)), nil
	}

	if n.attr != nil {
		if v := n.attr[id]; v != nil {
			return NewAttrValue(v), nil
		}
	}

	return nil, ua.StatusBadAttributeIDInvalid
}

func (n *baseNode) SetAttribute(_ context.Context, id ua.AttributeID, val *ua.DataValue) error {

	if id == ua.AttributeIDValue {
		return errors.New("set value attribute only supported on variable nodes")
	}

	n.attr[id] = val

	return nil
}

func (n *baseNode) BrowseName() *ua.QualifiedName {
	v := n.attr[ua.AttributeIDBrowseName]
	if v == nil || v.Value.Value() == nil {
		return &ua.QualifiedName{}
	}
	return v.Value.Value().(*ua.QualifiedName)
}

func (n *baseNode) DisplayName(ctx context.Context) *ua.LocalizedText {
	return ua.LocalizedTextFromLocale(
		n.displayNames,
		srvctx.PreferedLocalesFromContext(ctx),
	)
}

func (n *baseNode) SetDisplayName(text, locale string) {
	lt := ua.NewLocalizedTextWithLocale(text, locale)

	for idx := range n.displayNames {
		if n.displayNames[idx].Locale == locale {
			n.displayNames[idx] = lt
			return
		}
	}

	n.displayNames = append(n.displayNames, lt)
}

func (n *baseNode) SetDescription(text, locale string) {
	localized := ua.NewLocalizedTextWithLocale(text, locale)

	for idx := range n.descriptions {
		if n.descriptions[idx].Locale == locale {
			n.descriptions[idx] = localized
			return
		}
	}

	n.descriptions = append(n.descriptions, localized)
}

func (n *baseNode) DataType() *ua.ExpandedNodeID {
	v, ok := n.attr[ua.AttributeIDDataType]
	if !ok || v == nil || v.Value.Value() == nil {
		// if we have a type definition, return that?
		for r := range n.References().Find(func(rd types.ReferenceWrapper) bool {
			return rd.IsReferenceType(id.HasTypeDefinition) && rd.IsForward()
		}) {
			return r.TargetNodeID()
		}

		return ua.NewTwoByteExpandedNodeID(0)
	}

	switch val := v.Value.Value().(type) {
	case *ua.ExpandedNodeID:
		return val
	case *ua.NodeID:
		return &ua.ExpandedNodeID{NodeID: val}
	}

	return ua.NewTwoByteExpandedNodeID(0)
}

func (n *baseNode) NodeClass() ua.NodeClass {
	v := n.attr[ua.AttributeIDNodeClass]
	if v == nil || v.Value.Value() == nil {
		return ua.NodeClassObject
	}
	vi32, ok := v.Value.Value().(int32)
	if !ok {
		vui32, ok := v.Value.Value().(uint32)
		if !ok {
			return ua.NodeClassObject
		}
		return ua.NodeClass(int32(vui32))
	}
	return ua.NodeClass(vi32)
}

type RefType int

const (
	RefTypeIDHasComponent = id.HasComponent
	RefTypeIDOrganizes    = id.Organizes
)

func (n *baseNode) AddComponent(sub types.Node) types.Node {
	refs.LinkWithHasComponentReferenceDescriptions(n, sub)
	return n
}

func (n *baseNode) AddComponents(subs ...types.Node) types.Node {
	for _, sub := range subs {
		n.AddComponent(sub)
	}

	return n
}

func (n *baseNode) AddRef(refdesc types.ReferenceWrapper) {
	// only one type def reference allowed, so replace the old one if we already have one
	if refdesc.IsReferenceType(id.HasTypeDefinition) {
		hasTypeDefRefAtIndex := slices.IndexFunc(n.refs, func(rd types.ReferenceWrapper) bool {
			return rd.IsReferenceType(id.HasTypeDefinition)
		})

		if hasTypeDefRefAtIndex >= 0 {
			n.refs[hasTypeDefRefAtIndex] = refdesc
			return
		}
	}

	n.refs = append(n.refs, refdesc)
}

type refcollection struct {
	n *baseNode
}

func (n *baseNode) References() types.ReferenceCollection {
	return &refcollection{n}
}

// All implements [types.ReferenceCollection].
func (r *refcollection) All() iter.Seq[types.ReferenceWrapper] {
	return func(yield func(types.ReferenceWrapper) bool) {
		for _, k := range r.n.refs {
			if !yield(k) {
				return
			}
		}
	}
}

// Contains implements [types.ReferenceCollection].
func (r *refcollection) Contains(isMatching func(types.ReferenceWrapper) bool) bool {
	for r := range r.All() {
		if isMatching(r) {
			return true
		}
	}
	return false
}

func (r *refcollection) Count() int {
	return len(r.n.refs)
}

// Find implements [types.ReferenceCollection].
func (r *refcollection) Find(isMatching func(types.ReferenceWrapper) bool) iter.Seq[types.ReferenceWrapper] {
	return func(yield func(types.ReferenceWrapper) bool) {
		for _, k := range r.n.refs {
			if isMatching(k) && !yield(k) {
				return
			}
		}
	}
}
