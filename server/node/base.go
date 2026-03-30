package node

import (
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type Attributes map[ua.AttributeID]*ua.DataValue

type References []*ua.ReferenceDescription

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

		if cfg.descriptions == nil {
			cfg.descriptions = []*ua.LocalizedText{ua.NewLocalizedText("")}
		}

		if cfg.displayNames == nil {
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

	ns types.NameSpace
}

func newBaseNode(cfg *baseConfig) *baseNode {
	n := &baseNode{
		id: cfg.nodeID,
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

func (n *baseNode) Attribute(id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDValue {
		return nil, errors.New("value attribute only supported on variable nodes")
	}

	if id == ua.AttributeIDDisplayName && len(n.displayNames) > 0 {
		// TODO: Get the proper locale from the session's context
		return NewAttrValue(values.DataValueFromValue(n.displayNames[0])), nil
	}

	if id == ua.AttributeIDDescription && len(n.descriptions) > 0 {
		// TODO: Get the proper locale from the session's context
		return NewAttrValue(values.DataValueFromValue(n.descriptions[0])), nil
	}

	if n.attr != nil {
		if v := n.attr[id]; v != nil {
			return NewAttrValue(v), nil
		}
	}

	return nil, ua.StatusBadAttributeIDInvalid
}

func (n *baseNode) SetAttribute(id ua.AttributeID, val *ua.DataValue) error {

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

func (n *baseNode) SetBrowseName(s string) {
	n.attr[ua.AttributeIDBrowseName] = values.DataValueFromValue(&ua.QualifiedName{Name: s})
}

func (n *baseNode) DisplayName() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDisplayName]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	val := v.Value.Value().(*ua.LocalizedText)
	val.UpdateMask()
	return val
}

func (n *baseNode) SetDisplayName(text, locale string) {
	lt := &ua.LocalizedText{Text: text, Locale: locale}
	lt.UpdateMask()
	n.attr[ua.AttributeIDDisplayName] = values.DataValueFromValue(lt)
}

func (n *baseNode) Description() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDescription]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	return v.Value.Value().(*ua.LocalizedText)
}

func (n *baseNode) SetDescription(text, locale string) {
	n.attr[ua.AttributeIDDescription] = values.DataValueFromValue(&ua.LocalizedText{Text: text, Locale: locale})
}

func (n *baseNode) DataType() *ua.ExpandedNodeID {
	v, ok := n.attr[ua.AttributeIDDataType]
	if !ok || v == nil || v.Value.Value() == nil {
		// if we have a type definition, return that?
		for i := range n.refs {
			r := n.refs[i]
			if r.ReferenceTypeID == nil {
				fmt.Println("reftypeid was nil!")
			}
			if r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasTypeDefinition && r.IsForward {
				return r.NodeID
			}
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

func (n *baseNode) SetNodeClass(nc ua.NodeClass) {
	n.attr[ua.AttributeIDNodeClass] = values.DataValueFromValue(uint32(nc))
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

func (n *baseNode) AddRef(refdesc *ua.ReferenceDescription) {
	n.refs = append(n.refs, refdesc)
}

// Access returns true if the node has the access level requested.
// It checks both the UserAccessLevel and AccessLevel attributes.
// If neither are present, it assumes global access and returns true.
//
// I'm not sure what the best way to implement "user" specific access levels
// is presently.  Will need functioning user authentication first, and then a way to
// pass it into the nodes user access attribute so it can be checked properly.
func (n baseNode) Access(flag ua.AccessLevelType) bool {

	access, err := n.Attribute(ua.AttributeIDUserAccessLevel)
	if err == nil { // if we have a user access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}
		if val&uint8(flag) == 0 {
			return false
		}
	}

	access, err = n.Attribute(ua.AttributeIDAccessLevel)
	if err == nil { // if we have an access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}

		if val&uint8(flag) == 0 {
			return false
		}
	}

	return true
}

type refcollection struct {
	n *baseNode
}

func (n *baseNode) References() types.ReferenceCollection {
	return &refcollection{n}
}

// All implements [types.ReferenceCollection].
func (r *refcollection) All() iter.Seq[*ua.ReferenceDescription] {
	return func(yield func(*ua.ReferenceDescription) bool) {
		for _, k := range r.n.refs {
			if !yield(k) {
				return
			}
		}
	}
}

// Contains implements [types.ReferenceCollection].
func (r *refcollection) Contains(isMatching func(*ua.ReferenceDescription) bool) bool {
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
func (r *refcollection) Find(isMatching func(*ua.ReferenceDescription) bool) iter.Seq[*ua.ReferenceDescription] {
	return func(yield func(*ua.ReferenceDescription) bool) {
		for _, k := range r.n.refs {
			if isMatching(k) && !yield(k) {
				return
			}
		}
	}
}
