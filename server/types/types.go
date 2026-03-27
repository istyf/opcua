package types

import (
	"context"
	"iter"
	"time"

	"github.com/gopcua/opcua/ua"
)

type AttrValue struct {
	Value           *ua.DataValue
	SourceTimestamp time.Time
}

type ReferenceCollection interface {
	All() iter.Seq[*ua.ReferenceDescription]
	Contains(match func(*ua.ReferenceDescription) bool) bool
	Count() int
	Find(matching func(*ua.ReferenceDescription) bool) iter.Seq[*ua.ReferenceDescription]
}

type Node interface {
	ID() *ua.NodeID
	BrowseName() *ua.QualifiedName
	DisplayName() *ua.LocalizedText
	NodeClass() ua.NodeClass
	DataType() *ua.ExpandedNodeID

	Access(ua.AccessLevelType) bool

	CallMethod(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode)

	Value() *ua.DataValue

	AddRef(*ua.ReferenceDescription)
	References() ReferenceCollection

	Attribute(ua.AttributeID) (*AttrValue, error)
	SetAttribute(ua.AttributeID, *ua.DataValue) error
}
