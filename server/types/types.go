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

// These are all the functions a namespace needs in order to provide nodes into the server
type NameSpace interface {
	// Name of the namespace.  Per the standard it should be an URI.
	Name() string

	// This function should create a new node
	AddNode(n Node) Node

	// This function should lookup and return the node indicated by the Node ID
	Node(id *ua.NodeID) Node

	// This is the function to list all available nodes to the client that is browsing.
	// The BrowseDescription has the root node of the browse and what kind of nodes the
	// client is looking for.  The Browse Result should have the list of matching nodes.
	Browse(ctx context.Context, req *ua.BrowseDescription) *ua.BrowseResult

	// ID and SetID are the namespace ID number of this namespace.  When you add it to the server
	// with srv.AddNamespace(xxx) it will set these for you.
	ID() uint16
	SetID(uint16)

	// These are the functions for reading and writing arbitrary attributes.  The most common
	// is the value attribute, but many clients also read the datatype and description attributes.
	// as well as attributes related to array bounds
	Attribute(context.Context, *ua.NodeID, ua.AttributeID) *ua.DataValue
	SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode

	NewQualifiedName(name string) *ua.QualifiedName
	NextAvailableID() *ua.NodeID
}

type Node interface {
	ID() *ua.NodeID
	BrowseName() *ua.QualifiedName
	DisplayName() *ua.LocalizedText
	NodeClass() ua.NodeClass

	AddComponent(Node) Node
	AddComponents(...Node) Node

	AddRef(*ua.ReferenceDescription)
	References() ReferenceCollection

	Attribute(ua.AttributeID) (*AttrValue, error)
	SetAttribute(ua.AttributeID, *ua.DataValue) error
}

type TypeNode interface {
	Node

	DataType() *ua.ExpandedNodeID
	IsAbstract() bool
}

type DataTypeNode interface {
	TypeNode
}

type MethodNode interface {
	Node

	CallMethod(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode)

	IsExecutable(context.Context) bool
	SetExecutable(bool)
}

type ObjectNode interface {
	Node
}

type ObjectTypeNode interface {
	TypeNode
}

type ReferenceTypeNode interface {
	TypeNode

	IsSymetrical() bool
}

type VariableNode interface {
	Node

	Access(ua.AccessLevelType) bool
	Value() *ua.DataValue
	SetValue(*ua.DataValue)
	SetValueFunc(func() *ua.DataValue)

	Attribute(ua.AttributeID) (*AttrValue, error)
	SetAttribute(ua.AttributeID, *ua.DataValue) error
}

type VariableTypeNode interface {
	TypeNode
}
