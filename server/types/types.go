package types

import (
	"context"
	"crypto/rsa"
	"iter"
	"time"

	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/ua"
)

type AttrValue struct {
	Value           *ua.DataValue
	SourceTimestamp time.Time
}

type ReferenceWrapper interface {
	NodeClass() ua.NodeClass

	IsForward() bool

	IsReferenceType(refType uint32) bool
	ReferenceType() *ua.NodeID

	TargetNodeID() *ua.ExpandedNodeID
	TargetsNode(Node) bool

	Copy(context.Context) *ua.ReferenceDescription
}

type ReferenceCollection interface {
	All() iter.Seq[ReferenceWrapper]
	Contains(match func(ReferenceWrapper) bool) bool
	Count() int
	Find(matching func(ReferenceWrapper) bool) iter.Seq[ReferenceWrapper]
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
	DisplayName(context.Context) *ua.LocalizedText
	NodeClass() ua.NodeClass

	AddComponent(Node) Node
	AddComponents(...Node) Node

	AddRef(ReferenceWrapper)
	References() ReferenceCollection

	Attribute(context.Context, ua.AttributeID) (*AttrValue, error)
	SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error
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
	UserExecutable(context.Context) bool
	SetUserExecutable(bool)
	SetUserExecutableHandler(MethodUserExecutableHandler)
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

	Access(context.Context, ua.AccessLevelType) bool
	UserAccessLevel(context.Context) ua.AccessLevelType
	SetUserAccessLevelHandler(UserAccessLevelHandler)
	Value() *ua.DataValue
	SetValue(*ua.DataValue)
	SetValueFunc(func() *ua.DataValue)

	Attribute(context.Context, ua.AttributeID) (*AttrValue, error)
}

type VariableTypeNode interface {
	TypeNode
}

type SubscriptionID uint32

type Server interface {
	ImportNodeSet(context.Context, *schema.UANodeSet) error

	AddNamespace(ns NameSpace) int
	Namespace(int) (NameSpace, error)
	Namespaces() []NameSpace

	Node(*ua.NodeID) Node

	ChangeNotification(context.Context, *ua.NodeID)
	DeleteSubscription(id SubscriptionID)

	Config() ServerConfig
	Endpoints() []*ua.EndpointDescription
	Session(ctx context.Context, hdr *ua.RequestHeader) Session
	Status() *ua.ServerStatusDataType

	Close(context.Context) error
	Start(context.Context) error
}

type MethodFunc func(context.Context, ...*ua.Variant) ([]*ua.Variant, ua.StatusCode)
type MethodMiddleware func(MethodFunc) MethodFunc
type MethodUserExecutableHandler func(context.Context) bool
type UserAccessLevelHandler func(context.Context, ua.AccessLevelType) ua.AccessLevelType

type ServerConfig interface {
	Certificate() []byte
	Endpoints() []string
	PrivateKey() *rsa.PrivateKey

	// UserNameAuthenticator returns the callback used to authenticate decoded
	// username/password credentials during ActivateSession. A nil callback means
	// username/password activation is not available even if the mode is
	// advertised.
	UserNameAuthenticator() auth.UserNameAuthenticator

	// AuthorizationContextDecorator returns the optional hook used to enrich
	// method handler contexts from the authenticated user stored on the active
	// session.
	AuthorizationContextDecorator() auth.AuthorizationContextDecorator

	ApplicationURI() string
	ManufacturerName() string
	ProductName() string
	SoftwareVersion() string

	MaxNodesPerRead() uint32
	MaxMethodOperationsPerCall() uint32
	MaxBrowseOperationsPerCall() uint32
	MaxBrowseContinuationPoints() uint32
	MaxSubscriptions() uint32
	MaxSubscriptionsPerSession() uint32
	MaxSubscriptionOperationsPerCall() uint32
	MinSubscriptionPublishingInterval() time.Duration
	MinSubscriptionMaxKeepAliveCount() uint32
	MinSubscriptionLifetimeCount() uint32

	MethodCallMiddleware() MethodMiddleware
}

type PubReq struct {
	// The data of the publish request
	Req *ua.PublishRequest

	// The request ID (from the header) of the publish request.  This has to be used when replying.
	ID uint32
}

type Session interface {
	AuthTokenID() *ua.NodeID
	ID() *ua.NodeID

	Locales() []string
	SetLocales([]string)

	RemoteCertificate() []byte

	ServerNonce() []byte
	SetServerNonce([]byte)

	TimeOutInMillis() float64

	// Activated reports whether ActivateSession has completed successfully for
	// the session.
	Activated() bool
	SetActivated(bool)

	IsSameAs(Session) bool

	// AuthenticatedUser returns the user context stored by a successful
	// username/password activation. Anonymous or not-yet-activated sessions
	// return nil.
	AuthenticatedUser() *auth.AuthenticatedUser

	PublishRequestChannel() chan PubReq
}
