package services

import (
	"context"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

type Handler func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error)

type EndpointsProvider interface {
	Endpoints() []*ua.EndpointDescription
}

type NamespaceProvider interface {
	Namespace(int) (types.NameSpace, error)
}

type NodeProvider interface {
	Node(*ua.NodeID) types.Node
}

type SessionProvider interface {
	Session(ctx context.Context, hdr *ua.RequestHeader) types.Session
}

type SubscriptionDeleter interface {
	DeleteSubscription(types.SubscriptionID)
}

type SubscriptionProvider interface {
	Subscription(types.SubscriptionID) (*Subscription, bool)
}

func NewResponseHeader(reqID uint32, statusCode ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		RequestHandle:      reqID,
		ServiceResult:      statusCode,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

func serviceUnsupported(hdr *ua.RequestHeader) ua.Response {
	return &ua.ServiceFault{
		ResponseHeader: NewResponseHeader(hdr.RequestHandle, ua.StatusBadServiceUnsupported),
	}
}

func safeReq[T ua.Request](r ua.Request) (T, error) {
	var t T
	req, ok := r.(T)
	if !ok {
		//debug.Printf("expected %T, got %T", t, r)
		return t, ua.StatusBadRequestTypeInvalid
	}
	return req, nil
}

// func handleServiceFault(s Server, sc *uasc.SecureChannel, r ua.Request) (ua.Response, error) {
// 	debug.Printf("Handling %T", r)

// 	req, ok := r.(*ua.ServiceFault)
// 	if !ok {
// 		debug.Printf("handleServiceFault: Expected *ua.ServiceFault, got %T", r)
// 		return nil, ua.StatusBadRequestTypeInvalid
// 	}
// 	debug.Printf("Got ServiceFault: %s", req.ResponseHeader.ServiceResult)

// 	// No response required
// 	return nil, nil
// }
