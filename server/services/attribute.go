package services

import (
	"context"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type HandlerRegistrator interface {
	RegisterHandler(typeID int, h Handler)
}

type AttributeServiceBackend interface {
	HandlerRegistrator
	NamespaceProvider
	SessionProvider
	Config() types.ServerConfig
}

// AttributeService implements the Attribute Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10
type AttributeService struct {
	backend AttributeServiceBackend
}

func NewAttributeService(b AttributeServiceBackend) *AttributeService {
	as := &AttributeService{
		backend: b,
	}

	b.RegisterHandler(id.ReadRequest_Encoding_DefaultBinary, as.Read)
	b.RegisterHandler(id.HistoryReadRequest_Encoding_DefaultBinary, as.HistoryRead)
	b.RegisterHandler(id.WriteRequest_Encoding_DefaultBinary, as.Write)
	b.RegisterHandler(id.HistoryUpdateRequest_Encoding_DefaultBinary, as.HistoryUpdate)

	return as
}

var newAttributeServiceLogAttribute = newServiceLogAttributeCreatorForSet("attribute")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.2
func (s *AttributeService) Read(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newAttributeServiceLogAttribute("read"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.ReadRequest](r)
	if err != nil {
		return nil, err
	}

	if req.RequestHeader != nil {
		ctx = decorateAuthorizationContext(ctx, s.backend.Config(), s.backend.Session(ctx, req.RequestHeader))
	}

	results := make([]*ua.DataValue, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		ualog.Debug(ctx, "reading node",
			ualog.Any("node_id", n.NodeID), ualog.Any("attr", n.AttributeID),
		)

		ns, err := s.backend.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			results[i] = &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBad,
			}
			continue
		}
		results[i] = ns.Attribute(ctx, n.NodeID, n.AttributeID)
	}

	response := &ua.ReadResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:        results,
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.3
func (s *AttributeService) HistoryRead(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newAttributeServiceLogAttribute("history read"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.HistoryReadRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.4
func (s *AttributeService) Write(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newAttributeServiceLogAttribute("write"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.WriteRequest](r)
	if err != nil {
		return nil, err
	}

	if req.RequestHeader != nil {
		ctx = decorateAuthorizationContext(ctx, s.backend.Config(), s.backend.Session(ctx, req.RequestHeader))
	}

	status := make([]ua.StatusCode, len(req.NodesToWrite))

	for i := range req.NodesToWrite {
		n := req.NodesToWrite[i]
		ualog.Debug(ctx, "writing node",
			ualog.Any("node_id", n.NodeID), ualog.Any("attr", n.AttributeID),
		)

		ns, err := s.backend.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			status[i] = ua.StatusBadNodeNotInView
		}

		status[i] = ns.SetAttribute(ctx, n.NodeID, n.AttributeID, n.Value)
	}

	response := &ua.WriteResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         status,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.5
func (s *AttributeService) HistoryUpdate(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newAttributeServiceLogAttribute("history update"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.HistoryUpdateRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
