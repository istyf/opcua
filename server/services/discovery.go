package services

import (
	"context"
	"strings"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type DiscoveryServiceBackend interface {
	HandlerRegistrator
	EndpointsProvider
}

// DiscoveryService implements the Discovery Service Set
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4
type DiscoveryService struct {
	backend DiscoveryServiceBackend
}

func NewDiscoveryService(b DiscoveryServiceBackend) *DiscoveryService {
	ds := &DiscoveryService{
		backend: b,
	}

	b.RegisterHandler(id.FindServersRequest_Encoding_DefaultBinary, ds.FindServers)
	b.RegisterHandler(id.FindServersOnNetworkRequest_Encoding_DefaultBinary, ds.FindServersOnNetwork)
	b.RegisterHandler(id.GetEndpointsRequest_Encoding_DefaultBinary, ds.GetEndpoints)
	b.RegisterHandler(id.RegisterServerRequest_Encoding_DefaultBinary, ds.RegisterServer)
	b.RegisterHandler(id.RegisterServer2Request_Encoding_DefaultBinary, ds.RegisterServer2)

	return ds
}

var newDiscoveryServiceLogAttribute = newServiceLogAttributeCreatorForSet("discovery")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.2
func (s *DiscoveryService) FindServers(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newDiscoveryServiceLogAttribute("find servers"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.FindServersRequest](r)
	if err != nil {
		return nil, err
	}

	response := &ua.FindServersResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Servers: []*ua.ApplicationDescription{
			s.backend.Endpoints()[0].Server,
		},
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.3
func (s *DiscoveryService) FindServersOnNetwork(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newDiscoveryServiceLogAttribute("find servers on network"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.FindServersOnNetworkRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.4
func (s *DiscoveryService) GetEndpoints(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newDiscoveryServiceLogAttribute("get endpoints"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.GetEndpointsRequest](r)
	if err != nil {
		return nil, err
	}

	requrl := strings.ToLower(req.EndpointURL)
	matching_endpoints := make([]*ua.EndpointDescription, 0)
	for _, ep := range s.backend.Endpoints() {
		if strings.ToLower(ep.EndpointURL) == requrl {
			matching_endpoints = append(matching_endpoints, ep)
		}
	}

	response := &ua.GetEndpointsResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Endpoints:      matching_endpoints,
	}

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.5
func (s *DiscoveryService) RegisterServer(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newDiscoveryServiceLogAttribute("register server"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.RegisterServerRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.6
func (s *DiscoveryService) RegisterServer2(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newDiscoveryServiceLogAttribute("register server 2"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.RegisterServer2Request](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
