package services

import (
	"context"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type QueryServiceBackend interface {
	HandlerRegistrator
}

// QueryService implements the Query Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type QueryService struct {
	backend QueryServiceBackend
}

func NewQueryService(b QueryServiceBackend) *QueryService {
	return &QueryService{
		backend: b,
	}
}

var newQueryServiceLogAttribute = newServiceLogAttributeCreatorForSet("query")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *QueryService) QueryFirst(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newQueryServiceLogAttribute("query first"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.QueryFirstRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *QueryService) QueryNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newQueryServiceLogAttribute("query next"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.QueryNextRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
