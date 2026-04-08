package services

import (
	"context"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type NodeManagementBackend interface {
	HandlerRegistrator
}

// NodeManagementService implements the Node Management Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7
type NodeManagementService struct {
	backend NodeManagementBackend
}

func NewNodeManagementService(b NodeManagementBackend) *NodeManagementService {
	nms := &NodeManagementService{
		backend: b,
	}

	b.RegisterHandler(id.AddNodesRequest_Encoding_DefaultBinary, nms.AddNodes)
	b.RegisterHandler(id.AddReferencesRequest_Encoding_DefaultBinary, nms.AddReferences)
	b.RegisterHandler(id.DeleteNodesRequest_Encoding_DefaultBinary, nms.DeleteNodes)
	b.RegisterHandler(id.DeleteReferencesRequest_Encoding_DefaultBinary, nms.DeleteReferences)

	return nms
}

var newNodeMgmtServiceLogAttribute = newServiceLogAttributeCreatorForSet("nodemanagement")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.2
func (s *NodeManagementService) AddNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newNodeMgmtServiceLogAttribute("add nodes"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.AddNodesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.3
func (s *NodeManagementService) AddReferences(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newNodeMgmtServiceLogAttribute("add references"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.AddReferencesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.4
func (s *NodeManagementService) DeleteNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newNodeMgmtServiceLogAttribute("delete nodes"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.DeleteNodesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.5
func (s *NodeManagementService) DeleteReferences(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newNodeMgmtServiceLogAttribute("delete references"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.DeleteReferencesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
