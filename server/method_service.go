package server

import (
	"context"

	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

// MethodService implements the Method Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MethodService struct {
	srv        *Server
	middleware node.MethodMiddleware
}

func NewMethodService(s *Server, middleware node.MethodMiddleware) *MethodService {
	return &MethodService{
		srv:        s,
		middleware: middleware,
	}
}

var newMethodServiceLogAttribute = newServiceLogAttributeCreatorForSet("method")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.2
func (s *MethodService) Call(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(srvctx.WithServiceSetAndName(ctx, "method", "call"), newMethodServiceLogAttribute("call"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CallRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.CallMethodResult, 0, len(req.MethodsToCall))
	status := ua.StatusOK

	// Check if the method has a non forward reference to this object
	methodBelongsToObject := func(method types.MethodNode, object types.Node) bool {
		return method.References().Contains(func(e *ua.ReferenceDescription) bool {
			return (!e.IsForward && e.NodeID.NodeID.IntID() == object.ID().IntID())
		})
	}

	for _, method := range req.MethodsToCall {
		ns, err := s.srv.Namespace(int(method.ObjectID.Namespace()))
		if err != nil {
			return &ua.CallResponse{
				ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadMethodInvalid),
			}, nil
		}

		objectNode := ns.Node(method.ObjectID)
		if objectNode == nil {
			return &ua.CallResponse{
				ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadNodeIDUnknown),
			}, nil
		}

		var methodNode types.MethodNode
		if n := ns.Node(method.MethodID); n != nil {
			methodNode, _ = n.(types.MethodNode)
		}

		if methodNode == nil || !methodBelongsToObject(methodNode, objectNode) {
			ualog.Error(ctx, "method does not exist or does not belong to object",
				ualog.String("method", methodNode.DisplayName().Text),
				ualog.String("object", objectNode.DisplayName().Text),
			)
			return &ua.CallResponse{
				ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadMethodInvalid),
			}, nil
		}

		res := &ua.CallMethodResult{}
		res.OutputArguments, res.StatusCode = s.middleware(methodNode.CallMethod)(
			srvctx.WithMethodCall(ctx,
				objectNode.ID().String(), objectNode.DisplayName().Text,
				methodNode.ID().String(), methodNode.DisplayName().Text,
			),
			method.InputArguments...,
		)

		ualog.Info(ctx, "called method",
			ualog.String("method", methodNode.DisplayName().Text),
			ualog.String("object", objectNode.DisplayName().Text),
			ualog.Any("status", res.StatusCode),
		)

		if res.StatusCode != ua.StatusOK && status == ua.StatusOK {
			status = res.StatusCode
		}

		results = append(results, res)
	}

	response := &ua.CallResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, status),
		// TODO: Support result data ...
	}

	if status == ua.StatusOK {
		response.Results = results
	}

	return response, nil
}
