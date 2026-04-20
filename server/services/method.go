package services

import (
	"context"

	"github.com/gopcua/opcua/id"
	srvctx "github.com/gopcua/opcua/server/context"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

type MethodServiceBackend interface {
	HandlerRegistrator
	NamespaceProvider
}

// MethodService implements the Method Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MethodService struct {
	backend    MethodServiceBackend
	middleware types.MethodMiddleware
}

func NewMethodService(b MethodServiceBackend, middleware types.MethodMiddleware) *MethodService {
	ms := &MethodService{
		backend:    b,
		middleware: middleware,
	}

	b.RegisterHandler(id.CallRequest_Encoding_DefaultBinary, ms.Call)

	return ms
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
	appendResult := func(code ua.StatusCode, outputs ...*ua.Variant) {
		results = append(results, &ua.CallMethodResult{
			StatusCode:      code,
			OutputArguments: outputs,
		})
		if code != ua.StatusOK && status == ua.StatusOK {
			status = code
		}
	}

	// Check if the method has a non forward reference to this object
	methodBelongsToObject := func(method types.MethodNode, object types.Node) bool {
		return method.References().Contains(func(e types.ReferenceWrapper) bool {
			return !e.IsForward() && e.TargetsNode(object)
		})
	}

	for _, method := range req.MethodsToCall {
		if method.ObjectID == nil || method.MethodID == nil {
			appendResult(ua.StatusBadNodeIDInvalid)
			continue
		}

		objectNS, err := s.backend.Namespace(int(method.ObjectID.Namespace()))
		if err != nil {
			appendResult(ua.StatusBadNodeIDUnknown)
			continue
		}

		objectNode := objectNS.Node(method.ObjectID)
		if objectNode == nil {
			appendResult(ua.StatusBadNodeIDUnknown)
			continue
		}

		methodNS, err := s.backend.Namespace(int(method.MethodID.Namespace()))
		if err != nil {
			appendResult(ua.StatusBadMethodInvalid)
			continue
		}

		var methodNode types.MethodNode
		if n := methodNS.Node(method.MethodID); n != nil {
			methodNode, _ = n.(types.MethodNode)
		}

		if methodNode == nil || !methodBelongsToObject(methodNode, objectNode) {
			methodName := method.MethodID.String()
			if methodNode != nil {
				methodName = methodNode.BrowseName().String()
			}
			ualog.Error(ctx, "method does not exist or does not belong to object",
				ualog.String("method", methodName),
				ualog.String("object", objectNode.BrowseName().String()),
			)
			appendResult(ua.StatusBadMethodInvalid)
			continue
		}

		outputs, code := s.middleware(methodNode.CallMethod)(
			srvctx.WithMethodCall(ctx,
				objectNode.ID().String(), objectNode.BrowseName().String(),
				methodNode.ID().String(), methodNode.BrowseName().String(),
			),
			method.InputArguments...,
		)
		res := &ua.CallMethodResult{
			OutputArguments: outputs,
			StatusCode:      code,
		}

		ualog.Info(ctx, "called method",
			ualog.String("method", methodNode.BrowseName().String()),
			ualog.String("object", objectNode.BrowseName().String()),
			ualog.Any("status", res.StatusCode),
		)

		appendResult(res.StatusCode, res.OutputArguments...)
	}

	response := &ua.CallResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, status),
		// TODO: Support result data ...
	}

	if status == ua.StatusOK || len(results) != 0 {
		response.Results = results
	}

	return response, nil
}
