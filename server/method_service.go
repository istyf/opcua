package server

import (
	"context"
	"slices"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

// MethodService implements the Method Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MethodService struct {
	srv *Server
}

func NewMethodService(s *Server) *MethodService {
	return &MethodService{
		srv: s,
	}
}

var newMethodServiceLogAttribute = newServiceLogAttributeCreatorForSet("method")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.2
func (s *MethodService) Call(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newMethodServiceLogAttribute("call"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.CallRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.CallMethodResult, 0, len(req.MethodsToCall))
	status := ua.StatusOK

	// Check if the method has a non forward reference to this object
	methodBelongsToObject := func(method *Node, object *Node) bool {
		return slices.ContainsFunc(
			method.refs,
			func(e *ua.ReferenceDescription) bool {
				if !e.IsForward && e.NodeID.NodeID.IntID() == object.id.IntID() {
					return true
				}
				return false
			},
		)
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

		methodNode := ns.Node(method.MethodID)

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
		res.OutputArguments, res.StatusCode = methodNode.CallMethod(
			context.Background(),
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
