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
	SessionProvider
	Config() types.ServerConfig
}

// MethodService implements the Method Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MethodService struct {
	backend             MethodServiceBackend
	middleware          types.MethodMiddleware
	maxMethodOperations uint32
}

func NewMethodService(b MethodServiceBackend, middleware types.MethodMiddleware) *MethodService {
	if middleware == nil {
		middleware = func(fn types.MethodFunc) types.MethodFunc {
			return fn
		}
	}

	ms := &MethodService{
		backend:             b,
		middleware:          middleware,
		maxMethodOperations: b.Config().MaxMethodOperationsPerCall(),
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
	if len(req.MethodsToCall) == 0 {
		return nil, ua.StatusBadNothingToDo
	}
	if s.maxMethodOperations > 0 && uint32(len(req.MethodsToCall)) > s.maxMethodOperations {
		return nil, ua.StatusBadTooManyOperations
	}

	results := make([]*ua.CallMethodResult, 0, len(req.MethodsToCall))
	appendResult := func(code ua.StatusCode, outputs ...*ua.Variant) {
		results = append(results, &ua.CallMethodResult{
			StatusCode:      code,
			OutputArguments: outputs,
		})
	}
	nodeLogName := func(node types.Node) string {
		if node == nil {
			return ""
		}
		if browseName := node.BrowseName(); browseName != nil && browseName.Name != "" {
			return browseName.String()
		}
		if id := node.ID(); id != nil {
			return id.String()
		}
		return ""
	}
	requestedMethodLogName := func(methodID *ua.NodeID, methodNode types.MethodNode) string {
		if methodNode != nil {
			if browseName := methodNode.BrowseName(); browseName != nil && browseName.Name != "" {
				return browseName.String()
			}
			if id := methodNode.ID(); id != nil {
				return id.String()
			}
		}
		if methodID != nil {
			return methodID.String()
		}
		return ""
	}

	// Check if the method has a non forward reference to this object
	methodBelongsToObject := func(method types.MethodNode, object types.Node) bool {
		return method.References().Contains(func(e types.ReferenceWrapper) bool {
			return !e.IsForward() && e.TargetsNode(object)
		})
	}
	resolveTypeDefinitionNode := func(objectNode types.Node) types.Node {
		if objectNode == nil {
			return nil
		}
		for ref := range objectNode.References().Find(func(r types.ReferenceWrapper) bool {
			return r.IsReferenceType(id.HasTypeDefinition) && r.IsForward()
		}) {
			targetID := ref.TargetNodeID()
			if targetID == nil || targetID.NodeID == nil {
				continue
			}
			ns, err := s.backend.Namespace(int(targetID.NodeID.Namespace()))
			if err != nil {
				continue
			}
			if target := ns.Node(targetID.NodeID); target != nil {
				return target
			}
		}
		return nil
	}
	resolveBaseTypeNode := func(typeNode types.Node) types.Node {
		if typeNode == nil {
			return nil
		}
		for ref := range typeNode.References().Find(func(r types.ReferenceWrapper) bool {
			return r.IsReferenceType(id.HasSubtype) && !r.IsForward()
		}) {
			targetID := ref.TargetNodeID()
			if targetID == nil || targetID.NodeID == nil {
				continue
			}
			ns, err := s.backend.Namespace(int(targetID.NodeID.Namespace()))
			if err != nil {
				continue
			}
			if target := ns.Node(targetID.NodeID); target != nil {
				return target
			}
		}
		return nil
	}
	methodBelongsToObjectOrTypeHierarchy := func(method types.MethodNode, object types.Node) bool {
		if methodBelongsToObject(method, object) {
			return true
		}

		visited := make(map[string]struct{})
		for typeNode := resolveTypeDefinitionNode(object); typeNode != nil; typeNode = resolveBaseTypeNode(typeNode) {
			key := typeNode.ID().String()
			if _, ok := visited[key]; ok {
				break
			}
			visited[key] = struct{}{}

			if methodBelongsToObject(method, typeNode) {
				return true
			}
		}

		return false
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

		if methodNode == nil || !methodBelongsToObjectOrTypeHierarchy(methodNode, objectNode) {
			ualog.Error(ctx, "method does not exist or does not belong to object",
				ualog.String("method", requestedMethodLogName(method.MethodID, methodNode)),
				ualog.String("object", nodeLogName(objectNode)),
			)
			appendResult(ua.StatusBadMethodInvalid)
			continue
		}

		if !methodNode.IsExecutable(ctx) {
			ualog.Error(ctx, "method is not executable",
				ualog.String("method", nodeLogName(methodNode)),
				ualog.String("object", nodeLogName(objectNode)),
			)
			appendResult(ua.StatusBadNotExecutable)
			continue
		}

		outputs, code := s.middleware(methodNode.CallMethod)(
			s.decorateCallContext(ctx, req.RequestHeader, objectNode, methodNode),
			method.InputArguments...,
		)
		res := &ua.CallMethodResult{
			OutputArguments: outputs,
			StatusCode:      code,
		}

		ualog.Info(ctx, "called method",
			ualog.String("method", nodeLogName(methodNode)),
			ualog.String("object", nodeLogName(objectNode)),
			ualog.Any("status", res.StatusCode),
		)

		appendResult(res.StatusCode, res.OutputArguments...)
	}

	response := &ua.CallResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		// TODO: Support result data ...
	}

	if len(results) != 0 {
		response.Results = results
	}

	return response, nil
}

func (s *MethodService) decorateCallContext(
	ctx context.Context,
	reqHeader *ua.RequestHeader,
	objectNode types.Node,
	methodNode types.MethodNode,
) context.Context {
	callCtx := srvctx.WithMethodCall(ctx,
		objectNode.ID().String(), objectNode.BrowseName().String(),
		methodNode.ID().String(), methodNode.BrowseName().String(),
	)
	decorator := s.backend.Config().AuthorizationContextDecorator()
	if decorator == nil || reqHeader == nil {
		return callCtx
	}

	session := s.backend.Session(ctx, reqHeader)
	if session == nil {
		return callCtx
	}

	decoratedCtx := decorator(callCtx, session.AuthenticatedUser())
	if decoratedCtx == nil {
		panic("server authorization context decorator returned nil context")
	}
	return decoratedCtx
}
