package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/gopcua/opcua/id"
	srvctx "github.com/gopcua/opcua/server/context"
	srvnode "github.com/gopcua/opcua/server/node"
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
	Namespaces() []types.NameSpace
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
	appendResult := func(result *types.MethodResult) {
		if result == nil {
			panic("method handler returned nil result")
		}
		results = append(results, &ua.CallMethodResult{
			StatusCode:                   result.StatusCode,
			OutputArguments:              result.OutputArguments,
			InputArgumentResults:         result.InputArgumentResults,
			InputArgumentDiagnosticInfos: result.InputArgumentDiagnosticInfos,
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
	validateMethodInputArguments := func(methodNode types.MethodNode, inputArguments []*ua.Variant) *types.MethodResult {
		declared, ok := srvnode.MethodInputArguments(methodNode)
		if !ok {
			return nil
		}

		switch {
		case len(inputArguments) < len(declared):
			results := make([]ua.StatusCode, len(declared))
			for idx := range results {
				if idx < len(inputArguments) {
					results[idx] = ua.StatusOK
				} else {
					results[idx] = ua.StatusBadArgumentsMissing
				}
			}
			return &types.MethodResult{
				StatusCode:           ua.StatusBadArgumentsMissing,
				InputArgumentResults: results,
			}
		case len(inputArguments) > len(declared):
			results := make([]ua.StatusCode, len(inputArguments))
			for idx := range results {
				if idx < len(declared) {
					results[idx] = ua.StatusOK
				} else {
					results[idx] = ua.StatusBadTooManyArguments
				}
			}
			return &types.MethodResult{
				StatusCode:           ua.StatusBadTooManyArguments,
				InputArgumentResults: results,
			}
		}

		var (
			results      []ua.StatusCode
			overallError ua.StatusCode
		)
		for idx, arg := range inputArguments {
			status := ua.StatusOK
			if !srvnode.MethodInputArgumentMatches(s.backend, declared[idx], arg) {
				ualog.Warn(ctx, "method input argument type mismatch",
					methodInputArgumentMismatchLogAttrs(s.backend, methodNode, idx, declared[idx], arg)...,
				)
				status = ua.StatusBadTypeMismatch
			}

			if status != ua.StatusOK {
				if results == nil {
					results = make([]ua.StatusCode, len(inputArguments))
					for i := range results {
						results[i] = ua.StatusOK
					}
				}
				results[idx] = status
				if overallError == ua.StatusOK {
					overallError = ua.StatusBadTypeMismatch
				}
			}
		}

		if overallError != ua.StatusOK {
			return &types.MethodResult{
				StatusCode:           overallError,
				InputArgumentResults: results,
			}
		}
		return nil
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
			appendResult(types.NewMethodResult(ua.StatusBadNodeIDInvalid))
			continue
		}

		objectNS, err := s.backend.Namespace(int(method.ObjectID.Namespace()))
		if err != nil {
			appendResult(types.NewMethodResult(ua.StatusBadNodeIDUnknown))
			continue
		}

		objectNode := objectNS.Node(method.ObjectID)
		if objectNode == nil {
			appendResult(types.NewMethodResult(ua.StatusBadNodeIDUnknown))
			continue
		}

		methodNS, err := s.backend.Namespace(int(method.MethodID.Namespace()))
		if err != nil {
			appendResult(types.NewMethodResult(ua.StatusBadMethodInvalid))
			continue
		}

		var methodNode types.MethodNode
		if n := methodNS.Node(method.MethodID); n != nil {
			methodNode, _ = n.(types.MethodNode)
		}

		if methodNode == nil || !methodBelongsToObjectOrTypeHierarchy(methodNode, objectNode) {
			ualog.Error(ctx, "call failed",
				errors.New("method does not exist or does not belong to object"),
				ualog.String("method", requestedMethodLogName(method.MethodID, methodNode)),
				ualog.String("object", nodeLogName(objectNode)),
			)
			appendResult(types.NewMethodResult(ua.StatusBadMethodInvalid))
			continue
		}

		if !methodNode.IsExecutable(ctx) {
			ualog.Error(ctx, "call failed",
				errors.New("method is not executable"),
				ualog.String("method", nodeLogName(methodNode)),
				ualog.String("object", nodeLogName(objectNode)),
			)
			appendResult(types.NewMethodResult(ua.StatusBadNotExecutable))
			continue
		}

		callCtx := s.decorateCallContext(ctx, req.RequestHeader, objectNode, methodNode)
		if !methodNode.UserExecutable(callCtx) {
			ualog.Warn(ctx, "method is not executable for current user",
				ualog.String("method", nodeLogName(methodNode)),
				ualog.String("object", nodeLogName(objectNode)),
			)
			appendResult(types.NewMethodResult(ua.StatusBadUserAccessDenied))
			continue
		}
		if result := validateMethodInputArguments(methodNode, method.InputArguments); result != nil {
			appendResult(result)
			continue
		}

		result := s.middleware(methodNode.CallMethod)(callCtx, method.InputArguments...)
		if result == nil {
			panic("method handler returned nil result")
		}

		ualog.Info(ctx, "called method",
			ualog.String("method", nodeLogName(methodNode)),
			ualog.String("object", nodeLogName(objectNode)),
			ualog.Any("status", result.StatusCode),
		)

		appendResult(result)
	}

	response := &ua.CallResponse{
		ResponseHeader: NewResponseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
	}

	if len(results) != 0 {
		response.Results = results
	}

	return response, nil
}

func methodInputArgumentMismatchLogAttrs(
	backend MethodServiceBackend, methodNode types.MethodNode, index int, declared *ua.Argument, arg *ua.Variant,
) []ualog.Attr {
	attrs := make([]ualog.Attr, 0, 12)
	if methodNode != nil {
		if id := methodNode.ID(); id != nil {
			attrs = append(attrs, ualog.String("method_id", id.String()))
		}
		if browseName := methodNode.BrowseName(); browseName != nil {
			attrs = append(attrs, ualog.String("method_browse_name", browseName.String()))
		}
	}

	attrs = append(attrs, ualog.Int("argument_index", index))

	if declared != nil {
		attrs = append(attrs,
			ualog.String("declared_argument_name", declared.Name),
			ualog.Int("declared_value_rank", int(declared.ValueRank)),
		)
		if declared.DataType != nil {
			attrs = append(attrs, ualog.String("declared_data_type", declared.DataType.String()))
		}
	}

	if arg == nil {
		return append(attrs, ualog.String("actual_value", "<nil variant>"))
	}

	value := arg.Value()
	actualType, actualRank := srvnode.LookupTypeNodeIDFromValue(value)
	if actualType != nil {
		attrs = append(attrs, ualog.String("actual_type_from_value", actualType.String()))
	}
	attrs = append(attrs,
		ualog.Int("actual_value_rank", int(actualRank)),
		ualog.String("actual_go_type", fmt.Sprintf("%T", value)),
	)

	if extObj := arg.ExtensionObject(); extObj != nil {
		attrs = appendExtensionObjectTypeLogAttrs(backend, attrs, extObj.TypeID)
		return attrs
	}

	if extObjs, ok := value.([]*ua.ExtensionObject); ok {
		attrs = append(attrs, ualog.Int("extension_object_count", len(extObjs)))
		if len(extObjs) > 0 && extObjs[0] != nil {
			return appendExtensionObjectTypeLogAttrs(backend, attrs, extObjs[0].TypeID)
		}
	}

	return attrs
}

func appendExtensionObjectTypeLogAttrs(
	backend MethodServiceBackend, attrs []ualog.Attr, typeID *ua.ExpandedNodeID,
) []ualog.Attr {
	if typeID == nil || typeID.NodeID == nil {
		return append(attrs, ualog.String("extension_object_type_id", "<nil>"))
	}

	attrs = append(attrs, ualog.String("extension_object_type_id", typeID.NodeID.String()))
	if typeID.NamespaceURI != "" {
		attrs = append(attrs, ualog.String("extension_object_namespace_uri", typeID.NamespaceURI))
	}

	resolved := ua.NewNodeIDFromExpandedNodeID(typeID)
	if resolved == nil {
		return attrs
	}
	if typeID.NamespaceURI != "" {
		for _, ns := range backend.Namespaces() {
			if ns.Name() != typeID.NamespaceURI {
				continue
			}
			resolved.SetNamespace(ns.ID())
			break
		}
	}

	return append(attrs, ualog.String("extension_object_resolved_type_id", resolved.String()))
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
	return decorateAuthorizationContext(callCtx, s.backend.Config(), session)
}
