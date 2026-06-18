package node

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

type namespaceResolver interface {
	Namespace(int) (types.NameSpace, error)
	Namespaces() []types.NameSpace
}

// MethodInputArguments returns the decoded InputArguments property for a method
// node when that metadata is available in the address space.
func MethodInputArguments(method types.MethodNode) ([]*ua.Argument, bool) {
	for ref := range method.References().Find(func(r types.ReferenceWrapper) bool {
		return r.IsReferenceType(id.HasProperty) && r.IsForward()
	}) {
		target := ref.TargetNode()
		if target == nil {
			continue
		}

		browseName := target.BrowseName()
		if browseName == nil || browseName.Name != "InputArguments" {
			continue
		}

		valueNode, ok := target.(types.VariableNode)
		if !ok {
			return nil, false
		}

		value := valueNode.Value()
		if value == nil || value.Value == nil {
			return nil, false
		}

		switch v := value.Value.Value().(type) {
		case []*ua.Argument:
			return v, true
		case []ua.Argument:
			out := make([]*ua.Argument, 0, len(v))
			for idx := range v {
				arg := v[idx]
				out = append(out, &arg)
			}
			return out, true
		case []*ua.ExtensionObject:
			out := make([]*ua.Argument, 0, len(v))
			for _, eo := range v {
				if eo == nil {
					return nil, false
				}
				arg, ok := eo.Value.(*ua.Argument)
				if !ok || arg == nil {
					return nil, false
				}
				out = append(out, arg)
			}
			return out, true
		}

		return nil, false
	}

	return nil, false
}

// ValueRankMatches reports whether an actual argument rank is compatible with a
// declared OPC UA ValueRank.
func ValueRankMatches(actual int32, declared int32) bool {
	// OPC UA uses negative sentinel values here:
	// -2 means "Any", and -3 means "ScalarOrOneDimension".
	if declared == -2 {
		return true
	}
	if declared == -3 {
		return actual == -1 || actual == 1
	}
	return actual == declared
}

// MethodInputArgumentMatches reports whether a call argument matches the
// declared InputArguments metadata for one position.
func MethodInputArgumentMatches(resolver namespaceResolver, declared *ua.Argument, value *ua.Variant) bool {
	if declared == nil || value == nil || value.Value() == nil {
		return false
	}

	actualType, actualRank := LookupTypeNodeIDFromValue(value.Value())
	if actualType == nil || !ValueRankMatches(actualRank, declared.ValueRank) {
		return false
	}
	if declared.DataType == nil || declared.DataType.Equal(actualType) {
		return true
	}
	if methodArgumentEnumScalarMatchesDeclaredDataType(resolver, declared.DataType, actualType) {
		return true
	}
	if methodArgumentDataTypeDerivationMatches(resolver, declared.DataType, actualType) {
		return true
	}

	if !isExtensionObjectValue(value.Value()) || resolver == nil {
		return false
	}

	actualType = extensionObjectTypeNodeID(resolver, value.Value(), actualType)

	return methodArgumentEncodingMatchesDeclaredDataType(resolver, declared.DataType, actualType)
}

func methodArgumentEnumScalarMatchesDeclaredDataType(resolver namespaceResolver, declaredType, actualType *ua.NodeID) bool {
	if resolver == nil || declaredType == nil || actualType == nil {
		return false
	}
	if actualType.Namespace() != 0 || actualType.IntID() != id.Int32 {
		return false
	}

	return dataTypeDerivesFrom(resolver, declaredType, ua.NewNumericNodeID(0, id.Enumeration))
}

func methodArgumentDataTypeDerivationMatches(resolver namespaceResolver, declaredType, actualType *ua.NodeID) bool {
	if resolver == nil || declaredType == nil || actualType == nil {
		return false
	}

	return dataTypeDerivesFrom(resolver, declaredType, actualType) ||
		dataTypeDerivesFrom(resolver, actualType, declaredType)
}

func dataTypeDerivesFrom(resolver namespaceResolver, declaredType, superType *ua.NodeID) bool {
	if resolver == nil || declaredType == nil || superType == nil {
		return false
	}

	pending := []*ua.NodeID{declaredType}
	seen := map[string]struct{}{}

	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == nil {
			continue
		}
		if current.Equal(superType) {
			return true
		}
		if _, ok := seen[current.String()]; ok {
			continue
		}
		seen[current.String()] = struct{}{}

		currentNS, err := resolver.Namespace(int(current.Namespace()))
		if err != nil {
			continue
		}

		currentNode := currentNS.Node(current)
		if currentNode == nil {
			continue
		}

		for ref := range currentNode.References().Find(func(ref types.ReferenceWrapper) bool {
			return ref.IsReferenceType(id.HasSubtype) && !ref.IsForward()
		}) {
			target := ref.TargetNode()
			if target != nil {
				pending = append(pending, target.ID())
				continue
			}

			targetID := ref.TargetNodeID()
			if targetID == nil || targetID.NodeID == nil {
				continue
			}

			pending = append(pending, targetID.NodeID)
		}
	}

	return false
}

func methodArgumentEncodingMatchesDeclaredDataType(resolver namespaceResolver, declaredType, actualType *ua.NodeID) bool {
	if resolver == nil || declaredType == nil || actualType == nil {
		return false
	}

	actualNS, err := resolver.Namespace(int(actualType.Namespace()))
	if err != nil {
		return false
	}
	actualNode := actualNS.Node(actualType)
	if actualNode == nil {
		return methodArgumentDeclaredTypeReferencesEncoding(resolver, declaredType, actualType)
	}

	if actualNode.References().Contains(func(ref types.ReferenceWrapper) bool {
		if !ref.IsReferenceType(id.HasEncoding) {
			return false
		}

		target := ref.TargetNode()
		if target != nil {
			return target.ID().Equal(declaredType)
		}

		targetID := ref.TargetNodeID()
		return targetID != nil && targetID.NodeID != nil && targetID.NodeID.Equal(declaredType)
	}) {
		return true
	}

	return methodArgumentDeclaredTypeReferencesEncoding(resolver, declaredType, actualType)
}

func methodArgumentDeclaredTypeReferencesEncoding(resolver namespaceResolver, declaredType, actualType *ua.NodeID) bool {
	declaredNS, err := resolver.Namespace(int(declaredType.Namespace()))
	if err != nil {
		return false
	}

	declaredNode := declaredNS.Node(declaredType)
	if declaredNode == nil {
		return false
	}

	return declaredNode.References().Contains(func(ref types.ReferenceWrapper) bool {
		if !ref.IsReferenceType(id.HasEncoding) {
			return false
		}

		target := ref.TargetNode()
		if target != nil {
			return target.ID().Equal(actualType)
		}

		targetID := ref.TargetNodeID()
		return targetID != nil && targetID.NodeID != nil && targetID.NodeID.Equal(actualType)
	})
}

func isExtensionObjectValue(value any) bool {
	switch value.(type) {
	case *ua.ExtensionObject, []*ua.ExtensionObject:
		return true
	default:
		return false
	}
}

func extensionObjectTypeNodeID(resolver namespaceResolver, value any, fallback *ua.NodeID) *ua.NodeID {
	switch v := value.(type) {
	case *ua.ExtensionObject:
		return resolveExpandedNodeID(resolver, v.TypeID, fallback)
	case []*ua.ExtensionObject:
		if len(v) == 0 {
			return fallback
		}
		return resolveExpandedNodeID(resolver, v[0].TypeID, fallback)
	default:
		return fallback
	}
}

func resolveExpandedNodeID(resolver namespaceResolver, id *ua.ExpandedNodeID, fallback *ua.NodeID) *ua.NodeID {
	if id == nil || id.NodeID == nil {
		return fallback
	}

	nodeID := ua.NewNodeIDFromExpandedNodeID(id)
	if nodeID == nil {
		return fallback
	}

	if id.NamespaceURI == "" {
		return nodeID
	}

	for _, ns := range resolver.Namespaces() {
		if ns.Name() != id.NamespaceURI {
			continue
		}

		nodeID.SetNamespace(ns.ID())
		return nodeID
	}

	return nodeID
}
