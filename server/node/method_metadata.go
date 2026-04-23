package node

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

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
func MethodInputArgumentMatches(declared *ua.Argument, value *ua.Variant) bool {
	if declared == nil || value == nil {
		return false
	}

	actualType, actualRank := LookupTypeNodeIDFromValue(value.Value())
	if actualType == nil || !ValueRankMatches(actualRank, declared.ValueRank) {
		return false
	}
	if declared.DataType != nil && !declared.DataType.Equal(actualType) {
		return false
	}
	return true
}
