package node

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type ValueFunc func() *ua.DataValue

type variableConfig struct {
	variableTypeNode types.VariableTypeNode

	dataTypeNodeId *ua.NodeID
	rank           int32
	valueFunc      func() *ua.DataValue
	historizing    bool

	accessLevel   ua.AccessLevelType
	accessLevelEx ua.AccessLevelExType
}

type variableOption func(*variableConfig)

func WithAccessLevel(level uint8) variableOption {
	return func(cfg *variableConfig) {
		cfg.accessLevel = ua.AccessLevelType(level)
	}
}

func WithAccessLevelEx(level uint32) variableOption {
	return func(cfg *variableConfig) {
		if level != math.MaxUint32 {
			cfg.accessLevelEx = ua.AccessLevelExType(level)

			lowestBits := ua.AccessLevelType(uint32(level) & 255)
			cfg.accessLevel = lowestBits
		}
	}
}

func WithAccessLevels(levels ...ua.AccessLevelExType) variableOption {
	var level ua.AccessLevelExType

	for _, l := range levels {
		if l == ua.AccessLevelExTypeNone && len(levels) > 1 {
			panic("ua.AccessLevelExTypeNone can not be combined with other levels")
		}

		level |= l
	}

	return func(cfg *variableConfig) {
		cfg.accessLevelEx = level

		lowestBits := ua.AccessLevelType(uint32(level) & 255)
		cfg.accessLevel = lowestBits
	}
}

func WithDataType(dataTypeNodeId *ua.NodeID) variableOption {
	return func(cfg *variableConfig) {
		cfg.dataTypeNodeId = dataTypeNodeId
	}
}

func WithDataValue(value any) variableOption {
	v, isVal := value.(*ua.DataValue)
	f, isFun := value.(func() *ua.DataValue)

	if !isVal && !isFun {
		panic("variable data value must be a *ua.DataValue or a func returning *ua.DataValue")
	}

	return func(cfg *variableConfig) {
		if isVal {
			cfg.valueFunc = func() *ua.DataValue { return v }
		} else if isFun {
			cfg.valueFunc = f
		}
	}
}

func WithValueRank(rank int32) variableOption {
	return func(cfg *variableConfig) {
		cfg.rank = rank
	}
}

func WithVariableType(varType types.VariableTypeNode) variableOption {

	if varType == nil {
		panic("creating variables with a nil type is not allowed")
	}

	return func(cfg *variableConfig) {
		cfg.variableTypeNode = varType
	}
}

func WithHistorization(historizing bool) variableOption {
	return func(cfg *variableConfig) {
		cfg.historizing = historizing
	}
}

func WithValue(value any) variableOption {
	dataTypeNodeId, rank := LookupTypeNodeIDFromValue(value)
	if dataTypeNodeId == nil {
		panic(fmt.Sprintf("WithValue is only supported for built in types: %v", value))
	}

	return func(cfg *variableConfig) {
		cfg.dataTypeNodeId = dataTypeNodeId
		cfg.rank = rank

		dataValue := values.DataValueFromValue(value)
		cfg.valueFunc = func() *ua.DataValue { return dataValue }
	}
}

type variableNode struct {
	baseNode
	valueFunc func() *ua.DataValue
}

var typeNodeIdFromDataType map[int]*ua.NodeID = map[int]*ua.NodeID{
	id.Boolean:       ua.NewNumericNodeID(0, id.Boolean),
	id.SByte:         ua.NewNumericNodeID(0, id.SByte),
	id.Byte:          ua.NewNumericNodeID(0, id.Byte),
	id.Int16:         ua.NewNumericNodeID(0, id.Int16),
	id.UInt16:        ua.NewNumericNodeID(0, id.UInt16),
	id.Int32:         ua.NewNumericNodeID(0, id.Int32),
	id.UInt32:        ua.NewNumericNodeID(0, id.UInt32),
	id.Int64:         ua.NewNumericNodeID(0, id.Int64),
	id.UInt64:        ua.NewNumericNodeID(0, id.UInt64),
	id.Float:         ua.NewNumericNodeID(0, id.Float),
	id.Double:        ua.NewNumericNodeID(0, id.Double),
	id.String:        ua.NewNumericNodeID(0, id.String),
	id.ByteString:    ua.NewNumericNodeID(0, id.ByteString),
	id.UtcTime:       ua.NewNumericNodeID(0, id.UtcTime),
	id.DateTime:      ua.NewNumericNodeID(0, id.DateTime),
	id.LocalizedText: ua.NewNumericNodeID(0, id.LocalizedText),
}

func LookupTypeNodeIDFromValue(value any) (*ua.NodeID, int32) {
	valueRank := int32(-1)

	switch v := value.(type) {
	case func() *ua.DataValue:
		if dataValue := v(); dataValue != nil && dataValue.Value != nil {
			return LookupTypeNodeIDFromValue(dataValue.Value.Value())
		}
	case bool:
		return typeNodeIdFromDataType[id.Boolean], valueRank
	case int8:
		return typeNodeIdFromDataType[id.SByte], valueRank
	case uint8:
		return typeNodeIdFromDataType[id.Byte], valueRank
	case int16:
		return typeNodeIdFromDataType[id.Int16], valueRank
	case uint16:
		return typeNodeIdFromDataType[id.UInt16], valueRank
	case int32:
		return typeNodeIdFromDataType[id.Int32], valueRank
	case []int32:
		return typeNodeIdFromDataType[id.Int32], 1
	case uint32:
		return typeNodeIdFromDataType[id.UInt32], valueRank
	case int64:
		return typeNodeIdFromDataType[id.Int64], valueRank
	case uint64:
		return typeNodeIdFromDataType[id.UInt64], valueRank
	case int:
		if strconv.IntSize == 64 {
			return typeNodeIdFromDataType[id.Int64], valueRank
		} else {
			return typeNodeIdFromDataType[id.Int32], valueRank
		}
	case uint:
		if strconv.IntSize == 64 {
			return typeNodeIdFromDataType[id.UInt64], valueRank
		} else {
			return typeNodeIdFromDataType[id.UInt32], valueRank
		}
	case float32:
		return typeNodeIdFromDataType[id.Float], valueRank
	case float64:
		return typeNodeIdFromDataType[id.Double], valueRank
	case string:
		return typeNodeIdFromDataType[id.String], valueRank
	case []string:
		return typeNodeIdFromDataType[id.String], 1
	case time.Time:
		if v.Location() == time.UTC {
			return typeNodeIdFromDataType[id.UtcTime], valueRank
		}
		return typeNodeIdFromDataType[id.DateTime], valueRank
	case *ua.ExtensionObject:
		return v.TypeID.NodeID, valueRank
	case []*ua.ExtensionObject:
		return v[0].TypeID.NodeID, 1
	case *ua.LocalizedText:
		return typeNodeIdFromDataType[id.LocalizedText], valueRank
	case []*ua.LocalizedText:
		return typeNodeIdFromDataType[id.LocalizedText], 1
	case []byte:
		return typeNodeIdFromDataType[id.ByteString], valueRank
	default:
		fmt.Printf("failed to handle value type: %v (%T)", v, v)
	}

	return nil, valueRank
}

func NewVariableNode(base func(ua.NodeClass) *baseConfig, opts ...variableOption) types.VariableNode {

	cfg := &variableConfig{
		accessLevel:   ua.AccessLevelTypeCurrentRead,
		accessLevelEx: ua.AccessLevelExTypeCurrentRead,
	}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	if cfg.variableTypeNode == nil {
		panic("creating variables with no variable type is not allowed")
		//cfg.variableTypeNodeId = ua.NewNumericNodeID(0, id.BaseVariableType)
	}

	n := &variableNode{
		baseNode:  *newBaseNode(base(ua.NodeClassVariable)),
		valueFunc: cfg.valueFunc,
	}

	n.baseNode.attr[ua.AttributeIDValueRank] = values.DataValueFromValue(cfg.rank)
	n.baseNode.attr[ua.AttributeIDDataType] = values.DataValueFromValue(cfg.dataTypeNodeId)
	n.baseNode.attr[ua.AttributeIDHistorizing] = values.DataValueFromValue(cfg.historizing)
	n.baseNode.attr[ua.AttributeIDAccessLevel] = values.DataValueFromValue(uint8(cfg.accessLevel))
	n.baseNode.attr[ua.AttributeIDAccessLevelEx] = values.DataValueFromValue(uint32(cfg.accessLevelEx))

	n.AddRef(refs.NewHasTypeDefinitionRefDesc(cfg.variableTypeNode))

	return n
}

// Access returns true if the node has the access level requested.
// It checks both the UserAccessLevel and AccessLevel attributes.
// If neither are present, it assumes global access and returns true.
//
// I'm not sure what the best way to implement "user" specific access levels
// is presently.  Will need functioning user authentication first, and then a way to
// pass it into the nodes user access attribute so it can be checked properly.
func (n *variableNode) Access(ctx context.Context, flag ua.AccessLevelType) bool {

	access, err := n.Attribute(ctx, ua.AttributeIDAccessLevel)
	if err == nil { // if we have an access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}

		if val&uint8(flag) == 0 {
			return false
		}
	}

	return true
}

func (n *variableNode) Attribute(ctx context.Context, id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDValue {
		if !n.Access(ctx, ua.AccessLevelTypeCurrentRead) {
			return NewAttrValue(&ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadUserAccessDenied,
			}), nil
		}

		return NewAttrValue(n.valueFunc()), nil
	}

	return n.baseNode.Attribute(ctx, id)
}

func (n *variableNode) SetAttribute(ctx context.Context, id ua.AttributeID, val *ua.DataValue) error {

	if id == ua.AttributeIDValue {
		if !n.Access(ctx, ua.AccessLevelTypeCurrentWrite) {
			return ua.StatusBadUserAccessDenied
		}

		if val != nil {
			copy := *val
			n.SetValueFunc(func() *ua.DataValue { return &copy })
		} else {
			n.SetValue(nil)
		}

		return nil
	}

	return n.baseNode.SetAttribute(ctx, id, val)
}

func (n *variableNode) SetValue(value *ua.DataValue) {
	n.SetValueFunc(func() *ua.DataValue { return value })
}

func (n *variableNode) SetValueFunc(valueFunc func() *ua.DataValue) {
	n.valueFunc = valueFunc
}
