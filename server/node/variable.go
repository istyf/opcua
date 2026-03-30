package node

import (
	"strconv"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
)

type ValueFunc func() *ua.DataValue

type variableConfig struct {
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
		cfg.accessLevelEx = ua.AccessLevelExType(level)
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

func WithHistorization(historizing bool) variableOption {
	return func(cfg *variableConfig) {
		cfg.historizing = historizing
	}
}

func WithValue(value any) variableOption {
	dataTypeNodeId, rank := LookupTypeNodeIDFromValue(value)
	if dataTypeNodeId == nil {
		panic("WithValue is only supported for built in types")
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
	id.Boolean:    ua.NewNumericNodeID(0, id.Boolean),
	id.SByte:      ua.NewNumericNodeID(0, id.SByte),
	id.Byte:       ua.NewNumericNodeID(0, id.Byte),
	id.Int16:      ua.NewNumericNodeID(0, id.Int16),
	id.UInt16:     ua.NewNumericNodeID(0, id.UInt16),
	id.Int32:      ua.NewNumericNodeID(0, id.Int32),
	id.UInt32:     ua.NewNumericNodeID(0, id.UInt32),
	id.Int64:      ua.NewNumericNodeID(0, id.Int64),
	id.UInt64:     ua.NewNumericNodeID(0, id.UInt64),
	id.Float:      ua.NewNumericNodeID(0, id.Float),
	id.Double:     ua.NewNumericNodeID(0, id.Double),
	id.String:     ua.NewNumericNodeID(0, id.String),
	id.ByteString: ua.NewNumericNodeID(0, id.ByteString),
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
	case []byte:
		return typeNodeIdFromDataType[id.ByteString], valueRank
	case []any:
		if len(v) > 0 {
			if typeNode, _ := LookupTypeNodeIDFromValue(v[0]); typeNode != nil {
				return typeNode, 1
			}
		}
	}

	return nil, valueRank
}

func NewVariableNode(base func(ua.NodeClass) *baseConfig, opts ...variableOption) types.VariableNode {

	cfg := &variableConfig{}

	for _, applyOption := range opts {
		applyOption(cfg)
	}

	n := &variableNode{
		baseNode:  *newBaseNode(base(ua.NodeClassVariable)),
		valueFunc: cfg.valueFunc,
	}

	n.baseNode.attr[ua.AttributeIDValueRank] = values.DataValueFromValue(cfg.rank)
	n.baseNode.attr[ua.AttributeIDDataType] = values.DataValueFromValue(cfg.dataTypeNodeId)
	n.baseNode.attr[ua.AttributeIDHistorizing] = values.DataValueFromValue(cfg.historizing)

	return n
}

func (n *variableNode) Attribute(id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDValue {
		return NewAttrValue(n.valueFunc()), nil
	}

	return n.baseNode.Attribute(id)
}

func (n *variableNode) SetAttribute(id ua.AttributeID, val *ua.DataValue) error {

	if id == ua.AttributeIDValue {
		// TODO: probably need to do some type checking here.
		// And some permissions tests
		if val != nil {
			copy := *val
			n.valueFunc = func() *ua.DataValue { return &copy }
		} else {
			n.valueFunc = func() *ua.DataValue { return nil }
		}

		return nil
	}

	return n.baseNode.SetAttribute(id, val)
}
