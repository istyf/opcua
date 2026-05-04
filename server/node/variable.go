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

type variableValueSource struct {
	snapshotDataValue func() *ua.DataValue
	onChange          func(func())
	setDataValue      func(*ua.DataValue)
}

type variableConfig struct {
	variableTypeNode types.VariableTypeNode

	dataTypeNodeId *ua.NodeID
	rank           int32
	valueSource    variableValueSource
	historizing    bool

	accessLevel   ua.AccessLevelType
	accessLevelEx ua.AccessLevelExType

	userAccessLevelHandler types.UserAccessLevelHandler
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

func WithUserAccessLevelHandler(handler types.UserAccessLevelHandler) variableOption {
	return func(cfg *variableConfig) {
		cfg.userAccessLevelHandler = handler
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
	binding, isBinding := value.(types.DataValueBinding)

	if !isVal && !isFun && !isBinding {
		panic("variable data value must be a *ua.DataValue, a func returning *ua.DataValue, or a DataValueBinding")
	}

	return func(cfg *variableConfig) {
		if isVal {
			cfg.valueSource = dataValueSourceFromSnapshot(func() *ua.DataValue { return v })
		} else if isFun {
			cfg.valueSource = dataValueSourceFromSnapshot(f)
		} else {
			cfg.valueSource = dataValueSourceFromBinding(binding)
		}
	}
}

func WithDataValueFunc(valueFunc func() *ua.DataValue) variableOption {
	return WithDataValue(valueFunc)
}

func WithDataValueBinding(binding types.DataValueBinding) variableOption {
	return WithDataValue(binding)
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
		cfg.valueSource = dataValueSourceFromSnapshot(func() *ua.DataValue { return dataValue })
	}
}

func WithValueFunc(valueFunc func() any) variableOption {
	dataTypeNodeId, rank := LookupTypeNodeIDFromValue(valueFunc)
	return func(cfg *variableConfig) {
		if dataTypeNodeId != nil {
			cfg.dataTypeNodeId = dataTypeNodeId
			cfg.rank = rank
		}
		cfg.valueSource = dataValueSourceFromValueSnapshot(valueFunc)
	}
}

func WithValueBinding(binding types.ValueBinding) variableOption {
	dataTypeNodeId, rank := LookupTypeNodeIDFromValue(binding.Snapshot())
	return func(cfg *variableConfig) {
		if dataTypeNodeId != nil {
			cfg.dataTypeNodeId = dataTypeNodeId
			cfg.rank = rank
		}
		cfg.valueSource = dataValueSourceFromValueBinding(binding)
	}
}

type variableNode struct {
	baseNode
	valueSource            variableValueSource
	accessLevel            ua.AccessLevelType
	userAccessLevelHandler types.UserAccessLevelHandler
	changeNotifier         func()
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
	id.QualifiedName: ua.NewNumericNodeID(0, id.QualifiedName),
	id.LocalizedText: ua.NewNumericNodeID(0, id.LocalizedText),
}

func cloneDataValue(value *ua.DataValue) *ua.DataValue {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func dataValueSourceFromSnapshot(snapshot func() *ua.DataValue) variableValueSource {
	return variableValueSource{
		snapshotDataValue: func() *ua.DataValue {
			return cloneDataValue(snapshot())
		},
	}
}

func dataValueSourceFromValueSnapshot(snapshot func() any) variableValueSource {
	return variableValueSource{
		snapshotDataValue: func() *ua.DataValue {
			value := snapshot()
			if value == nil {
				return nil
			}
			return values.DataValueFromValue(value)
		},
	}
}

func dataValueSourceFromBinding(binding types.DataValueBinding) variableValueSource {
	source := variableValueSource{
		snapshotDataValue: binding.SnapshotDataValue,
		onChange:          binding.OnChange,
	}

	if mutableBinding, ok := binding.(types.MutableDataValueBinding); ok {
		source.setDataValue = mutableBinding.SetDataValue
	}

	return source
}

func dataValueSourceFromValueBinding(binding types.ValueBinding) variableValueSource {
	source := variableValueSource{
		snapshotDataValue: func() *ua.DataValue {
			value := binding.Snapshot()
			if value == nil {
				return nil
			}
			return values.DataValueFromValue(value)
		},
		onChange: binding.OnChange,
	}

	if mutableBinding, ok := binding.(types.MutableValueBinding); ok {
		source.setDataValue = func(value *ua.DataValue) {
			if value == nil || value.Value == nil {
				mutableBinding.Set(nil)
				return
			}
			mutableBinding.Set(value.Value.Value())
		}
	}

	return source
}

func LookupTypeNodeIDFromValue(value any) (*ua.NodeID, int32) {
	valueRank := int32(-1)

	switch v := value.(type) {
	case func() *ua.DataValue:
		if dataValue := v(); dataValue != nil && dataValue.Value != nil {
			return LookupTypeNodeIDFromValue(dataValue.Value.Value())
		}
	case func() any:
		return LookupTypeNodeIDFromValue(v())
	case types.DataValueBinding:
		if dataValue := v.SnapshotDataValue(); dataValue != nil && dataValue.Value != nil {
			return LookupTypeNodeIDFromValue(dataValue.Value.Value())
		}
	case types.ValueBinding:
		return LookupTypeNodeIDFromValue(v.Snapshot())
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
	case *ua.QualifiedName:
		return typeNodeIdFromDataType[id.QualifiedName], valueRank
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
		baseNode:               *newBaseNode(base(ua.NodeClassVariable)),
		valueSource:            cfg.valueSource,
		accessLevel:            cfg.accessLevel,
		userAccessLevelHandler: cfg.userAccessLevelHandler,
	}

	n.baseNode.attr[ua.AttributeIDValueRank] = values.DataValueFromValue(cfg.rank)
	n.baseNode.attr[ua.AttributeIDDataType] = values.DataValueFromValue(cfg.dataTypeNodeId)
	n.baseNode.attr[ua.AttributeIDHistorizing] = values.DataValueFromValue(cfg.historizing)
	n.baseNode.attr[ua.AttributeIDAccessLevel] = values.DataValueFromValue(uint8(cfg.accessLevel))
	n.baseNode.attr[ua.AttributeIDAccessLevelEx] = values.DataValueFromValue(uint32(cfg.accessLevelEx))

	n.AddRef(refs.NewHasTypeDefinitionReferenceDescription(cfg.variableTypeNode))

	return n
}

// Access returns true if the node has the requested effective per-user access
// level.
func (n *variableNode) Access(ctx context.Context, flag ua.AccessLevelType) bool {
	return n.UserAccessLevel(ctx)&flag != 0
}

func (n *variableNode) UserAccessLevel(ctx context.Context) ua.AccessLevelType {
	if n.userAccessLevelHandler == nil {
		return n.accessLevel
	}

	return n.userAccessLevelHandler(ctx, n.accessLevel)
}

func (n *variableNode) SetUserAccessLevelHandler(handler types.UserAccessLevelHandler) {
	n.userAccessLevelHandler = handler
}

func (n *variableNode) Attribute(ctx context.Context, id ua.AttributeID) (*types.AttrValue, error) {
	if id == ua.AttributeIDUserAccessLevel {
		return NewAttrValue(values.DataValueFromValue(uint8(n.UserAccessLevel(ctx)))), nil
	}

	if id == ua.AttributeIDValue {
		if !n.Access(ctx, ua.AccessLevelTypeCurrentRead) {
			return NewAttrValue(&ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadUserAccessDenied,
			}), nil
		}

		return NewAttrValue(n.Value()), nil
	}

	return n.baseNode.Attribute(ctx, id)
}

func (n *variableNode) SetAttribute(ctx context.Context, id ua.AttributeID, val *ua.DataValue) error {

	if id == ua.AttributeIDValue {
		if !n.Access(ctx, ua.AccessLevelTypeCurrentWrite) {
			return ua.StatusBadUserAccessDenied
		}

		if n.valueSource.setDataValue != nil {
			n.valueSource.setDataValue(cloneDataValue(val))
			return nil
		}

		n.SetValue(cloneDataValue(val))
		return nil
	}

	return n.baseNode.SetAttribute(ctx, id, val)
}

func (n *variableNode) SetValue(value *ua.DataValue) {
	n.SetValueFunc(func() *ua.DataValue { return value })
}

func (n *variableNode) SetValueFunc(valueFunc func() *ua.DataValue) {
	n.setValueSource(dataValueSourceFromSnapshot(valueFunc))
}

func (n *variableNode) SetValueBinding(binding types.ValueBinding) {
	n.setValueSource(dataValueSourceFromValueBinding(binding))
}

func (n *variableNode) SetDataValueBinding(binding types.DataValueBinding) {
	n.setValueSource(dataValueSourceFromBinding(binding))
}

func (n *variableNode) BindChangeNotification(fn func()) {
	n.changeNotifier = fn
	if fn != nil && n.valueSource.onChange != nil {
		n.valueSource.onChange(fn)
	}
}

func (n *variableNode) setValueSource(source variableValueSource) {
	n.valueSource = source
	if n.changeNotifier != nil && source.onChange != nil {
		source.onChange(n.changeNotifier)
	}
}
