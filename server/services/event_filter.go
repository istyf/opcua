package services

import (
	"context"
	"strings"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

const eventFieldPathSeparator = "/"

func newEventFilterResult(filter *ua.EventFilter) *ua.ExtensionObject {
	result := &ua.EventFilterResult{
		SelectClauseDiagnosticInfos: []*ua.DiagnosticInfo{},
		WhereClauseResult: &ua.ContentFilterResult{
			ElementResults:         []*ua.ContentFilterElementResult{},
			ElementDiagnosticInfos: []*ua.DiagnosticInfo{},
		},
	}
	if filter != nil {
		result.SelectClauseResults = make([]ua.StatusCode, len(filter.SelectClauses))
		for i := range result.SelectClauseResults {
			result.SelectClauseResults[i] = ua.StatusOK
		}
	}
	return ua.NewExtensionObject(result)
}

func validateEventFilter(ctx context.Context, filter *ua.EventFilter, filterResult *ua.ExtensionObject) ua.StatusCode {
	if filter == nil {
		return ua.StatusBadMonitoredItemFilterInvalid
	}

	var result *ua.EventFilterResult
	if filterResult != nil {
		result, _ = filterResult.Value.(*ua.EventFilterResult)
	}
	var status ua.StatusCode = ua.StatusOK
	for i, clause := range filter.SelectClauses {
		clauseStatus := validateEventSelectClause(clause)
		if clauseStatus != ua.StatusOK {
			if result != nil && i < len(result.SelectClauseResults) {
				result.SelectClauseResults[i] = clauseStatus
			}
			status = ua.StatusBadEventFilterInvalid
		}
	}
	if status != ua.StatusOK {
		return status
	}

	whereResult, whereStatus := validateEventWhereClause(ctx, filter.WhereClause)
	if whereResult != nil && result != nil {
		result.WhereClauseResult = whereResult
	}
	return whereStatus
}

func validateEventSelectClause(clause *ua.SimpleAttributeOperand) ua.StatusCode {
	if clause == nil {
		return ua.StatusBadFilterOperandInvalid
	}
	if clause.AttributeID == ua.AttributeIDNodeID && len(clause.BrowsePath) == 0 {
		return ua.StatusOK
	}
	if clause.AttributeID != ua.AttributeIDValue || len(clause.BrowsePath) == 0 {
		return ua.StatusBadFilterOperandInvalid
	}
	for _, name := range clause.BrowsePath {
		if name == nil || name.Name == "" {
			return ua.StatusBadFilterOperandInvalid
		}
	}
	return ua.StatusOK
}

func validateEventWhereClause(ctx context.Context, where *ua.ContentFilter) (*ua.ContentFilterResult, ua.StatusCode) {
	if where == nil || len(where.Elements) == 0 {
		return nil, ua.StatusOK
	}

	for i, elem := range where.Elements {
		ualog.Debug(ctx, "event where clause element",
			ualog.Int("index", i),
			ualog.Any("operator", elem.FilterOperator),
			ualog.Int("operand_count", len(elem.FilterOperands)),
			ualog.Any("operands", elem.FilterOperands),
		)
	}

	result := &ua.ContentFilterResult{
		ElementResults:         make([]*ua.ContentFilterElementResult, len(where.Elements)),
		ElementDiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	if len(where.Elements) != 1 {
		for i, element := range where.Elements {
			result.ElementResults[i] = unsupportedContentFilterElementResult(element)
		}
		return result, ua.StatusBadMonitoredItemFilterUnsupported
	}

	elementResult, status := validateEventWhereElement(where.Elements[0])
	result.ElementResults[0] = elementResult
	return result, status
}

func validateEventWhereElement(element *ua.ContentFilterElement) (*ua.ContentFilterElementResult, ua.StatusCode) {
	if element == nil {
		return &ua.ContentFilterElementResult{
			StatusCode:             ua.StatusBadFilterElementInvalid,
			OperandStatusCodes:     []ua.StatusCode{},
			OperandDiagnosticInfos: []*ua.DiagnosticInfo{},
		}, ua.StatusBadEventFilterInvalid
	}

	result := &ua.ContentFilterElementResult{
		StatusCode:             ua.StatusOK,
		OperandStatusCodes:     make([]ua.StatusCode, len(element.FilterOperands)),
		OperandDiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	for i := range result.OperandStatusCodes {
		result.OperandStatusCodes[i] = ua.StatusOK
	}

	if element.FilterOperator == ua.FilterOperatorOfType {
		return validateEventWhereOfTypeElement(element, result)
	}

	if !eventFilterComparisonOperatorSupported(element.FilterOperator) {
		result.StatusCode = ua.StatusBadFilterOperatorUnsupported
		return result, ua.StatusBadMonitoredItemFilterUnsupported
	}
	if len(element.FilterOperands) != 2 {
		result.StatusCode = ua.StatusBadFilterOperandCountMismatch
		return result, ua.StatusBadEventFilterInvalid
	}

	left, ok := simpleAttributeOperandFromExtensionObject(element.FilterOperands[0])
	if !ok || validateEventSelectClause(left) != ua.StatusOK || !eventWhereSelectClauseSupported(left) {
		result.OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
		return result, ua.StatusBadEventFilterInvalid
	}
	right, ok := literalOperandFromExtensionObject(element.FilterOperands[1])
	if !ok || right.Value == nil || !variantIsNumeric(right.Value) {
		result.OperandStatusCodes[1] = ua.StatusBadFilterOperandInvalid
		return result, ua.StatusBadEventFilterInvalid
	}

	return result, ua.StatusOK
}

func validateEventWhereOfTypeElement(element *ua.ContentFilterElement, result *ua.ContentFilterElementResult) (*ua.ContentFilterElementResult, ua.StatusCode) {
	if len(element.FilterOperands) != 1 {
		result.StatusCode = ua.StatusBadFilterOperandCountMismatch
		return result, ua.StatusBadEventFilterInvalid
	}

	operand, ok := literalOperandFromExtensionObject(element.FilterOperands[0])
	if !ok || operand.Value == nil {
		result.OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
		return result, ua.StatusBadEventFilterInvalid
	}

	if _, ok := nodeIDFromVariant(operand.Value); !ok {
		result.OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
		return result, ua.StatusBadEventFilterInvalid
	}

	return result, ua.StatusOK
}

func nodeIDFromVariant(value *ua.Variant) (*ua.NodeID, bool) {
	if value == nil || value.ArrayLength() > 0 {
		return nil, false
	}

	switch v := value.Value().(type) {
	case *ua.NodeID:
		return v, v != nil
	case ua.NodeID:
		return &v, true
	default:
		return nil, false
	}
}

func unsupportedContentFilterElementResult(element *ua.ContentFilterElement) *ua.ContentFilterElementResult {
	operandCount := 0
	if element != nil {
		operandCount = len(element.FilterOperands)
	}
	return &ua.ContentFilterElementResult{
		StatusCode:             ua.StatusBadFilterOperatorUnsupported,
		OperandStatusCodes:     make([]ua.StatusCode, operandCount),
		OperandDiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

func eventWhereSelectClauseSupported(clause *ua.SimpleAttributeOperand) bool {
	return canonicalBaseEventFieldName(selectClauseBrowsePathKey(clause)) == "Severity"
}

func eventFilterComparisonOperatorSupported(operator ua.FilterOperator) bool {
	switch operator {
	case ua.FilterOperatorEquals,
		ua.FilterOperatorGreaterThan,
		ua.FilterOperatorLessThan,
		ua.FilterOperatorGreaterThanOrEqual,
		ua.FilterOperatorLessThanOrEqual:
		return true
	default:
		return false
	}
}

func eventFilterSelectFields(filter *ua.EventFilter, event *types.Event) []*ua.Variant {
	if filter == nil {
		return nil
	}

	fields := make([]*ua.Variant, len(filter.SelectClauses))
	for i, clause := range filter.SelectClauses {
		fields[i] = eventFieldVariant(event, clause)
	}
	return fields
}

func eventFilterMatches(filter *ua.EventFilter, event *types.Event) bool {
	if filter == nil || event == nil {
		return false
	}
	if filter.WhereClause == nil || len(filter.WhereClause.Elements) == 0 {
		return true
	}
	if len(filter.WhereClause.Elements) != 1 {
		return false
	}
	return eventWhereElementMatches(filter.WhereClause.Elements[0], event)
}

func eventWhereElementMatches(element *ua.ContentFilterElement, event *types.Event) bool {
	if element == nil {
		return false
	}

	if element.FilterOperator == ua.FilterOperatorOfType {
		return eventWhereOfTypeElementMatches(element, event)
	}

	if len(element.FilterOperands) != 2 {
		return false
	}

	leftOperand, ok := simpleAttributeOperandFromExtensionObject(element.FilterOperands[0])
	if !ok {
		return false
	}
	rightOperand, ok := literalOperandFromExtensionObject(element.FilterOperands[1])
	if !ok || rightOperand.Value == nil {
		return false
	}

	left := eventFieldVariant(event, leftOperand)
	return compareVariantNumbers(element.FilterOperator, left, rightOperand.Value)
}

func eventWhereOfTypeElementMatches(element *ua.ContentFilterElement, event *types.Event) bool {
	if element == nil || event == nil || len(element.FilterOperands) != 1 {
		return false
	}

	operand, ok := literalOperandFromExtensionObject(element.FilterOperands[0])
	if !ok || operand.Value == nil {
		return false
	}

	requestedType, ok := nodeIDFromVariant(operand.Value)
	if !ok || requestedType == nil || event.EventType == nil {
		return false
	}

	// TODO: walk the event type hierarchy so OfType also matches subtypes.
	return event.EventType.Equal(requestedType)
}

func eventFieldVariant(event *types.Event, clause *ua.SimpleAttributeOperand) *ua.Variant {
	if event == nil || clause == nil {
		return nullVariant()
	}

	if clause.AttributeID == ua.AttributeIDNodeID && len(clause.BrowsePath) == 0 {
		return variantOrNull(event.SourceNode)
	}

	key := selectClauseBrowsePathKey(clause)
	switch canonicalBaseEventFieldName(key) {
	case "EventId":
		return variantOrNull(event.EventID)
	case "EventType":
		return variantOrNull(event.EventType)
	case "SourceNode":
		return variantOrNull(event.SourceNode)
	case "SourceName":
		return variantOrNull(event.SourceName)
	case "Time":
		return variantOrNull(event.Time)
	case "ReceiveTime":
		return variantOrNull(event.ReceiveTime)
	case "Message":
		return variantOrNull(event.Message)
	case "Severity":
		return variantOrNull(event.Severity)
	}

	if event.Fields != nil {
		if value := event.Fields[key]; value != nil {
			return value
		}
	}
	return nullVariant()
}

func selectClauseBrowsePathKey(clause *ua.SimpleAttributeOperand) string {
	if clause == nil || len(clause.BrowsePath) == 0 {
		return ""
	}

	parts := make([]string, 0, len(clause.BrowsePath))
	for _, name := range clause.BrowsePath {
		if name == nil {
			return ""
		}
		parts = append(parts, name.Name)
	}
	return strings.Join(parts, eventFieldPathSeparator)
}

func canonicalBaseEventFieldName(key string) string {
	switch strings.ToLower(key) {
	case "eventid":
		return "EventId"
	case "eventtype":
		return "EventType"
	case "sourcenode":
		return "SourceNode"
	case "sourcename":
		return "SourceName"
	case "time":
		return "Time"
	case "receivetime":
		return "ReceiveTime"
	case "message":
		return "Message"
	case "severity":
		return "Severity"
	default:
		return ""
	}
}

func simpleAttributeOperandFromExtensionObject(obj *ua.ExtensionObject) (*ua.SimpleAttributeOperand, bool) {
	if obj == nil || obj.Value == nil {
		return nil, false
	}
	switch operand := obj.Value.(type) {
	case *ua.SimpleAttributeOperand:
		return operand, operand != nil
	case ua.SimpleAttributeOperand:
		return &operand, true
	default:
		return nil, false
	}
}

func literalOperandFromExtensionObject(obj *ua.ExtensionObject) (*ua.LiteralOperand, bool) {
	if obj == nil || obj.Value == nil {
		return nil, false
	}
	switch operand := obj.Value.(type) {
	case *ua.LiteralOperand:
		return operand, operand != nil
	case ua.LiteralOperand:
		return &operand, true
	default:
		return nil, false
	}
}

func compareVariantNumbers(operator ua.FilterOperator, left, right *ua.Variant) bool {
	leftNumber, ok := variantNumber(left)
	if !ok {
		return false
	}
	rightNumber, ok := variantNumber(right)
	if !ok {
		return false
	}

	switch operator {
	case ua.FilterOperatorEquals:
		return leftNumber == rightNumber
	case ua.FilterOperatorGreaterThan:
		return leftNumber > rightNumber
	case ua.FilterOperatorLessThan:
		return leftNumber < rightNumber
	case ua.FilterOperatorGreaterThanOrEqual:
		return leftNumber >= rightNumber
	case ua.FilterOperatorLessThanOrEqual:
		return leftNumber <= rightNumber
	default:
		return false
	}
}

func variantIsNumeric(value *ua.Variant) bool {
	_, ok := variantNumber(value)
	return ok
}

func variantNumber(value *ua.Variant) (float64, bool) {
	if value == nil || value.ArrayLength() > 0 {
		return 0, false
	}
	switch v := value.Value().(type) {
	case int8:
		return float64(v), true
	case uint8:
		return float64(v), true
	case int16:
		return float64(v), true
	case uint16:
		return float64(v), true
	case int32:
		return float64(v), true
	case uint32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

func variantOrNull(value any) *ua.Variant {
	switch v := value.(type) {
	case nil:
		return nullVariant()
	case time.Time:
		if v.IsZero() {
			return nullVariant()
		}
	case []byte:
		if v == nil {
			return nullVariant()
		}
	case *ua.NodeID:
		if v == nil {
			return nullVariant()
		}
	case *ua.LocalizedText:
		if v == nil {
			return nullVariant()
		}
	}
	return ua.MustVariant(value)
}

func nullVariant() *ua.Variant {
	return &ua.Variant{}
}
