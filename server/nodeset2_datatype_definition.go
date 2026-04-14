package server

import (
	"strconv"
	"strings"

	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/ua"
)

type importedDataTypeDefinitionKind uint8

const (
	importedDataTypeDefinitionStructure importedDataTypeDefinitionKind = iota + 1
	importedDataTypeDefinitionEnum
)

type dataTypeFieldResolver func(string) (*ua.NodeID, error)

type importedDataTypeClassification struct {
	kind          importedDataTypeDefinitionKind
	structureType ua.StructureType
}

func newImportedNodeIDResolver(aliases map[string]string, nsID *nsIDLookup) dataTypeFieldResolver {
	return func(nodeID string) (*ua.NodeID, error) {
		if aliases != nil {
			if aliasedID, ok := aliases[nodeID]; ok {
				nodeID = aliasedID
			}
		}

		nid, err := ua.ParseNodeID(nodeID)
		if err != nil {
			return nil, err
		}
		if nid == nil {
			return nil, errors.Errorf("invalid node id %q", nodeID)
		}

		if nsID != nil {
			if correctNS, ok := (*nsID)[nid.Namespace()]; ok {
				nid.SetNamespace(uint16(correctNS))
			}
		}

		return nid, nil
	}
}

func convertSchemaDataTypeDefinition(
	def *schema.DataTypeDefinition,
	classification importedDataTypeClassification,
	resolveFieldType dataTypeFieldResolver,
) (any, error) {
	if def == nil {
		return nil, nil
	}

	switch classification.kind {
	case importedDataTypeDefinitionStructure:
		return convertSchemaStructureDefinition(def, classification.structureType, nil, resolveFieldType)
	case importedDataTypeDefinitionEnum:
		return convertSchemaEnumDefinition(def), nil
	default:
		return nil, errors.Errorf("unsupported data type definition kind %d", classification.kind)
	}
}

func importSchemaDataTypeDefinition(dt *schema.UADataType, resolveFieldType dataTypeFieldResolver) (*ua.ExtensionObject, error) {
	if dt == nil || dt.Definition == nil {
		return nil, nil
	}

	classification, err := classifySchemaDataTypeDefinition(dt)
	if err != nil {
		return nil, err
	}

	var definition any
	switch classification.kind {
	case importedDataTypeDefinitionStructure:
		baseDataType, err := resolveSchemaStructureBaseDataType(dt, resolveFieldType)
		if err != nil {
			return nil, err
		}
		definition, err = convertSchemaStructureDefinition(dt.Definition, classification.structureType, baseDataType, resolveFieldType)
		if err != nil {
			return nil, err
		}
	case importedDataTypeDefinitionEnum:
		definition, err = convertSchemaDataTypeDefinition(dt.Definition, classification, resolveFieldType)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Errorf("unsupported data type definition kind %d", classification.kind)
	}

	return ua.NewExtensionObject(definition), nil
}

func classifySchemaDataTypeDefinition(dt *schema.UADataType) (importedDataTypeClassification, error) {
	if dt == nil || dt.Definition == nil {
		return importedDataTypeClassification{}, errors.New("missing data type definition")
	}

	def := dt.Definition
	superTypeID := schemaDataTypeSuperTypeID(dt)
	isUnion := def.IsUnionAttr || superTypeID == id.Union
	hasOptionalFields := false
	allowSubtypes := false
	for _, field := range def.Field {
		if field == nil {
			continue
		}
		hasOptionalFields = hasOptionalFields || field.IsOptionalAttr
		allowSubtypes = allowSubtypes || field.AllowSubTypesAttr
	}

	if def.IsOptionSetAttr || superTypeID == id.Enumeration {
		return importedDataTypeClassification{
			kind: importedDataTypeDefinitionEnum,
		}, nil
	}

	structureType := ua.StructureTypeStructure
	switch {
	case isUnion && allowSubtypes:
		structureType = ua.StructureTypeUnionWithSubtypedValues
	case isUnion:
		structureType = ua.StructureTypeUnion
	case allowSubtypes:
		structureType = ua.StructureTypeStructureWithSubtypedValues
	case hasOptionalFields:
		structureType = ua.StructureTypeStructureWithOptionalFields
	}

	return importedDataTypeClassification{
		kind:          importedDataTypeDefinitionStructure,
		structureType: structureType,
	}, nil
}

func schemaDataTypeSuperTypeNodeID(dt *schema.UADataType) *ua.NodeID {
	if dt == nil || dt.UAType == nil || dt.UANode == nil || dt.References == nil {
		return nil
	}

	for _, ref := range dt.References.Reference {
		if ref == nil {
			continue
		}
		if ref.ReferenceTypeAttr != "HasSubtype" && ref.ReferenceTypeAttr != "i=45" {
			continue
		}
		if ref.IsForwardAttr == nil || *ref.IsForwardAttr {
			continue
		}

		superTypeID, err := ua.ParseNodeID(ref.Value)
		if err != nil || superTypeID == nil {
			return nil
		}
		return superTypeID
	}

	return nil
}

func schemaDataTypeSuperTypeID(dt *schema.UADataType) uint32 {
	superTypeID := schemaDataTypeSuperTypeNodeID(dt)
	if superTypeID == nil {
		return 0
	}
	return superTypeID.IntID()
}

func resolveSchemaStructureBaseDataType(dt *schema.UADataType, resolveFieldType dataTypeFieldResolver) (*ua.NodeID, error) {
	if dt == nil || dt.Definition == nil {
		return nil, errors.New("missing data type definition")
	}
	if resolveFieldType == nil {
		return nil, errors.New("missing structure field type resolver")
	}

	if dt.Definition.BaseTypeAttr != "" {
		return resolveFieldType(dt.Definition.BaseTypeAttr)
	}

	superTypeID := schemaDataTypeSuperTypeNodeID(dt)
	if superTypeID == nil {
		return nil, nil
	}

	return resolveFieldType(superTypeID.String())
}

func convertSchemaStructureDefinition(def *schema.DataTypeDefinition, structureType ua.StructureType, baseDataType *ua.NodeID, resolveFieldType dataTypeFieldResolver) (*ua.StructureDefinition, error) {
	fields := make([]*ua.StructureField, 0, len(def.Field))
	for _, field := range def.Field {
		converted, err := convertSchemaStructureField(field, resolveFieldType)
		if err != nil {
			return nil, err
		}
		fields = append(fields, converted)
	}

	return &ua.StructureDefinition{
		BaseDataType:  baseDataType,
		StructureType: structureType,
		Fields:        fields,
	}, nil
}

func convertSchemaStructureField(field *schema.DataTypeField, resolveFieldType dataTypeFieldResolver) (*ua.StructureField, error) {
	if field == nil {
		return nil, nil
	}

	var dataType *ua.NodeID
	if field.DataTypeAttr != "" {
		if resolveFieldType == nil {
			return nil, errors.New("missing structure field type resolver")
		}

		var err error
		dataType, err = resolveFieldType(field.DataTypeAttr)
		if err != nil {
			return nil, err
		}
	}

	arrayDimensions, err := parseSchemaArrayDimensions(field.ArrayDimensionsAttr)
	if err != nil {
		return nil, err
	}

	return &ua.StructureField{
		Name:            field.NameAttr,
		Description:     firstNonEmptyLocalizedTextFromSchema(field.Description, field.DisplayName),
		DataType:        dataType,
		ValueRank:       int32(field.ValueRankAttr),
		ArrayDimensions: arrayDimensions,
		MaxStringLength: field.MaxStringLengthAttr,
		IsOptional:      field.IsOptionalAttr,
	}, nil
}

func convertSchemaEnumDefinition(def *schema.DataTypeDefinition) *ua.EnumDefinition {
	fields := make([]*ua.EnumField, 0, len(def.Field))
	for _, field := range def.Field {
		fields = append(fields, convertSchemaEnumField(field))
	}

	return &ua.EnumDefinition{
		Fields: fields,
	}
}

func convertSchemaEnumField(field *schema.DataTypeField) *ua.EnumField {
	if field == nil {
		return nil
	}

	return &ua.EnumField{
		Value:       int64(field.ValueAttr),
		DisplayName: firstLocalizedTextFromSchema(field.DisplayName),
		Description: firstNonEmptyLocalizedTextFromSchema(field.Description, field.DisplayName),
		Name:        field.NameAttr,
	}
}

func firstLocalizedTextFromSchema(texts []*schema.LocalizedText) *ua.LocalizedText {
	if len(texts) == 0 {
		return nil
	}

	return ua.NewLocalizedTextWithLocale(texts[0].Value, texts[0].LocaleAttr)
}

func firstNonEmptyLocalizedTextFromSchema(primary, fallback []*schema.LocalizedText) *ua.LocalizedText {
	if text := firstLocalizedTextFromSchema(primary); text != nil {
		return text
	}
	return firstLocalizedTextFromSchema(fallback)
}

func parseSchemaArrayDimensions(attr string) ([]uint32, error) {
	if attr == "" {
		return nil, nil
	}

	parts := strings.Split(attr, ",")
	dimensions := make([]uint32, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		dimension, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, errors.Errorf("invalid array dimension %q", part)
		}
		dimensions = append(dimensions, uint32(dimension))
	}

	return dimensions, nil
}
