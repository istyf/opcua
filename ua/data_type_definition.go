package ua

// Encode writes StructureField with explicit null/default values for optional
// pointer fields so the on-wire structure remains decodable.
func (f *StructureField) Encode() ([]byte, error) {
	buf := NewBuffer(nil)

	description := f.Description
	if description == nil {
		description = &LocalizedText{}
	}
	dataType := f.DataType
	if dataType == nil {
		dataType = NewTwoByteNodeID(0)
	}

	buf.WriteString(f.Name)
	buf.WriteStruct(description)
	buf.WriteStruct(dataType)
	buf.WriteInt32(f.ValueRank)
	buf.WriteStruct(f.ArrayDimensions)
	buf.WriteUint32(f.MaxStringLength)
	buf.WriteBool(f.IsOptional)

	return buf.Bytes(), buf.Error()
}

// Encode writes StructureDefinition with explicit null/default values for
// optional pointer fields so the on-wire structure remains decodable.
func (d *StructureDefinition) Encode() ([]byte, error) {
	buf := NewBuffer(nil)

	defaultEncodingID := d.DefaultEncodingID
	if defaultEncodingID == nil {
		defaultEncodingID = NewTwoByteNodeID(0)
	}
	baseDataType := d.BaseDataType
	if baseDataType == nil {
		baseDataType = NewTwoByteNodeID(0)
	}

	buf.WriteStruct(defaultEncodingID)
	buf.WriteStruct(baseDataType)
	buf.WriteInt32(int32(d.StructureType))
	buf.WriteStruct(d.Fields)

	return buf.Bytes(), buf.Error()
}

// Encode writes EnumField with explicit null/default values for optional
// pointer fields so the on-wire structure remains decodable.
func (f *EnumField) Encode() ([]byte, error) {
	buf := NewBuffer(nil)

	displayName := f.DisplayName
	if displayName == nil {
		displayName = &LocalizedText{}
	}
	description := f.Description
	if description == nil {
		description = &LocalizedText{}
	}

	buf.WriteInt64(f.Value)
	buf.WriteStruct(displayName)
	buf.WriteStruct(description)
	buf.WriteString(f.Name)

	return buf.Bytes(), buf.Error()
}

// Encode writes EnumDefinition with explicit array encoding for its fields so
// nested enum metadata remains decodable.
func (d *EnumDefinition) Encode() ([]byte, error) {
	buf := NewBuffer(nil)
	buf.WriteStruct(d.Fields)
	return buf.Bytes(), buf.Error()
}
