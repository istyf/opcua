package ua

// Encode writes ReferenceDescription with explicit null/default values for
// omitted pointer fields so the on-wire structure remains decodable even when a
// BrowseResultMask trims optional data.
func (r *ReferenceDescription) Encode() ([]byte, error) {
	buf := NewBuffer(nil)

	referenceTypeID := r.ReferenceTypeID
	if referenceTypeID == nil {
		referenceTypeID = NewTwoByteNodeID(0)
	}
	nodeID := r.NodeID
	if nodeID == nil {
		nodeID = &ExpandedNodeID{}
	}
	browseName := r.BrowseName
	if browseName == nil {
		browseName = &QualifiedName{}
	}
	displayName := r.DisplayName
	if displayName == nil {
		displayName = &LocalizedText{}
	}
	typeDefinition := r.TypeDefinition
	if typeDefinition == nil {
		typeDefinition = &ExpandedNodeID{}
	}

	buf.WriteStruct(referenceTypeID)
	buf.WriteBool(r.IsForward)
	buf.WriteStruct(nodeID)
	buf.WriteStruct(browseName)
	buf.WriteStruct(displayName)
	buf.WriteUint32(uint32(r.NodeClass))
	buf.WriteStruct(typeDefinition)

	return buf.Bytes(), buf.Error()
}
