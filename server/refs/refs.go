package refs

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/attrs"
	"github.com/gopcua/opcua/ua"
)

var (
	OrganizesRefTypeID  *ua.NodeID = ua.NewNumericNodeID(0, id.Organizes)
	HasSubtypeRefTypeID *ua.NodeID = ua.NewNumericNodeID(0, id.HasSubtype)
)

// NewHasSubtypeRefDesc returns a NewHasSubtypeRefDesc reference.
func NewHasSubtypeRefDesc(typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: HasSubtypeRefTypeID,
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}

func NewOrganizesRefDesc(nid *ua.NodeID, browseName, displayName string, typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: OrganizesRefTypeID,
		NodeID:          &ua.ExpandedNodeID{NodeID: nid},
		BrowseName:      attrs.BrowseName(browseName),
		DisplayName:     attrs.DisplayName(displayName, ""),
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}
