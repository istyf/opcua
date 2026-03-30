package refs

import (
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

type Type uint32

var (
	OrganizesRefTypeID         *ua.NodeID = ua.NewNumericNodeID(0, id.Organizes)
	HasComponentRefTypeID      *ua.NodeID = ua.NewNumericNodeID(0, id.HasComponent)
	HasSubtypeRefTypeID        *ua.NodeID = ua.NewNumericNodeID(0, id.HasSubtype)
	HasTypeDefinitionRefTypeID *ua.NodeID = ua.NewNumericNodeID(0, id.HasTypeDefinition)
)

func NewReferenceDescription(toNode types.Node, refType Type, isForward bool) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, uint32(refType)),
		NodeID:          &ua.ExpandedNodeID{NodeID: toNode.ID()},
		IsForward:       isForward,
	}
}

func NewHasComponentRefDesc(o types.Node) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: HasComponentRefTypeID,
		NodeID:          &ua.ExpandedNodeID{NodeID: o.ID()},
		IsForward:       true,
	}
}

func NewHasSubtypeRefDesc(typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: HasSubtypeRefTypeID,
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}

func NewHasTypeDefinitionRefDesc(typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: HasTypeDefinitionRefTypeID,
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}

func NewOrganizesRefDesc(o types.Node) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: OrganizesRefTypeID,
		NodeID:          &ua.ExpandedNodeID{NodeID: o.ID()},
		BrowseName:      o.BrowseName(),
		DisplayName:     o.DisplayName(),
		TypeDefinition:  o.DataType(),
		IsForward:       true,
	}
}
