package refs

import (
	"context"

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

func Copy(_ context.Context, _ types.Node, r *ua.ReferenceDescription) *ua.ReferenceDescription {
	// TODO: Use the context to request the correct display name from the node
	refdesc := &ua.ReferenceDescription{
		ReferenceTypeID: r.ReferenceTypeID,
		IsForward:       r.IsForward,
		NodeID:          r.NodeID,
		BrowseName:      r.BrowseName,
		DisplayName:     r.DisplayName,
		NodeClass:       r.NodeClass,
		TypeDefinition:  r.TypeDefinition,
	}

	return refdesc
}

func NewReferenceDescription(targetNode types.Node, refTypeNodeID *ua.NodeID, isForward bool) *ua.ReferenceDescription {
	rd := &ua.ReferenceDescription{
		ReferenceTypeID: refTypeNodeID,
		NodeClass:       targetNode.NodeClass(),
		BrowseName:      targetNode.BrowseName(),
		DisplayName:     targetNode.DisplayName(),
		NodeID:          &ua.ExpandedNodeID{NodeID: targetNode.ID()},
		IsForward:       isForward,
	}

	switch rd.NodeClass {
	case ua.NodeClassObject, ua.NodeClassVariable:
		if td, ok := targetNode.(types.TypeNode); ok {
			rd.TypeDefinition = td.DataType()
		}
	default:
	}

	if rd.TypeDefinition == nil {
		rd.TypeDefinition = &ua.ExpandedNodeID{}
	}

	return rd
}

func AddHasComponentRefDescs(fromNode, toNode types.Node) {
	fromNode.AddRef(NewReferenceDescription(toNode, HasComponentRefTypeID, true))
	toNode.AddRef(NewReferenceDescription(fromNode, HasComponentRefTypeID, false))
}

func NewHasTypeDefinitionRefDesc(typeNode types.TypeNode) *ua.ReferenceDescription {
	return NewReferenceDescription(typeNode, HasTypeDefinitionRefTypeID, true)
}

func AddOrganizesRefDescs(organizer, organizedItem types.Node) {
	organizer.AddRef(NewReferenceDescription(organizedItem, OrganizesRefTypeID, true))
	organizedItem.AddRef(NewReferenceDescription(organizer, OrganizesRefTypeID, false))
}

func TypeID(typeID uint32) *ua.NodeID {
	switch typeID {
	case id.HasComponent:
		return HasComponentRefTypeID
	case id.HasSubtype:
		return HasSubtypeRefTypeID
	case id.HasTypeDefinition:
		return HasTypeDefinitionRefTypeID
	case id.Organizes:
		return OrganizesRefTypeID
	default:
		return ua.NewNumericNodeID(0, typeID)
	}
}
