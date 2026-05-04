package refs

import (
	"context"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

var (
	OrganizesRefTypeID         *ua.NodeID = ua.NewNumericNodeID(0, id.Organizes)
	HasComponentRefTypeID      *ua.NodeID = ua.NewNumericNodeID(0, id.HasComponent)
	HasPropertyRefTypeID       *ua.NodeID = ua.NewNumericNodeID(0, id.HasProperty)
	HasSubtypeRefTypeID        *ua.NodeID = ua.NewNumericNodeID(0, id.HasSubtype)
	HasTypeDefinitionRefTypeID *ua.NodeID = ua.NewNumericNodeID(0, id.HasTypeDefinition)
)

type Description interface {
	Copy(context.Context) *ua.ReferenceDescription
}

type desc struct {
	refType *ua.NodeID
	target  types.Node
	forward bool
}

func (d *desc) NodeClass() ua.NodeClass {
	return d.target.NodeClass()
}

// IsForward implements [types.ReferenceWrapper].
func (d *desc) IsForward() bool {
	return d.forward
}

// IsReferenceType implements [types.ReferenceWrapper].
func (d *desc) IsReferenceType(refTypeID uint32) bool {
	return d.refType.Namespace() == 0 && d.refType.IntID() == refTypeID
}

func (d *desc) ReferenceType() *ua.NodeID {
	return d.refType
}

func (d *desc) TargetNode() types.Node {
	return d.target
}

// TargetNodeID implements [types.ReferenceWrapper].
func (d *desc) TargetNodeID() *ua.ExpandedNodeID {
	return &ua.ExpandedNodeID{NodeID: d.target.ID()}
}

// Targets implements [types.ReferenceWrapper].
func (d *desc) TargetsNode(other types.Node) bool {
	return d.target.ID().Equal(other.ID())
}

func (d *desc) Copy(ctx context.Context) *ua.ReferenceDescription {

	rd := &ua.ReferenceDescription{
		ReferenceTypeID: d.refType,
		IsForward:       d.forward,
		NodeID:          &ua.ExpandedNodeID{NodeID: d.target.ID()},
		BrowseName:      d.target.BrowseName(),
		DisplayName:     d.target.DisplayName(ctx),
		NodeClass:       d.target.NodeClass(),
	}

	switch rd.NodeClass {
	case ua.NodeClassObject, ua.NodeClassVariable:
		if td, ok := d.target.(types.TypeNode); ok {
			rd.TypeDefinition = td.DataType()
		}
	default:
	}

	if rd.TypeDefinition == nil {
		rd.TypeDefinition = &ua.ExpandedNodeID{}
	}

	return rd
}

func NewReferenceDescription(targetNode types.Node, refTypeNodeID *ua.NodeID, isForward bool) types.ReferenceWrapper {

	d := &desc{
		refType: refTypeNodeID,
		target:  targetNode,
		forward: isForward,
	}

	return d
}

func LinkWithHasComponentReferenceDescriptions(fromNode, toNode types.Node) {
	fromNode.AddRef(NewReferenceDescription(toNode, HasComponentRefTypeID, true))
	toNode.AddRef(NewReferenceDescription(fromNode, HasComponentRefTypeID, false))
}

func LinkWithHasPropertyReferenceDescriptions(fromNode, toNode types.Node) {
	fromNode.AddRef(NewReferenceDescription(toNode, HasPropertyRefTypeID, true))
	toNode.AddRef(NewReferenceDescription(fromNode, HasPropertyRefTypeID, false))
}

func NewHasTypeDefinitionReferenceDescription(typeNode types.TypeNode) types.ReferenceWrapper {
	return NewReferenceDescription(typeNode, HasTypeDefinitionRefTypeID, true)
}

func LinkWithOrganizesReferenceDescriptions(organizer, organizedItem types.Node) {
	organizer.AddRef(NewReferenceDescription(organizedItem, OrganizesRefTypeID, true))
	organizedItem.AddRef(NewReferenceDescription(organizer, OrganizesRefTypeID, false))
}

func TypeID(typeID uint32) *ua.NodeID {
	switch typeID {
	case id.HasComponent:
		return HasComponentRefTypeID
	case id.HasProperty:
		return HasPropertyRefTypeID
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
