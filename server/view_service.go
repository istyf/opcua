package server

import (
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uasc"
)

var (
	hasSubtype = ua.NewNumericNodeID(0, id.HasSubtype)
)

// ViewService implements the View Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type ViewService struct {
	srv *Server
}

func NewViewService(s *Server) *ViewService {
	return &ViewService{
		srv: s,
	}
}

var newViewServiceLogAttribute = newServiceLogAttributeCreatorForSet("view")

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.2
func (s *ViewService) Browse(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("browse"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.BrowseRequest](r)
	if err != nil {
		return nil, err
	}

	resp := &ua.BrowseResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results: make([]*ua.BrowseResult, len(req.NodesToBrowse)),

		DiagnosticInfos: []*ua.DiagnosticInfo{{}},
	}

	for i := range req.NodesToBrowse {
		br := req.NodesToBrowse[i]
		ualog.Debug(ctx, "browsing node",
			ualog.Any(ualog.NodeIdKey, br.NodeID),
			ualog.Any("dir", br.BrowseDirection),
			ualog.Any("subtypes", br.IncludeSubtypes),
			ualog.String("ref", br.ReferenceTypeID.String()),
		)

		ns, err := s.srv.Namespace(int(br.NodeID.Namespace()))
		if err != nil {
			resp.Results[i] = &ua.BrowseResult{StatusCode: ua.StatusBad}
			continue
		}

		resp.Results[i] = ns.Browse(ctx, br)
	}

	return resp, nil
}

func suitableRef(_ context.Context, srv *Server, desc *ua.BrowseDescription, ref *ua.ReferenceDescription) bool {
	if !suitableDirection(desc.BrowseDirection, ref.IsForward) {
		return false
	}
	if !suitableRefType(srv, desc.ReferenceTypeID, ref.ReferenceTypeID, desc.IncludeSubtypes) {
		return false
	}
	if desc.NodeClassMask > 0 && desc.NodeClassMask&uint32(ref.NodeClass) == 0 {
		return false
	}
	return true
}

func suitableDirection(bd ua.BrowseDirection, isForward bool) bool {
	switch {
	case bd == ua.BrowseDirectionBoth:
		return true
	case bd == ua.BrowseDirectionForward && isForward:
		return true
	case bd == ua.BrowseDirectionInverse && !isForward:
		return true
	default:
		return false
	}
}

var noNodeID = ua.NewNumericNodeID(0, 0)

func suitableRefType(srv *Server, ref1, ref2 *ua.NodeID, subtypes bool) bool {
	if ref1.Equal(noNodeID) {
		// refType is not specified in browse description. Return all types
		return true
	}
	if ref1.Equal(ref2) {
		return true
	}
	hasRef2Fn := func(nid *ua.NodeID) bool { return nid.Equal(ref2) }
	hasSubtypeFn := func(nid *ua.NodeID) bool { return nid.Equal(hasSubtype) }
	oktypes := getSubRefs(srv, ref1)
	if !subtypes && slices.ContainsFunc(oktypes, hasSubtypeFn) {
		for n := slices.IndexFunc(oktypes, hasSubtypeFn); n > 0; {
			oktypes = slices.Delete(oktypes, n, n+1)
		}
	}
	return slices.ContainsFunc(oktypes, hasRef2Fn)
}

func getSubRefs(srv *Server, nid *ua.NodeID) []*ua.NodeID {
	ns, err := srv.Namespace(int(nid.Namespace()))
	if err != nil {
		// TODO: return error
		return nil
	}
	node := ns.Node(nid)
	if node == nil {
		return nil
	}

	refs := make([]*ua.NodeID, 0, node.References().Count())

	for ref := range node.References().Find(func(r *ua.ReferenceDescription) bool {
		return r.ReferenceTypeID.Equal(hasSubtype) && r.IsForward && r.NodeID != nil
	}) {
		refs = append(refs, ref.NodeID.NodeID)
		refs = append(refs, getSubRefs(srv, ref.NodeID.NodeID)...)
	}
	return refs
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *ViewService) BrowseNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("browse next"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.BrowseNextRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *ViewService) TranslateBrowsePathsToNodeIDs(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("translate browse paths to node ids"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.TranslateBrowsePathsToNodeIDsRequest](r)
	if err != nil {
		return nil, err
	}

	resp := &ua.TranslateBrowsePathsToNodeIDsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results: make([]*ua.BrowsePathResult, len(req.BrowsePaths)),

		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	findTarget := func(n types.INode, pathElements []*ua.RelativePathElement) (*ua.BrowsePathResult, error) {
		for _, elem := range pathElements {
			var e *ua.RelativePathElement = elem
			for ref := range n.References().Find(func(r *ua.ReferenceDescription) bool {
				if r.ReferenceTypeID.Equal(e.ReferenceTypeID) && r.IsForward == !e.IsInverse {
					referenceTarget := s.srv.Node(r.NodeID.NodeID)
					if strings.Compare(referenceTarget.DisplayName().Text, e.TargetName.Name) == 0 {
						return true
					}
				}

				return false
			}) {
				return &ua.BrowsePathResult{
					StatusCode: ua.StatusOK,
					Targets: []*ua.BrowsePathTarget{
						{TargetID: ref.NodeID, RemainingPathIndex: math.MaxUint32},
					},
				}, nil
			}
		}

		return &ua.BrowsePathResult{
			StatusCode: ua.StatusBadNoMatch,
			Targets:    []*ua.BrowsePathTarget{},
		}, nil
	}

	for idx, path := range req.BrowsePaths {
		if n := s.srv.Node(path.StartingNode); n != nil && path.RelativePath != nil {
			if bpr, err := findTarget(n, path.RelativePath.Elements); err == nil {
				resp.Results[idx] = bpr
			}
		}
	}

	return resp, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.5
func (s *ViewService) RegisterNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("register nodes"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.RegisterNodesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.6
func (s *ViewService) UnregisterNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("unregister nodes"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.UnregisterNodesRequest](r)
	if err != nil {
		return nil, err
	}

	return serviceUnsupported(req.RequestHeader), nil
}
