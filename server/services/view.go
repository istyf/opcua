package services

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

type ViewServiceBackend interface {
	HandlerRegistrator
	NamespaceProvider
	NodeProvider
	Config() types.ServerConfig
}

// ViewService implements the View Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type ViewService struct {
	backend               ViewServiceBackend
	maxBrowseOperations   uint32
	maxContinuationPoints uint32

	continuationMu     sync.Mutex
	continuationPoints map[string]browseContinuation
	nextContinuationID atomic.Uint64
}

type browseContinuation struct {
	references []*ua.ReferenceDescription
	pageSize   uint32
}

func NewViewService(b ViewServiceBackend) *ViewService {
	vs := &ViewService{
		backend:               b,
		maxBrowseOperations:   b.Config().MaxBrowseOperationsPerCall(),
		maxContinuationPoints: b.Config().MaxBrowseContinuationPoints(),
		continuationPoints:    make(map[string]browseContinuation),
	}

	b.RegisterHandler(id.BrowseRequest_Encoding_DefaultBinary, vs.Browse)
	b.RegisterHandler(id.BrowseNextRequest_Encoding_DefaultBinary, vs.BrowseNext)
	b.RegisterHandler(id.TranslateBrowsePathsToNodeIDsRequest_Encoding_DefaultBinary, vs.TranslateBrowsePathsToNodeIDs)
	b.RegisterHandler(id.RegisterNodesRequest_Encoding_DefaultBinary, vs.RegisterNodes)
	b.RegisterHandler(id.UnregisterNodesRequest_Encoding_DefaultBinary, vs.UnregisterNodes)

	return vs
}

var newViewServiceLogAttribute = newServiceLogAttributeCreatorForSet("view")

func isEmptyViewDescription(view *ua.ViewDescription) bool {
	if view == nil {
		return true
	}
	if view.ViewID != nil && !view.ViewID.Equal(noNodeID) {
		return false
	}
	return view.Timestamp.IsZero() && view.ViewVersion == 0
}

func validateBrowseView(view *ua.ViewDescription) error {
	if isEmptyViewDescription(view) {
		return nil
	}
	if view == nil {
		return nil
	}
	if view.ViewID == nil || view.ViewID.Equal(noNodeID) {
		return ua.StatusBadViewParameterMismatch
	}
	if !view.Timestamp.IsZero() {
		return ua.StatusBadViewTimestampInvalid
	}
	if view.ViewVersion != 0 {
		return ua.StatusBadViewVersionInvalid
	}
	return ua.StatusBadViewIDUnknown
}

func isValidBrowseDirection(direction ua.BrowseDirection) bool {
	switch direction {
	case ua.BrowseDirectionForward, ua.BrowseDirectionInverse, ua.BrowseDirectionBoth:
		return true
	default:
		return false
	}
}

func isAllReferences(referenceTypeID *ua.NodeID) bool {
	return referenceTypeID == nil || referenceTypeID.Equal(noNodeID)
}

func newBrowseResponse(requestHandle uint32, resultCount int) *ua.BrowseResponse {
	return &ua.BrowseResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      requestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         make([]*ua.BrowseResult, resultCount),
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

func newBrowseNextResponse(requestHandle uint32, resultCount int) *ua.BrowseNextResponse {
	return &ua.BrowseNextResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      requestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         make([]*ua.BrowseResult, resultCount),
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

func (s *ViewService) newContinuationPoint() []byte {
	id := s.nextContinuationID.Add(1)
	return []byte(strconv.FormatUint(id, 10))
}

func (s *ViewService) storeBrowseContinuation(references []*ua.ReferenceDescription, pageSize uint32) ([]byte, bool) {
	if len(references) == 0 {
		return nil, true
	}
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()

	if s.maxContinuationPoints > 0 && uint32(len(s.continuationPoints)) >= s.maxContinuationPoints {
		return nil, false
	}

	token := s.newContinuationPoint()
	s.continuationPoints[string(token)] = browseContinuation{
		references: references,
		pageSize:   pageSize,
	}
	return token, true
}

func (s *ViewService) takeBrowseContinuation(token []byte) (browseContinuation, bool) {
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()

	key := string(token)
	cont, ok := s.continuationPoints[key]
	if ok {
		delete(s.continuationPoints, key)
	}
	return cont, ok
}

func (s *ViewService) releaseBrowseContinuation(token []byte) {
	s.continuationMu.Lock()
	delete(s.continuationPoints, string(token))
	s.continuationMu.Unlock()
}

func (s *ViewService) applyBrowseReferenceLimit(result *ua.BrowseResult, requestedMax uint32) *ua.BrowseResult {
	if result == nil || result.StatusCode != ua.StatusOK || requestedMax == 0 || len(result.References) <= int(requestedMax) {
		return result
	}

	limited := &ua.BrowseResult{
		StatusCode: result.StatusCode,
		References: append([]*ua.ReferenceDescription(nil), result.References[:requestedMax]...),
	}
	token, ok := s.storeBrowseContinuation(
		append([]*ua.ReferenceDescription(nil), result.References[requestedMax:]...),
		requestedMax,
	)
	if !ok {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNoContinuationPoints}
	}
	limited.ContinuationPoint = token
	return limited
}

func (s *ViewService) resumeBrowseContinuation(token []byte) *ua.BrowseResult {
	cont, ok := s.takeBrowseContinuation(token)
	if !ok {
		return &ua.BrowseResult{StatusCode: ua.StatusBadContinuationPointInvalid}
	}

	result := &ua.BrowseResult{StatusCode: ua.StatusOK}
	if cont.pageSize == 0 || len(cont.references) <= int(cont.pageSize) {
		result.References = cont.references
		return result
	}

	result.References = append([]*ua.ReferenceDescription(nil), cont.references[:cont.pageSize]...)
	nextToken, ok := s.storeBrowseContinuation(
		append([]*ua.ReferenceDescription(nil), cont.references[cont.pageSize:]...),
		cont.pageSize,
	)
	if !ok {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNoContinuationPoints}
	}
	result.ContinuationPoint = nextToken
	return result
}

func (s *ViewService) browseNode(ctx context.Context, desc *ua.BrowseDescription) *ua.BrowseResult {
	if desc == nil || desc.NodeID == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDInvalid}
	}
	if !isValidBrowseDirection(desc.BrowseDirection) {
		return &ua.BrowseResult{StatusCode: ua.StatusBadBrowseDirectionInvalid}
	}
	if !isAllReferences(desc.ReferenceTypeID) {
		refType := s.backend.Node(desc.ReferenceTypeID)
		if refType == nil || refType.NodeClass() != ua.NodeClassReferenceType {
			return &ua.BrowseResult{StatusCode: ua.StatusBadReferenceTypeIDInvalid}
		}
	}

	ns, err := s.backend.Namespace(int(desc.NodeID.Namespace()))
	if err != nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}
	if ns.Node(desc.NodeID) == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	result := ns.Browse(ctx, desc)
	if result == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadInternalError}
	}

	return result
}

// Browse returns one BrowseResult per BrowseDescription in request order and
// leaves service-level validation to explicit follow-up checks as spec support
// is expanded.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.2
func (s *ViewService) Browse(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	ctx = ualog.WithAttrs(ctx, newViewServiceLogAttribute("browse"))
	logServiceRequest(ctx, r)

	req, err := safeReq[*ua.BrowseRequest](r)
	if err != nil {
		return nil, err
	}
	if len(req.NodesToBrowse) == 0 {
		return nil, ua.StatusBadNothingToDo
	}
	if s.maxBrowseOperations > 0 && uint32(len(req.NodesToBrowse)) > s.maxBrowseOperations {
		return nil, ua.StatusBadTooManyOperations
	}
	if err := validateBrowseView(req.View); err != nil {
		return nil, err
	}

	resp := newBrowseResponse(req.RequestHeader.RequestHandle, len(req.NodesToBrowse))

	for i := range req.NodesToBrowse {
		br := req.NodesToBrowse[i]
		ualog.Debug(ctx, "browsing node",
			ualog.Any(ualog.NodeIdKey, br.NodeID),
			ualog.Any("dir", br.BrowseDirection),
			ualog.Any("subtypes", br.IncludeSubtypes),
			ualog.String("ref", fmt.Sprint(br.ReferenceTypeID)),
		)

		resp.Results[i] = s.applyBrowseReferenceLimit(s.browseNode(ctx, br), req.RequestedMaxReferencesPerNode)
	}

	return resp, nil
}

func SuitableReference(_ context.Context, srv types.Server, desc *ua.BrowseDescription, ref types.ReferenceWrapper) bool {
	if !suitableDirection(desc.BrowseDirection, ref.IsForward()) {
		return false
	}
	if !suitableRefType(srv, desc.ReferenceTypeID, ref.ReferenceType(), desc.IncludeSubtypes) {
		return false
	}
	if desc.NodeClassMask > 0 && desc.NodeClassMask&uint32(ref.NodeClass()) == 0 {
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

func suitableRefType(srv types.Server, ref1, ref2 *ua.NodeID, subtypes bool) bool {
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

func getSubRefs(srv types.Server, nid *ua.NodeID) []*ua.NodeID {
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

	for ref := range node.References().Find(func(r types.ReferenceWrapper) bool {
		return r.IsReferenceType(id.HasSubtype) && r.IsForward()
	}) {
		refs = append(refs, ref.TargetNodeID().NodeID)
		refs = append(refs, getSubRefs(srv, ref.TargetNodeID().NodeID)...)
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
	if len(req.ContinuationPoints) == 0 {
		return nil, ua.StatusBadNothingToDo
	}
	if s.maxBrowseOperations > 0 && uint32(len(req.ContinuationPoints)) > s.maxBrowseOperations {
		return nil, ua.StatusBadTooManyOperations
	}
	if req.ReleaseContinuationPoints {
		for _, token := range req.ContinuationPoints {
			s.releaseBrowseContinuation(token)
		}
		return newBrowseNextResponse(req.RequestHeader.RequestHandle, 0), nil
	}

	resp := newBrowseNextResponse(req.RequestHeader.RequestHandle, len(req.ContinuationPoints))
	for i, token := range req.ContinuationPoints {
		resp.Results[i] = s.resumeBrowseContinuation(token)
	}
	return resp, nil
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

	findTarget := func(n types.Node, pathElements []*ua.RelativePathElement) (*ua.BrowsePathResult, error) {
		for _, elem := range pathElements {
			var e *ua.RelativePathElement = elem
			for ref := range n.References().Find(func(r types.ReferenceWrapper) bool {
				if r.ReferenceType().Equal(e.ReferenceTypeID) && r.IsForward() == !e.IsInverse {
					referenceTarget := s.backend.Node(r.TargetNodeID().NodeID)
					if strings.Compare(referenceTarget.BrowseName().Name, e.TargetName.Name) == 0 {
						return true
					}
				}

				return false
			}) {
				return &ua.BrowsePathResult{
					StatusCode: ua.StatusOK,
					Targets: []*ua.BrowsePathTarget{
						{TargetID: ref.TargetNodeID(), RemainingPathIndex: math.MaxUint32},
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
		if n := s.backend.Node(path.StartingNode); n != nil && path.RelativePath != nil {
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
