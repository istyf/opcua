package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

func TestBrowseReturnsResultsInRequestOrder(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	firstNodeID := ua.NewNumericNodeID(1, 1001)
	secondNodeID := ua.NewNumericNodeID(2, 2002)

	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(firstNodeID) {
				return viewTestNode{id: firstNodeID}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{StatusCode: ua.StatusOK, References: []*ua.ReferenceDescription{
				{BrowseName: &ua.QualifiedName{Name: "first"}},
			}}
		},
	}
	backend.namespaces[2] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(secondNodeID) {
				return viewTestNode{id: secondNodeID}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{StatusCode: ua.StatusOK, References: []*ua.ReferenceDescription{
				{BrowseName: &ua.QualifiedName{Name: "second"}},
			}}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 41},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: firstNodeID},
			{NodeID: secondNodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp, ok := resp.(*ua.BrowseResponse)
	if !ok {
		t.Fatalf("expected BrowseResponse, got %T", resp)
	}
	if len(browseResp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(browseResp.Results))
	}
	if len(browseResp.DiagnosticInfos) != 0 {
		t.Fatalf("expected empty diagnostic infos, got %d entries", len(browseResp.DiagnosticInfos))
	}
	if got := browseResp.Results[0].References[0].BrowseName.Name; got != "first" {
		t.Fatalf("expected first result to stay first, got %q", got)
	}
	if got := browseResp.Results[1].References[0].BrowseName.Name; got != "second" {
		t.Fatalf("expected second result to stay second, got %q", got)
	}
}

func TestBrowseRequestedMaxReferencesPerNodeZeroReturnsAllReferences(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	nodeID := ua.NewNumericNodeID(1, 1001)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(nodeID) {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: "one"}},
					{BrowseName: &ua.QualifiedName{Name: "two"}},
					{BrowseName: &ua.QualifiedName{Name: "three"}},
				},
			}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader:                 &ua.RequestHeader{RequestHandle: 40},
		RequestedMaxReferencesPerNode: 0,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if len(browseResp.Results[0].References) != 3 {
		t.Fatalf("expected 3 references, got %d", len(browseResp.Results[0].References))
	}
	if len(browseResp.Results[0].ContinuationPoint) != 0 {
		t.Fatal("expected no continuation point when max references is zero")
	}
}

func TestBrowseTruncatesResultsAndReturnsContinuationPoint(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	nodeID := ua.NewNumericNodeID(1, 1001)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(nodeID) {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: "one"}},
					{BrowseName: &ua.QualifiedName{Name: "two"}},
					{BrowseName: &ua.QualifiedName{Name: "three"}},
				},
			}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader:                 &ua.RequestHeader{RequestHandle: 40},
		RequestedMaxReferencesPerNode: 2,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if len(browseResp.Results[0].References) != 2 {
		t.Fatalf("expected 2 references, got %d", len(browseResp.Results[0].References))
	}
	if got := browseResp.Results[0].References[0].BrowseName.Name; got != "one" {
		t.Fatalf("expected first returned reference to be one, got %q", got)
	}
	if len(browseResp.Results[0].ContinuationPoint) == 0 {
		t.Fatal("expected continuation point for truncated browse result")
	}
}

func TestBrowseNextReturnsNextReferenceBatch(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	nodeID := ua.NewNumericNodeID(1, 1001)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(nodeID) {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: "one"}},
					{BrowseName: &ua.QualifiedName{Name: "two"}},
					{BrowseName: &ua.QualifiedName{Name: "three"}},
				},
			}
		},
	}

	browseResp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader:                 &ua.RequestHeader{RequestHandle: 41},
		RequestedMaxReferencesPerNode: 2,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	firstBatch := browseResp.(*ua.BrowseResponse).Results[0]
	resp, err := service.BrowseNext(t.Context(), nil, &ua.BrowseNextRequest{
		RequestHeader:             &ua.RequestHeader{RequestHandle: 42},
		ContinuationPoints:        [][]byte{firstBatch.ContinuationPoint},
		ReleaseContinuationPoints: false,
	}, 2)
	if err != nil {
		t.Fatalf("browse next: %v", err)
	}

	nextResp := resp.(*ua.BrowseNextResponse)
	if len(nextResp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(nextResp.Results))
	}
	if len(nextResp.Results[0].References) != 1 {
		t.Fatalf("expected 1 remaining reference, got %d", len(nextResp.Results[0].References))
	}
	if got := nextResp.Results[0].References[0].BrowseName.Name; got != "three" {
		t.Fatalf("expected remaining reference to be three, got %q", got)
	}
	if len(nextResp.Results[0].ContinuationPoint) != 0 {
		t.Fatal("expected continuation point to be exhausted after final batch")
	}
}

func TestBrowseNextReleaseContinuationPointsReturnsEmptyResults(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	nodeID := ua.NewNumericNodeID(1, 1001)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(nodeID) {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: "one"}},
					{BrowseName: &ua.QualifiedName{Name: "two"}},
				},
			}
		},
	}

	browseResp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader:                 &ua.RequestHeader{RequestHandle: 43},
		RequestedMaxReferencesPerNode: 1,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	firstBatch := browseResp.(*ua.BrowseResponse).Results[0]
	resp, err := service.BrowseNext(t.Context(), nil, &ua.BrowseNextRequest{
		RequestHeader:             &ua.RequestHeader{RequestHandle: 44},
		ContinuationPoints:        [][]byte{firstBatch.ContinuationPoint},
		ReleaseContinuationPoints: true,
	}, 2)
	if err != nil {
		t.Fatalf("browse next release: %v", err)
	}

	nextResp := resp.(*ua.BrowseNextResponse)
	if len(nextResp.Results) != 0 {
		t.Fatalf("expected empty results when releasing continuation points, got %d", len(nextResp.Results))
	}
	if len(nextResp.DiagnosticInfos) != 0 {
		t.Fatalf("expected empty diagnostics when releasing continuation points, got %d", len(nextResp.DiagnosticInfos))
	}
}

func TestBrowseNextReturnsBadContinuationPointInvalid(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	resp, err := service.BrowseNext(t.Context(), nil, &ua.BrowseNextRequest{
		RequestHeader:             &ua.RequestHeader{RequestHandle: 45},
		ContinuationPoints:        [][]byte{[]byte("missing")},
		ReleaseContinuationPoints: false,
	}, 1)
	if err != nil {
		t.Fatalf("browse next: %v", err)
	}

	nextResp := resp.(*ua.BrowseNextResponse)
	if got := nextResp.Results[0].StatusCode; got != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("expected %s, got %s", ua.StatusBadContinuationPointInvalid, got)
	}
}

func TestBrowseReturnsBadNoContinuationPointsWhenCapacityIsExhausted(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend(viewTestConfig{
		maxBrowseContinuationPoints: 1,
	})
	service := NewViewService(backend)
	firstNodeID := ua.NewNumericNodeID(1, 1001)
	secondNodeID := ua.NewNumericNodeID(1, 1002)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			switch {
			case id.Equal(firstNodeID), id.Equal(secondNodeID):
				return viewTestNode{id: id}
			default:
				return nil
			}
		},
		browseFn: func(_ context.Context, desc *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: desc.NodeID.String() + "-one"}},
					{BrowseName: &ua.QualifiedName{Name: desc.NodeID.String() + "-two"}},
				},
			}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader:                 &ua.RequestHeader{RequestHandle: 46},
		RequestedMaxReferencesPerNode: 1,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: firstNodeID},
			{NodeID: secondNodeID},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusOK {
		t.Fatalf("expected first result to succeed, got %s", got)
	}
	if len(browseResp.Results[0].ContinuationPoint) == 0 {
		t.Fatal("expected first result to allocate continuation point")
	}
	if got := browseResp.Results[1].StatusCode; got != ua.StatusBadNoContinuationPoints {
		t.Fatalf("expected %s, got %s", ua.StatusBadNoContinuationPoints, got)
	}
}

func TestBrowseReturnsBadNodeIDInvalidForNilNodeID(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 42},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nil},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadNodeIDInvalid {
		t.Fatalf("expected %s, got %s", ua.StatusBadNodeIDInvalid, got)
	}
}

func TestBrowseReturnsBadNodeIDUnknownForMissingNamespace(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 43},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(9, 9009)},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadNodeIDUnknown {
		t.Fatalf("expected %s, got %s", ua.StatusBadNodeIDUnknown, got)
	}
}

func TestBrowseReturnsBadInternalErrorWhenNamespaceBrowseReturnsNil(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.IntID() == 1001 {
				return viewTestNode{id: id}
			}
			return nil
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 44},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadInternalError {
		t.Fatalf("expected %s, got %s", ua.StatusBadInternalError, got)
	}
}

func TestBrowseRejectsEmptyNodesToBrowse(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 45},
		NodesToBrowse: nil,
	}, 1)
	if err != ua.StatusBadNothingToDo {
		t.Fatalf("expected %s, got %v", ua.StatusBadNothingToDo, err)
	}
}

func TestBrowseRejectsTooManyOperations(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend(viewTestConfig{
		maxBrowseOperationsPerCall: 1,
	})
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 46},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
			{NodeID: ua.NewNumericNodeID(1, 1002)},
		},
	}, 1)
	if err != ua.StatusBadTooManyOperations {
		t.Fatalf("expected %s, got %v", ua.StatusBadTooManyOperations, err)
	}
}

func TestBrowseAcceptsEmptyViewDescription(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.IntID() == 1001 {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{StatusCode: ua.StatusOK}
		},
	}

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 47},
		View:          &ua.ViewDescription{ViewID: ua.NewNumericNodeID(0, 0)},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}
}

func TestBrowseAcceptsNilViewDescription(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.IntID() == 1001 {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{StatusCode: ua.StatusOK}
		},
	}

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 47},
		View:          nil,
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}
}

func TestBrowseRejectsUnsupportedViewID(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 48},
		View: &ua.ViewDescription{
			ViewID: ua.NewNumericNodeID(1, 5001),
		},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != ua.StatusBadViewIDUnknown {
		t.Fatalf("expected %s, got %v", ua.StatusBadViewIDUnknown, err)
	}
}

func TestBrowseRejectsViewParameterMismatch(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 49},
		View: &ua.ViewDescription{
			Timestamp: time.Unix(1, 0),
		},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != ua.StatusBadViewParameterMismatch {
		t.Fatalf("expected %s, got %v", ua.StatusBadViewParameterMismatch, err)
	}
}

func TestBrowseRejectsUnsupportedViewTimestamp(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 50},
		View: &ua.ViewDescription{
			ViewID:    ua.NewNumericNodeID(1, 5002),
			Timestamp: time.Unix(1, 0),
		},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != ua.StatusBadViewTimestampInvalid {
		t.Fatalf("expected %s, got %v", ua.StatusBadViewTimestampInvalid, err)
	}
}

func TestBrowseRejectsUnsupportedViewVersion(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 51},
		View: &ua.ViewDescription{
			ViewID:      ua.NewNumericNodeID(1, 5003),
			ViewVersion: 1,
		},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1001)},
		},
	}, 1)
	if err != ua.StatusBadViewVersionInvalid {
		t.Fatalf("expected %s, got %v", ua.StatusBadViewVersionInvalid, err)
	}
}

func TestBrowseReturnsBadNodeIDUnknownForMissingNodeInKnownNamespace(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(*ua.NodeID) types.Node { return nil },
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 52},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: ua.NewNumericNodeID(1, 1234)},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadNodeIDUnknown {
		t.Fatalf("expected %s, got %s", ua.StatusBadNodeIDUnknown, got)
	}
}

func TestBrowseReturnsBadBrowseDirectionInvalid(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 53},
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          ua.NewNumericNodeID(1, 1234),
				BrowseDirection: ua.BrowseDirectionInvalid,
			},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadBrowseDirectionInvalid {
		t.Fatalf("expected %s, got %s", ua.StatusBadBrowseDirectionInvalid, got)
	}
}

func TestBrowseReturnsBadReferenceTypeIDInvalid(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)
	backend.nodes[ua.NewNumericNodeID(0, 85).String()] = viewTestNode{
		id:        ua.NewNumericNodeID(0, 85),
		nodeClass: ua.NodeClassObject,
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 54},
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          ua.NewNumericNodeID(1, 1234),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, 85),
			},
		},
	}, 1)
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	browseResp := resp.(*ua.BrowseResponse)
	if got := browseResp.Results[0].StatusCode; got != ua.StatusBadReferenceTypeIDInvalid {
		t.Fatalf("expected %s, got %s", ua.StatusBadReferenceTypeIDInvalid, got)
	}
}

type viewTestBackend struct {
	handlers   map[int]Handler
	namespaces map[int]types.NameSpace
	nodes      map[string]types.Node
	cfg        viewTestConfig
}

func newViewTestBackend(options ...viewTestConfig) *viewTestBackend {
	cfg := viewTestConfig{}
	if len(options) > 0 {
		cfg = options[0]
	}
	return &viewTestBackend{
		handlers:   make(map[int]Handler),
		namespaces: make(map[int]types.NameSpace),
		nodes:      make(map[string]types.Node),
		cfg:        cfg,
	}
}

func (b *viewTestBackend) RegisterHandler(typeID int, h Handler) {
	b.handlers[typeID] = h
}

func (b *viewTestBackend) Namespace(id int) (types.NameSpace, error) {
	ns, ok := b.namespaces[id]
	if !ok {
		return nil, errors.New("namespace not found")
	}
	return ns, nil
}

func (b *viewTestBackend) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	return b.nodes[id.String()]
}

func (b *viewTestBackend) Config() types.ServerConfig {
	return b.cfg
}

type viewTestNamespace struct {
	nodeFn   func(*ua.NodeID) types.Node
	browseFn func(context.Context, *ua.BrowseDescription) *ua.BrowseResult
}

func (ns *viewTestNamespace) Name() string { return "test" }

func (ns *viewTestNamespace) AddNode(n types.Node) types.Node { return n }

func (ns *viewTestNamespace) Node(id *ua.NodeID) types.Node {
	if ns.nodeFn == nil {
		return nil
	}
	return ns.nodeFn(id)
}

func (ns *viewTestNamespace) Browse(ctx context.Context, req *ua.BrowseDescription) *ua.BrowseResult {
	if ns.browseFn == nil {
		return nil
	}
	return ns.browseFn(ctx, req)
}

func (ns *viewTestNamespace) ID() uint16 { return 0 }

func (ns *viewTestNamespace) SetID(uint16) {}

func (ns *viewTestNamespace) Attribute(context.Context, *ua.NodeID, ua.AttributeID) *ua.DataValue {
	return nil
}

func (ns *viewTestNamespace) SetAttribute(context.Context, *ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode {
	return ua.StatusOK
}

func (ns *viewTestNamespace) NewQualifiedName(name string) *ua.QualifiedName {
	return &ua.QualifiedName{Name: name}
}

func (ns *viewTestNamespace) NextAvailableID() *ua.NodeID { return ua.NewNumericNodeID(1, 1) }

type viewTestNode struct {
	id        *ua.NodeID
	nodeClass ua.NodeClass
}

func (n viewTestNode) ID() *ua.NodeID { return n.id }

func (n viewTestNode) BrowseName() *ua.QualifiedName { return &ua.QualifiedName{Name: n.id.String()} }

func (n viewTestNode) DisplayName(context.Context) *ua.LocalizedText {
	return ua.NewLocalizedText(n.id.String())
}

func (n viewTestNode) NodeClass() ua.NodeClass {
	if n.nodeClass == 0 {
		return ua.NodeClassObject
	}
	return n.nodeClass
}

func (n viewTestNode) AddComponent(types.Node) types.Node { return nil }

func (n viewTestNode) AddComponents(...types.Node) types.Node { return nil }

func (n viewTestNode) AddRef(types.ReferenceWrapper) {}

func (n viewTestNode) References() types.ReferenceCollection { return nil }

func (n viewTestNode) Attribute(context.Context, ua.AttributeID) (*types.AttrValue, error) {
	return nil, nil
}

func (n viewTestNode) SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error { return nil }

type viewTestConfig struct {
	maxBrowseOperationsPerCall  uint32
	maxBrowseContinuationPoints uint32
}

func (cfg viewTestConfig) Certificate() []byte { return nil }

func (cfg viewTestConfig) Endpoints() []string { return nil }

func (cfg viewTestConfig) PrivateKey() *rsa.PrivateKey { return nil }

func (cfg viewTestConfig) ApplicationURI() string { return "" }

func (cfg viewTestConfig) ManufacturerName() string { return "" }

func (cfg viewTestConfig) ProductName() string { return "" }

func (cfg viewTestConfig) SoftwareVersion() string { return "" }

func (cfg viewTestConfig) MaxNodesPerRead() uint32 { return 0 }

func (cfg viewTestConfig) MaxBrowseOperationsPerCall() uint32 {
	return cfg.maxBrowseOperationsPerCall
}

func (cfg viewTestConfig) MaxBrowseContinuationPoints() uint32 {
	return cfg.maxBrowseContinuationPoints
}

func (cfg viewTestConfig) MaxSubscriptions() uint32 { return 0 }

func (cfg viewTestConfig) MaxSubscriptionsPerSession() uint32 { return 0 }

func (cfg viewTestConfig) MaxSubscriptionOperationsPerCall() uint32 { return 0 }

func (cfg viewTestConfig) MinSubscriptionPublishingInterval() time.Duration { return 0 }

func (cfg viewTestConfig) MinSubscriptionMaxKeepAliveCount() uint32 { return 0 }

func (cfg viewTestConfig) MinSubscriptionLifetimeCount() uint32 { return 0 }

func (cfg viewTestConfig) MethodCallMiddleware() types.MethodMiddleware { return nil }
