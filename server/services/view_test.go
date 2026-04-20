package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"iter"
	"slices"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			{NodeID: firstNodeID, ResultMask: uint32(ua.BrowseResultMaskBrowseName)},
			{NodeID: secondNodeID, ResultMask: uint32(ua.BrowseResultMaskBrowseName)},
		},
	}, 1)
	require.NoError(t, err)

	browseResp, ok := resp.(*ua.BrowseResponse)
	require.True(t, ok, "expected BrowseResponse, got %T", resp)
	require.Len(t, browseResp.Results, 2)
	assert.Empty(t, browseResp.DiagnosticInfos)
	assert.Equal(t, "first", browseResp.Results[0].References[0].BrowseName.Name)
	assert.Equal(t, "second", browseResp.Results[1].References[0].BrowseName.Name)
}

func TestBrowsePreservesRequestOrderForMixedSuccessAndFailure(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	validNodeID := ua.NewNumericNodeID(1, 1001)
	backend.namespaces[1] = &viewTestNamespace{
		nodeFn: func(id *ua.NodeID) types.Node {
			if id.Equal(validNodeID) {
				return viewTestNode{id: id}
			}
			return nil
		},
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{
				StatusCode: ua.StatusOK,
				References: []*ua.ReferenceDescription{
					{BrowseName: &ua.QualifiedName{Name: "valid"}},
				},
			}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 56},
		NodesToBrowse: []*ua.BrowseDescription{
			{NodeID: nil},
			{NodeID: ua.NewNumericNodeID(9, 9009)},
			{
				NodeID:          validNodeID,
				BrowseDirection: ua.BrowseDirectionForward,
				ResultMask:      uint32(ua.BrowseResultMaskBrowseName),
			},
			{
				NodeID:          validNodeID,
				BrowseDirection: ua.BrowseDirectionInvalid,
			},
		},
	}, 1)
	require.NoError(t, err)

	browseResp, ok := resp.(*ua.BrowseResponse)
	require.True(t, ok, "expected BrowseResponse, got %T", resp)
	require.Len(t, browseResp.Results, 4)
	assert.Empty(t, browseResp.DiagnosticInfos)
	assert.Equal(t, ua.StatusBadNodeIDInvalid, browseResp.Results[0].StatusCode)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, browseResp.Results[1].StatusCode)
	assert.Equal(t, ua.StatusOK, browseResp.Results[2].StatusCode)
	assert.Equal(t, "valid", browseResp.Results[2].References[0].BrowseName.Name)
	assert.Equal(t, ua.StatusBadBrowseDirectionInvalid, browseResp.Results[3].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Len(t, browseResp.Results[0].References, 3)
	assert.Empty(t, browseResp.Results[0].ContinuationPoint)
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
			{NodeID: nodeID, ResultMask: uint32(ua.BrowseResultMaskBrowseName)},
		},
	}, 1)
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Len(t, browseResp.Results[0].References, 2)
	assert.Equal(t, "one", browseResp.Results[0].References[0].BrowseName.Name)
	assert.NotEmpty(t, browseResp.Results[0].ContinuationPoint)
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
			{NodeID: nodeID, ResultMask: uint32(ua.BrowseResultMaskBrowseName)},
		},
	}, 1)
	require.NoError(t, err)

	firstBatch := browseResp.(*ua.BrowseResponse).Results[0]
	resp, err := service.BrowseNext(t.Context(), nil, &ua.BrowseNextRequest{
		RequestHeader:             &ua.RequestHeader{RequestHandle: 42},
		ContinuationPoints:        [][]byte{firstBatch.ContinuationPoint},
		ReleaseContinuationPoints: false,
	}, 2)
	require.NoError(t, err)

	nextResp := resp.(*ua.BrowseNextResponse)
	assert.Len(t, nextResp.Results, 1)
	assert.Len(t, nextResp.Results[0].References, 1)
	assert.Equal(t, "three", nextResp.Results[0].References[0].BrowseName.Name)
	assert.Empty(t, nextResp.Results[0].ContinuationPoint)
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
	require.NoError(t, err)

	firstBatch := browseResp.(*ua.BrowseResponse).Results[0]
	resp, err := service.BrowseNext(t.Context(), nil, &ua.BrowseNextRequest{
		RequestHeader:             &ua.RequestHeader{RequestHandle: 44},
		ContinuationPoints:        [][]byte{firstBatch.ContinuationPoint},
		ReleaseContinuationPoints: true,
	}, 2)
	require.NoError(t, err)

	nextResp := resp.(*ua.BrowseNextResponse)
	assert.Empty(t, nextResp.Results)
	assert.Empty(t, nextResp.DiagnosticInfos)
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
	require.NoError(t, err)

	nextResp := resp.(*ua.BrowseNextResponse)
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, nextResp.Results[0].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusOK, browseResp.Results[0].StatusCode)
	assert.NotEmpty(t, browseResp.Results[0].ContinuationPoint)
	assert.Equal(t, ua.StatusBadNoContinuationPoints, browseResp.Results[1].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadNodeIDInvalid, browseResp.Results[0].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, browseResp.Results[0].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadInternalError, browseResp.Results[0].StatusCode)
}

func TestBrowseRejectsEmptyNodesToBrowse(t *testing.T) {
	t.Parallel()

	backend := newViewTestBackend()
	service := NewViewService(backend)

	_, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 45},
		NodesToBrowse: nil,
	}, 1)
	assert.Equal(t, ua.StatusBadNothingToDo, err)
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
	assert.Equal(t, ua.StatusBadTooManyOperations, err)
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
	assert.NoError(t, err)
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
	assert.NoError(t, err)
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
	assert.Equal(t, ua.StatusBadViewIDUnknown, err)
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
	assert.Equal(t, ua.StatusBadViewParameterMismatch, err)
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
	assert.Equal(t, ua.StatusBadViewTimestampInvalid, err)
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
	assert.Equal(t, ua.StatusBadViewVersionInvalid, err)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, browseResp.Results[0].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadBrowseDirectionInvalid, browseResp.Results[0].StatusCode)
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
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	assert.Equal(t, ua.StatusBadReferenceTypeIDInvalid, browseResp.Results[0].StatusCode)
}

func TestSuitableDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		direction   ua.BrowseDirection
		isForward   bool
		isSymmetric bool
		want        bool
	}{
		{name: "forward matches forward reference", direction: ua.BrowseDirectionForward, isForward: true, want: true},
		{name: "forward rejects inverse reference", direction: ua.BrowseDirectionForward, isForward: false, want: false},
		{name: "inverse matches inverse non symmetric reference", direction: ua.BrowseDirectionInverse, isForward: false, want: true},
		{name: "inverse rejects forward reference", direction: ua.BrowseDirectionInverse, isForward: true, want: false},
		{name: "both matches forward reference", direction: ua.BrowseDirectionBoth, isForward: true, want: true},
		{name: "both matches inverse reference", direction: ua.BrowseDirectionBoth, isForward: false, want: true},
		{name: "inverse rejects symmetric reference", direction: ua.BrowseDirectionInverse, isForward: false, isSymmetric: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, suitableDirection(tt.direction, tt.isForward, tt.isSymmetric))
		})
	}
}

func TestSuitableRefType(t *testing.T) {
	t.Parallel()

	hierarchical := ua.NewNumericNodeID(0, id.HierarchicalReferences)
	organizes := ua.NewNumericNodeID(0, id.Organizes)
	hasComponent := ua.NewNumericNodeID(0, id.HasComponent)
	srv := &viewTestServer{
		namespaces: map[int]types.NameSpace{
			0: &viewTestNamespace{
				nodeFn: func(nodeID *ua.NodeID) types.Node {
					switch {
					case nodeID.Equal(hierarchical):
						return viewTestReferenceTypeNode{
							viewTestNode: viewTestNode{
								id:        hierarchical,
								nodeClass: ua.NodeClassReferenceType,
								refs: viewTestReferences{
									items: []types.ReferenceWrapper{
										viewTestReference{
											refType:    ua.NewNumericNodeID(0, id.HasSubtype),
											isForward:  true,
											targetNode: viewTestReferenceTypeNode{viewTestNode: viewTestNode{id: organizes, nodeClass: ua.NodeClassReferenceType}},
										},
										viewTestReference{
											refType:    ua.NewNumericNodeID(0, id.HasSubtype),
											isForward:  true,
											targetNode: viewTestReferenceTypeNode{viewTestNode: viewTestNode{id: hasComponent, nodeClass: ua.NodeClassReferenceType}},
										},
									},
								},
							},
							symmetric: false,
						}
					case nodeID.Equal(organizes):
						return viewTestReferenceTypeNode{
							viewTestNode: viewTestNode{id: organizes, nodeClass: ua.NodeClassReferenceType},
							symmetric:    false,
						}
					case nodeID.Equal(hasComponent):
						return viewTestReferenceTypeNode{
							viewTestNode: viewTestNode{id: hasComponent, nodeClass: ua.NodeClassReferenceType},
							symmetric:    false,
						}
					default:
						return nil
					}
				},
			},
		},
	}

	assert.True(t, suitableRefType(srv, hierarchical, hierarchical, false))
	assert.False(t, suitableRefType(srv, hierarchical, organizes, false))
	assert.True(t, suitableRefType(srv, hierarchical, organizes, true))
	assert.False(t, suitableRefType(srv, hierarchical, ua.NewNumericNodeID(0, id.HasTypeDefinition), true))
}

func TestTrimReferenceDescriptionByResultMask(t *testing.T) {
	t.Parallel()

	ref := &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		IsForward:       true,
		NodeID:          ua.NewNumericExpandedNodeID(1, 2001),
		BrowseName:      &ua.QualifiedName{Name: "target"},
		DisplayName:     ua.NewLocalizedText("Target"),
		NodeClass:       ua.NodeClassObject,
		TypeDefinition:  ua.NewNumericExpandedNodeID(0, id.BaseObjectType),
	}

	trimmed := trimReferenceDescriptionByResultMask(ref, uint32(ua.BrowseResultMaskBrowseName|ua.BrowseResultMaskTypeDefinition))

	assert.Nil(t, trimmed.ReferenceTypeID)
	require.NotNil(t, trimmed.BrowseName)
	assert.Equal(t, "target", trimmed.BrowseName.Name)
	require.NotNil(t, trimmed.TypeDefinition)
	assert.True(t, trimmed.TypeDefinition.NodeID.Equal(ua.NewNumericNodeID(0, id.BaseObjectType)))
	assert.Nil(t, trimmed.DisplayName)
	require.NotNil(t, trimmed.NodeID)
	assert.True(t, trimmed.NodeID.NodeID.Equal(ua.NewNumericNodeID(1, 2001)))
}

func TestBrowseAppliesResultMask(t *testing.T) {
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
					{
						ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
						IsForward:       true,
						NodeID:          ua.NewNumericExpandedNodeID(1, 2001),
						BrowseName:      &ua.QualifiedName{Name: "target"},
						DisplayName:     ua.NewLocalizedText("Target"),
						NodeClass:       ua.NodeClassObject,
						TypeDefinition:  ua.NewNumericExpandedNodeID(0, id.BaseObjectType),
					},
				},
			}
		},
	}

	resp, err := service.Browse(t.Context(), nil, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 55},
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          nodeID,
				BrowseDirection: ua.BrowseDirectionForward,
				ResultMask:      uint32(ua.BrowseResultMaskBrowseName | ua.BrowseResultMaskNodeClass),
			},
		},
	}, 1)
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	ref := browseResp.Results[0].References[0]
	require.NotNil(t, ref.BrowseName)
	assert.Equal(t, "target", ref.BrowseName.Name)
	assert.Equal(t, ua.NodeClassObject, ref.NodeClass)
	assert.Nil(t, ref.ReferenceTypeID)
	assert.Nil(t, ref.DisplayName)
	require.NotNil(t, ref.NodeID)
	assert.True(t, ref.NodeID.NodeID.Equal(ua.NewNumericNodeID(1, 2001)))
	assert.Nil(t, ref.TypeDefinition)
}

func TestSuitableReferenceNodeClassMask(t *testing.T) {
	t.Parallel()

	ref := viewTestReference{
		refType:    ua.NewNumericNodeID(0, id.Organizes),
		isForward:  true,
		targetNode: viewTestNode{id: ua.NewNumericNodeID(1, 2001), nodeClass: ua.NodeClassObject},
	}
	srv := &viewTestServer{
		namespaces: map[int]types.NameSpace{
			0: &viewTestNamespace{
				nodeFn: func(id *ua.NodeID) types.Node {
					if id.Equal(ref.refType) {
						return viewTestReferenceTypeNode{
							viewTestNode: viewTestNode{id: id, nodeClass: ua.NodeClassReferenceType},
							symmetric:    false,
						}
					}
					return nil
				},
			},
		},
	}

	tests := []struct {
		name string
		mask uint32
		want bool
	}{
		{name: "zero mask matches all classes", mask: 0, want: true},
		{name: "matching object bit passes", mask: uint32(ua.NodeClassObject), want: true},
		{name: "non matching variable bit fails", mask: uint32(ua.NodeClassVariable), want: false},
		{name: "combined mask containing object passes", mask: uint32(ua.NodeClassObject | ua.NodeClassVariable), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			desc := &ua.BrowseDescription{
				NodeID:          ua.NewNumericNodeID(1, 1001),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, 0),
				IncludeSubtypes: true,
				NodeClassMask:   tt.mask,
			}
			assert.Equal(t, tt.want, SuitableReference(t.Context(), srv, desc, ref))
		})
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
	refs      types.ReferenceCollection
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

func (n viewTestNode) References() types.ReferenceCollection { return n.refs }

func (n viewTestNode) Attribute(context.Context, ua.AttributeID) (*types.AttrValue, error) {
	return nil, nil
}

func (n viewTestNode) SetAttribute(context.Context, ua.AttributeID, *ua.DataValue) error { return nil }

type viewTestReferenceTypeNode struct {
	viewTestNode
	symmetric bool
}

func (n viewTestReferenceTypeNode) DataType() *ua.ExpandedNodeID { return &ua.ExpandedNodeID{} }

func (n viewTestReferenceTypeNode) IsAbstract() bool { return false }

func (n viewTestReferenceTypeNode) IsSymetrical() bool { return n.symmetric }

type viewTestReference struct {
	refType    *ua.NodeID
	isForward  bool
	targetNode types.Node
}

func (r viewTestReference) NodeClass() ua.NodeClass { return r.targetNode.NodeClass() }

func (r viewTestReference) IsForward() bool { return r.isForward }

func (r viewTestReference) IsReferenceType(refType uint32) bool {
	return r.refType.Namespace() == 0 && r.refType.IntID() == refType
}

func (r viewTestReference) ReferenceType() *ua.NodeID { return r.refType }

func (r viewTestReference) TargetNodeID() *ua.ExpandedNodeID {
	return &ua.ExpandedNodeID{NodeID: r.targetNode.ID()}
}

func (r viewTestReference) TargetsNode(other types.Node) bool {
	return other != nil && r.targetNode.ID().Equal(other.ID())
}

func (r viewTestReference) Copy(context.Context) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: r.refType,
		IsForward:       r.isForward,
		NodeID:          &ua.ExpandedNodeID{NodeID: r.targetNode.ID()},
		NodeClass:       r.targetNode.NodeClass(),
	}
}

type viewTestReferences struct {
	items []types.ReferenceWrapper
}

func (r viewTestReferences) All() iter.Seq[types.ReferenceWrapper] {
	return func(yield func(types.ReferenceWrapper) bool) {
		for _, item := range r.items {
			if !yield(item) {
				return
			}
		}
	}
}

func (r viewTestReferences) Contains(match func(types.ReferenceWrapper) bool) bool {
	return slices.ContainsFunc(r.items, match)
}

func (r viewTestReferences) Count() int { return len(r.items) }

func (r viewTestReferences) Find(matching func(types.ReferenceWrapper) bool) iter.Seq[types.ReferenceWrapper] {
	return func(yield func(types.ReferenceWrapper) bool) {
		for _, item := range r.items {
			if matching(item) && !yield(item) {
				return
			}
		}
	}
}

type viewTestServer struct {
	namespaces map[int]types.NameSpace
}

func (s *viewTestServer) ImportNodeSet(context.Context, *schema.UANodeSet) error { return nil }

func (s *viewTestServer) AddNamespace(ns types.NameSpace) int {
	id := int(ns.ID())
	s.namespaces[id] = ns
	return id
}

func (s *viewTestServer) Namespace(id int) (types.NameSpace, error) {
	ns, ok := s.namespaces[id]
	if !ok {
		return nil, errors.New("namespace not found")
	}
	return ns, nil
}

func (s *viewTestServer) Namespaces() []types.NameSpace { return nil }

func (s *viewTestServer) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	ns, ok := s.namespaces[int(id.Namespace())]
	if !ok {
		return nil
	}
	return ns.Node(id)
}

func (s *viewTestServer) ChangeNotification(context.Context, *ua.NodeID) {}

func (s *viewTestServer) DeleteSubscription(types.SubscriptionID) {}

func (s *viewTestServer) Config() types.ServerConfig { return viewTestConfig{} }

func (s *viewTestServer) Endpoints() []*ua.EndpointDescription { return nil }

func (s *viewTestServer) Session(context.Context, *ua.RequestHeader) types.Session { return nil }

func (s *viewTestServer) Status() *ua.ServerStatusDataType { return nil }

func (s *viewTestServer) Close(context.Context) error { return nil }

func (s *viewTestServer) Start(context.Context) error { return nil }

type viewTestConfig struct {
	maxBrowseOperationsPerCall  uint32
	maxBrowseContinuationPoints uint32
}

func (cfg viewTestConfig) Certificate() []byte { return nil }

func (cfg viewTestConfig) Endpoints() []string { return nil }

func (cfg viewTestConfig) PrivateKey() *rsa.PrivateKey { return nil }

func (cfg viewTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator { return nil }

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
