package services

import (
	"context"
	"errors"
	"testing"

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
		browseFn: func(context.Context, *ua.BrowseDescription) *ua.BrowseResult {
			return &ua.BrowseResult{StatusCode: ua.StatusOK, References: []*ua.ReferenceDescription{
				{BrowseName: &ua.QualifiedName{Name: "first"}},
			}}
		},
	}
	backend.namespaces[2] = &viewTestNamespace{
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
	backend.namespaces[1] = &viewTestNamespace{}

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

type viewTestBackend struct {
	handlers   map[int]Handler
	namespaces map[int]types.NameSpace
	nodes      map[string]types.Node
}

func newViewTestBackend() *viewTestBackend {
	return &viewTestBackend{
		handlers:   make(map[int]Handler),
		namespaces: make(map[int]types.NameSpace),
		nodes:      make(map[string]types.Node),
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

type viewTestNamespace struct {
	browseFn func(context.Context, *ua.BrowseDescription) *ua.BrowseResult
}

func (ns *viewTestNamespace) Name() string { return "test" }

func (ns *viewTestNamespace) AddNode(n types.Node) types.Node { return n }

func (ns *viewTestNamespace) Node(*ua.NodeID) types.Node { return nil }

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
