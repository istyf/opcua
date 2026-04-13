package server

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

func TestMapNamespaceBrowseFiltersReferencesAndDoesNotReturnNilEntries(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewMapNamespace(srv, "map")
	ns.data["alpha"] = int32(1)
	ns.data["beta"] = int32(2)

	result := ns.Browse(t.Context(), &ua.BrowseDescription{
		NodeID:          ns.objectsFolder.ID(),
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
		IncludeSubtypes: false,
		NodeClassMask:   uint32(ua.NodeClassVariable),
	})

	if result.StatusCode != ua.StatusOK {
		t.Fatalf("expected %s, got %s", ua.StatusOK, result.StatusCode)
	}
	if len(result.References) != 2 {
		t.Fatalf("expected 2 references, got %d", len(result.References))
	}
	for i, ref := range result.References {
		if ref == nil {
			t.Fatalf("expected reference %d to be non-nil", i)
		}
		if ref.ReferenceTypeID == nil || ref.ReferenceTypeID.IntID() != id.HasComponent {
			t.Fatalf("expected reference %d to use HasComponent, got %#v", i, ref.ReferenceTypeID)
		}
		if !ref.IsForward {
			t.Fatalf("expected reference %d to be forward", i)
		}
		if ref.NodeClass != ua.NodeClassVariable {
			t.Fatalf("expected reference %d to target a variable, got %s", i, ref.NodeClass)
		}
	}
}

func TestMapNamespaceBrowseHonorsDirectionAndReferenceTypeFilters(t *testing.T) {
	t.Parallel()

	srv := newMapNamespaceTestServer()
	ns := NewMapNamespace(srv, "map")
	ns.data["alpha"] = int32(1)

	inverse := ns.Browse(t.Context(), &ua.BrowseDescription{
		NodeID:          ns.objectsFolder.ID(),
		BrowseDirection: ua.BrowseDirectionInverse,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
		IncludeSubtypes: false,
	})
	if len(inverse.References) != 0 {
		t.Fatalf("expected inverse browse to return 0 references, got %d", len(inverse.References))
	}

	wrongType := ns.Browse(t.Context(), &ua.BrowseDescription{
		NodeID:          ns.objectsFolder.ID(),
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		IncludeSubtypes: false,
	})
	if len(wrongType.References) != 0 {
		t.Fatalf("expected wrong reference type browse to return 0 references, got %d", len(wrongType.References))
	}
}

type mapNamespaceTestServer struct {
	namespaces map[int]types.NameSpace
	nodes      map[string]types.Node
	nextNS     uint16
}

func newMapNamespaceTestServer() *mapNamespaceTestServer {
	srv := &mapNamespaceTestServer{
		namespaces: make(map[int]types.NameSpace),
		nodes:      make(map[string]types.Node),
		nextNS:     1,
	}

	folderType := node.NewObjectTypeNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.FolderType)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "FolderType"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("FolderType")}),
		),
	)
	objects := node.NewObjectNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(0, id.ObjectsFolder)),
			node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: 0, Name: "Objects"}),
			node.WithDisplayNames([]*ua.LocalizedText{ua.NewLocalizedText("Objects")}),
		),
		node.WithType(folderType),
	)

	srv.nodes[folderType.ID().String()] = folderType
	srv.nodes[objects.ID().String()] = objects

	return srv
}

func (s *mapNamespaceTestServer) ImportNodeSet(context.Context, *schema.UANodeSet) error { return nil }

func (s *mapNamespaceTestServer) AddNamespace(ns types.NameSpace) int {
	if ns.ID() == 0 {
		ns.SetID(s.nextNS)
		s.nextNS++
	}
	s.namespaces[int(ns.ID())] = ns
	return int(ns.ID())
}

func (s *mapNamespaceTestServer) Namespace(id int) (types.NameSpace, error) {
	ns, ok := s.namespaces[id]
	if !ok {
		return nil, ua.StatusBadNodeIDUnknown
	}
	return ns, nil
}

func (s *mapNamespaceTestServer) Namespaces() []types.NameSpace { return nil }

func (s *mapNamespaceTestServer) Node(id *ua.NodeID) types.Node {
	if id == nil {
		return nil
	}
	if node, ok := s.nodes[id.String()]; ok {
		return node
	}
	ns, ok := s.namespaces[int(id.Namespace())]
	if !ok {
		return nil
	}
	return ns.Node(id)
}

func (s *mapNamespaceTestServer) ChangeNotification(context.Context, *ua.NodeID) {}

func (s *mapNamespaceTestServer) DeleteSubscription(types.SubscriptionID) {}

func (s *mapNamespaceTestServer) Config() types.ServerConfig { return mapNamespaceTestConfig{} }

func (s *mapNamespaceTestServer) Endpoints() []*ua.EndpointDescription { return nil }

func (s *mapNamespaceTestServer) Session(context.Context, *ua.RequestHeader) types.Session {
	return nil
}

func (s *mapNamespaceTestServer) Status() *ua.ServerStatusDataType { return nil }

func (s *mapNamespaceTestServer) Close(context.Context) error { return nil }

func (s *mapNamespaceTestServer) Start(context.Context) error { return nil }

type mapNamespaceTestConfig struct{}

func (mapNamespaceTestConfig) Certificate() []byte { return nil }

func (mapNamespaceTestConfig) Endpoints() []string { return nil }

func (mapNamespaceTestConfig) PrivateKey() *rsa.PrivateKey { return nil }

func (mapNamespaceTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator { return nil }

func (mapNamespaceTestConfig) ApplicationURI() string { return "" }

func (mapNamespaceTestConfig) ManufacturerName() string { return "" }

func (mapNamespaceTestConfig) ProductName() string { return "" }

func (mapNamespaceTestConfig) SoftwareVersion() string { return "" }

func (mapNamespaceTestConfig) MaxNodesPerRead() uint32 { return 0 }

func (mapNamespaceTestConfig) MaxBrowseOperationsPerCall() uint32 { return 0 }

func (mapNamespaceTestConfig) MaxBrowseContinuationPoints() uint32 { return 0 }

func (mapNamespaceTestConfig) MaxSubscriptions() uint32 { return 0 }

func (mapNamespaceTestConfig) MaxSubscriptionsPerSession() uint32 { return 0 }

func (mapNamespaceTestConfig) MaxSubscriptionOperationsPerCall() uint32 { return 0 }

func (mapNamespaceTestConfig) MinSubscriptionPublishingInterval() time.Duration { return 0 }

func (mapNamespaceTestConfig) MinSubscriptionMaxKeepAliveCount() uint32 { return 0 }

func (mapNamespaceTestConfig) MinSubscriptionLifetimeCount() uint32 { return 0 }

func (mapNamespaceTestConfig) MethodCallMiddleware() types.MethodMiddleware { return nil }
