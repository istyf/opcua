package main

import (
	"log"
	"net"
	"strconv"
	"testing"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

func TestBrowse(t *testing.T) {
	ctx := t.Context()
	port := reserveTestPort(t)
	endpoint := "opc.tcp://localhost:" + strconv.Itoa(port)

	// start the server
	s := server.New(
		ctx,
		server.EndPoint("localhost", port),
		server.EnableSecurity(server.SecurityPolicyNone, ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)

	populateServer(s)

	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)

	// prepare the client
	c, err := opcua.NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)

	// browse the nodes
	nodeList, err := browse(
		ctx,
		c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		"",
		maxDepth-3, // faster test with reduced depth
	)
	if err != nil {
		t.Fatal(err)
	}

	// ensure that the TestVar1 node was found
	found := false
	for _, n := range nodeList {
		if n.BrowseName == "TestObj1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("TestObj1 not found in nodeList: %v", nodeList)
	}
}

func reserveTestPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve test port: %v", err)
	}
	defer l.Close()

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", l.Addr())
	}

	return tcpAddr.Port
}

func populateServer(s types.Server) {
	// When the server is created, it will automatically create namespace 0 and populate it with
	// the core opc ua nodes.

	// add the namespaces to the server, and add a reference to them (otherwise browsing will not find it).
	// here we are choosing to add the namespaces to the root/object folder
	// to do this we first need to get the root namespace object folder so we
	// get the object node
	rootNS, _ := s.Namespace(0)

	// Now we'll add a node namespace.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")
	log.Printf("node namespace added at index %d", nodeNS.ID())

	objectTypeNode := rootNS.Node(ua.NewNumericNodeID(0, id.BaseObjectType))
	objectType, _ := objectTypeNode.(types.VariableTypeNode)

	// Add forward and backward organizes references between the existing root
	// ObjectsFolder and a test object that we create here
	refs.LinkWithOrganizesReferenceDescriptions(
		rootNS.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		nodeNS.AddNode(
			node.NewObjectNode(
				node.WithBase(
					node.WithID(nodeNS.NextAvailableID()),
					node.WithBrowseName(nodeNS.NewQualifiedName("TestObj1")),
				),
				node.WithType(objectType),
			),
		),
	)
}
