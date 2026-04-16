// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uatest2

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

type startedServer struct {
	types.Server
	endpoint string
}

func startServer(t testing.TB, ctx context.Context) *startedServer {
	t.Helper()

	var opts []server.Option
	port := reserveTestPort(t)

	opts = append(opts,
		server.EnableSecurity(server.SecurityPolicyNone, ua.MessageSecurityModeNone),
	)

	opts = append(opts,
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		// server.EnableAuthWithoutEncryption(), // Dangerous and not recommended, shown for illustration only
	)

	opts = append(opts,
		server.EndPoint("localhost", port),
	)

	s := server.New(ctx, opts...)

	rootNS, _ := s.Namespace(0)
	folderTypeNode := rootNS.Node(ua.NewNumericNodeID(0, id.FolderType))
	folderType, _ := folderTypeNode.(types.ObjectTypeNode)

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")

	// Create an objects folder for this namespace
	nodeNSObjectsFolder := nodeNS.AddNode(
		node.NewObjectNode(
			node.WithBase(
				node.WithID(nodeNS.NextAvailableID()),
				node.WithBrowseName(nodeNS.NewQualifiedName(nodeNS.Name())),
			),
			node.WithType(folderType),
		),
	)

	// add the reference for this namespace's root object folder to the server's root object folder
	refs.LinkWithOrganizesReferenceDescriptions(
		rootNS.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		nodeNSObjectsFolder,
	)

	propertyTypeNode := s.Node(ua.NewNumericNodeID(0, id.PropertyType))
	propertyType, _ := propertyTypeNode.(types.VariableTypeNode)

	// Create some nodes for it.
	nodeNSObjectsFolder.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ro_bool")),
			node.WithBrowseName(nodeNS.NewQualifiedName("ro_bool")),
		),
		node.WithValue(true),
		node.WithVariableType(propertyType),
	)))

	nodeNSObjectsFolder.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "rw_bool")),
			node.WithBrowseName(nodeNS.NewQualifiedName("rw_bool")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
		node.WithValue(true),
		node.WithVariableType(propertyType),
	)))

	nodeNSObjectsFolder.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ro_int32")),
			node.WithBrowseName(nodeNS.NewQualifiedName("ro_int32")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead),
		node.WithValue(int32(5)),
		node.WithVariableType(propertyType),
	)))

	nodeNSObjectsFolder.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "rw_int32")),
			node.WithBrowseName(nodeNS.NewQualifiedName("rw_int32")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
		node.WithValue(int32(5)),
		node.WithVariableType(propertyType),
	)))

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "NoPermVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("NoPermVariable")),
				),
				node.WithValue(int32(742)),
				node.WithVariableType(propertyType),
			),
		),
	)

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ReadWriteVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadWriteVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
				node.WithValue(12.34),
				node.WithVariableType(propertyType),
			),
		),
	)

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ReadOnlyVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadOnlyVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead),
				node.WithValue(9.87),
				node.WithVariableType(propertyType),
			),
		),
	)

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "NoAccessVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("NoAccessVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeNone),
				node.WithValue(55.43),
				node.WithVariableType(propertyType),
			),
		),
	)

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	gopcuaNS := server.NewNodeNameSpace(s, "http://gopcua.com/")

	// Create an objects folder for this namespace
	gopcuaNSObjectsFolder := gopcuaNS.AddNode(
		node.NewObjectNode(
			node.WithBase(
				node.WithID(gopcuaNS.NextAvailableID()),
				node.WithBrowseName(gopcuaNS.NewQualifiedName(gopcuaNS.Name())),
			),
			node.WithType(folderType),
		),
	)

	refs.LinkWithOrganizesReferenceDescriptions(
		rootNS.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		gopcuaNSObjectsFolder,
	)

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	// Start the server
	if err := s.Start(ctx); err != nil {
		log.Fatalf("Error starting server, exiting: %s", err)
	}

	return &startedServer{
		Server:   s,
		endpoint: fmt.Sprintf("opc.tcp://localhost:%d", port),
	}
}

func reserveTestPort(t testing.TB) int {
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
