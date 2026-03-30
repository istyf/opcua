// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uatest2

import (
	"context"
	"log"

	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/ua"
)

func startServer(ctx context.Context) *server.Server {
	var opts []server.Option
	port := 4840

	opts = append(opts,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic128Rsa15", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic128Rsa15", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Basic256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Aes128_Sha256_RsaOaep", ua.MessageSecurityModeSign),
		server.EnableSecurity("Aes128_Sha256_RsaOaep", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Aes256_Sha256_RsaPss", ua.MessageSecurityModeSign),
		server.EnableSecurity("Aes256_Sha256_RsaPss", ua.MessageSecurityModeSignAndEncrypt),
	)

	opts = append(opts,
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		//		server.EnableAuthWithoutEncryption(), // Dangerous and not recommended, shown for illustration only
	)

	opts = append(opts,
		server.EndPoint("localhost", port),
	)

	s := server.New(ctx, opts...)

	rootNS, _ := s.Namespace(0)
	rootObjects := rootNS.Objects()

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")
	// add it to the server.
	s.AddNamespace(nodeNS)

	nodeNSObjects := nodeNS.Objects()
	// add the reference for this namespace's root object folder to the server's root object folder
	rootObjects.AddComponent(nodeNSObjects)

	// Create some nodes for it.
	nodeNSObjects.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ro_bool")),
			node.WithBrowseName(nodeNS.NewQualifiedName("ro_bool")),
		),
		node.WithValue(true),
	)))

	nodeNSObjects.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "rw_bool")),
			node.WithBrowseName(nodeNS.NewQualifiedName("rw_bool")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
		node.WithValue(true),
	)))

	nodeNSObjects.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ro_int32")),
			node.WithBrowseName(nodeNS.NewQualifiedName("ro_int32")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead),
		node.WithValue(int32(5)),
	)))

	nodeNSObjects.AddComponent(nodeNS.AddNode(node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewStringNodeID(nodeNS.ID(), "rw_int32")),
			node.WithBrowseName(nodeNS.NewQualifiedName("rw_int32")),
		),
		node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
		node.WithValue(int32(5)),
	)))

	nodeNSObjects.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "NoPermVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("NoPermVariable")),
				),
				node.WithValue(int32(742)),
			),
		),
	)

	nodeNSObjects.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ReadWriteVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadWriteVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
				node.WithValue(12.34),
			),
		),
	)

	nodeNSObjects.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "ReadOnlyVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadOnlyVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead),
				node.WithValue(9.87),
			),
		),
	)

	nodeNSObjects.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "NoAccessVariable")),
					node.WithBrowseName(nodeNS.NewQualifiedName("NoAccessVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeNone),
				node.WithValue(55.43),
			),
		),
	)

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	gopcuaNS := server.NewNodeNameSpace(s, "http://gopcua.com/")
	// add it to the server.
	s.AddNamespace(gopcuaNS)

	nodeNSObjects = gopcuaNS.Objects()
	// add the reference for this namespace's root object folder to the server's root object folder
	rootObjects.AddComponent(nodeNSObjects)

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	// Start the server
	if err := s.Start(ctx); err != nil {
		log.Fatalf("Error starting server, exiting: %s", err)
	}

	return s
}
