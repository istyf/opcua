// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uatest2

import (
	"context"
	"log"

	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/attrs"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/values"
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

	root_ns, _ := s.Namespace(0)
	obj_node := root_ns.Objects()

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")
	// add it to the server.
	s.AddNamespace(nodeNS)
	nns_obj := nodeNS.Objects()
	// add the reference for this namespace's root object folder to the server's root object folder
	obj_node.AddRef(refs.NewHasComponentRefDesc(nns_obj))

	// Create some nodes for it.
	n := nodeNS.AddNewVariableStringNode("ro_bool", true)
	n.SetAttribute(ua.AttributeIDUserAccessLevel, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(uint32(1))})
	nns_obj.AddRef(refs.NewHasComponentRefDesc(n))
	n = nodeNS.AddNewVariableStringNode("rw_bool", true)
	nns_obj.AddRef(refs.NewHasComponentRefDesc(n))

	n = nodeNS.AddNewVariableStringNode("ro_int32", int32(5))
	n.SetAttribute(ua.AttributeIDUserAccessLevel, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(uint32(1))})
	nns_obj.AddRef(refs.NewHasComponentRefDesc(n))
	n = nodeNS.AddNewVariableStringNode("rw_int32", int32(5))
	nns_obj.AddRef(refs.NewHasComponentRefDesc(n))

	var3 := node.NewNode(
		ua.NewStringNodeID(nodeNS.ID(), "NoPermVariable"), // you can use whatever node id you want here, whether it's numeric, string, guid, etc...
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDBrowseName: values.DataValueFromValue(attrs.BrowseName("NoPermVariable")),
			ua.AttributeIDNodeClass:  values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(int32(742)) },
	)
	nodeNS.AddNode(var3)
	nns_obj.AddRef(refs.NewHasComponentRefDesc(var3))

	var4 := node.NewNode(
		ua.NewStringNodeID(nodeNS.ID(), "ReadWriteVariable"), // you can use whatever node id you want here, whether it's numeric, string, guid, etc...
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDAccessLevel:     values.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite)),
			ua.AttributeIDUserAccessLevel: values.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite)),
			ua.AttributeIDBrowseName:      values.DataValueFromValue(attrs.BrowseName("ReadWriteVariable")),
			ua.AttributeIDNodeClass:       values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(12.34) },
	)
	nodeNS.AddNode(var4)
	nns_obj.AddRef(refs.NewHasComponentRefDesc(var4))

	var5 := node.NewNode(
		ua.NewStringNodeID(nodeNS.ID(), "ReadOnlyVariable"), // you can use whatever node id you want here, whether it's numeric, string, guid, etc...
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDAccessLevel:     values.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: values.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDBrowseName:      values.DataValueFromValue(attrs.BrowseName("ReadOnlyVariable")),
			ua.AttributeIDNodeClass:       values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(9.87) },
	)
	nodeNS.AddNode(var5)
	nns_obj.AddRef(refs.NewHasComponentRefDesc(var5))

	var6 := node.NewNode(
		ua.NewStringNodeID(nodeNS.ID(), "NoAccessVariable"), // you can use whatever node id you want here, whether it's numeric, string, guid, etc...
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDAccessLevel:     values.DataValueFromValue(byte(ua.AccessLevelTypeNone)),
			ua.AttributeIDUserAccessLevel: values.DataValueFromValue(byte(ua.AccessLevelTypeNone)),
			ua.AttributeIDBrowseName:      values.DataValueFromValue(attrs.BrowseName("NoAccessVariable")),
			ua.AttributeIDNodeClass:       values.DataValueFromValue(uint32(ua.NodeClassVariable)),
		},
		nil,
		func() *ua.DataValue { return values.DataValueFromValue(55.43) },
	)
	nodeNS.AddNode(var6)
	nns_obj.AddRef(refs.NewHasComponentRefDesc(var6))

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	gopcuaNS := server.NewNodeNameSpace(s, "http://gopcua.com/")
	// add it to the server.
	s.AddNamespace(gopcuaNS)
	nns_obj = gopcuaNS.Objects()
	// add the reference for this namespace's root object folder to the server's root object folder
	obj_node.AddRef(refs.NewHasComponentRefDesc(nns_obj))

	// Create a new node namespace.  You can add namespaces before or after starting the server.
	// Start the server
	if err := s.Start(ctx); err != nil {
		log.Fatalf("Error starting server, exiting: %s", err)
	}

	return s
}
