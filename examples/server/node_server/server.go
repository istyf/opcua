// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/node"
	"github.com/gopcua/opcua/server/refs"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/server/values"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

var (
	endpoint = flag.String("endpoint", "0.0.0.0", "OPC UA Endpoint URL")
	port     = flag.Int("port", 4840, "OPC UA Endpoint port")
	certfile = flag.String("cert", "cert.pem", "Path to certificate file")
	keyfile  = flag.String("key", "key.pem", "Path to PEM Private Key file")
	gencert  = flag.Bool("gen-cert", false, "Generate a new certificate")
)

func main() {
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()

	ctx := ualog.New(context.Background(), ualog.WithHandler(
		slog.NewJSONHandler(os.Stdout, func() *slog.HandlerOptions {
			if debug.Enable {
				return &slog.HandlerOptions{Level: slog.LevelDebug}
			}
			return nil
		}()),
	))

	var opts []server.Option

	// Set your security options.
	opts = append(opts,
		server.EnableSecurity(server.SecurityPolicyNone, ua.MessageSecurityModeNone),
		server.EnableSecurity(server.SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		/*
			Additional secure server modes currently supported:
			server.EnableSecurity(server.SecurityPolicyBasic256, ua.MessageSecurityModeSign),
			server.EnableSecurity(server.SecurityPolicyBasic256, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableSecurity(server.SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSign),
			server.EnableSecurity(server.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityModeSign),
			server.EnableSecurity(server.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableSecurity(server.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityModeSign),
			server.EnableSecurity(server.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt),

			Basic128Rsa15 is intentionally unsupported on the server because it is deprecated.
		*/
	)

	// Set your user authentication options.
	opts = append(opts,
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		/*
			These authentication modes are not implemented yet
			server.EnableAuthMode(ua.UserTokenTypeUserName),
			server.EnableAuthMode(ua.UserTokenTypeCertificate),
		*/
		//		server.EnableAuthWithoutEncryption(), // Dangerous and not recommended, shown for illustration only
	)

	// Here we're automatically adding the hostname and localhost to the endpoint list.
	// Some clients are picky about the endpoint matching the connection url, so be sure to add any addresses/hostnames that
	// clients will use to connect to the server.
	//
	// be sure the hostname(s) also match the certificate the server is going to use.
	hostname, err := os.Hostname()
	if err != nil {
		fatal(ctx, "error getting host name", err)
	}

	opts = append(opts,
		server.EndPoint(*endpoint, *port),
		server.EndPoint("localhost", *port),
		server.EndPoint(hostname, *port),
	)

	// Here is an example of certificate generation.  This is not necessary if you already have a certificate.
	if *gencert {
		// it is important that the certificate is generated with the correct hostname/IP address URIs
		// or the clients may not accept the certificate.
		endpoints := []string{
			"localhost",
			hostname,
			*endpoint,
		}

		c, k, err := GenerateCert(endpoints, 4096, time.Minute*60*24*365*10)
		if err != nil {
			fatal(ctx, "problem creating certificate", err)
		}
		err = os.WriteFile(*certfile, c, 0644)
		if err != nil {
			fatal(ctx, "problem writing certificate", err)
		}
		err = os.WriteFile(*keyfile, k, 0600)
		if err != nil {
			fatal(ctx, "problem writing key", err)
		}
	}

	var cert []byte
	if *gencert || (*certfile != "" && *keyfile != "") {
		ualog.Info(ctx, "loading certificate and key from files",
			ualog.String("cert", *certfile),
			ualog.String("key", *keyfile),
		)
		c, err := tls.LoadX509KeyPair(*certfile, *keyfile)
		if err != nil {
			ualog.Error(ctx, "failed to load certificate", ualog.Err(err))
		} else {
			pk, ok := c.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				fatal(ctx, "invalid private key", errors.New("incorrect type"))
			}
			cert = c.Certificate[0]
			opts = append(opts, server.PrivateKey(pk), server.Certificate(cert))
		}
	}

	// Now that all the options are set, create the server.
	// When the server is created, it will automatically create namespace 0 and populate it with
	// the core opc ua nodes.
	s := server.New(ctx, opts...)

	// add the namespaces to the server, and add a reference to them if desired.
	// here we are choosing to add the namespaces to the root/object folder
	// to do this we first need to get the root namespace object folder so we
	// get the object node
	rootNamespace, _ := s.Namespace(0)

	// Start the server
	// Note that you can add namespaces before or after starting the server.
	if err := s.Start(ctx); err != nil {
		fatal(ctx, "unable to start server", err)
	}
	defer s.Close(ctx)

	// Now we'll add a node namespace.  This is a more traditional way to add nodes to the server
	// and is more in line with the opc ua node model, but may be more cumbersome for some use cases.
	nodeNS := server.NewNodeNameSpace(s, "NodeNamespace")
	ualog.Info(ctx, "node namespace added", ualog.Uint32("index", uint32(nodeNS.ID())))

	// add the reference for this namespace's root object folder to the server's root object folder
	// but you can add a reference to whatever node(s) you need

	folderTypeNode := rootNamespace.Node(ua.NewNumericNodeID(0, id.FolderType))
	folderType, _ := folderTypeNode.(types.ObjectTypeNode)

	nodeNSObjectsFolder := nodeNS.AddNode(
		node.NewObjectNode(
			node.WithBase(
				node.WithID(nodeNS.NextAvailableID()),
				node.WithBrowseName(nodeNS.NewQualifiedName("Objects")),
			),
			node.WithType(folderType),
		),
	)

	refs.AddOrganizesRefDescs(
		rootNamespace.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)),
		nodeNSObjectsFolder,
	)

	// Create some nodes for it.  Here we are creating a new variable node
	// with an integer node ID that is automatically assigned. (ns=<namespace id>,s=<auto assigned>)
	// be sure to add the reference to the node somewhere if desired, or clients won't be able to browse it.
	var1 := node.NewVariableNode(
		node.WithBase(
			node.WithID(ua.NewNumericNodeID(nodeNS.ID(), nodeNS.GetNextNodeID())),
			node.WithBrowseName(nodeNS.NewQualifiedName("TestVar1")),
		),
		node.WithValue(float32(123.45)),
	)
	nodeNSObjectsFolder.AddComponent(nodeNS.AddNode(var1))

	// This node will have a string node id (ns=<namespace id>,s=TestVar2)
	// your variable node's value can also return a ua.Variant from a function if you want to update the value dynamically
	// here we are just incrementing a counter every time the value is read.
	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewStringNodeID(nodeNS.ID(), "TestVar2")),
					node.WithBrowseName(nodeNS.NewQualifiedName("TestVar2")),
				),
				node.WithDataType(ua.NewNumericNodeID(0, id.Int32)),
				node.WithDataValue(
					func() func() *ua.DataValue {
						var2Value := atomic.Int32{}
						return func() *ua.DataValue {
							return values.DataValueFromValue(var2Value.Add(1))
						}
					}(),
				),
			),
		))

	// Now we'll add a node from scratch.  This is a more manual way to add nodes to the server and gives you full
	// control, but you'll have to build the node up with the correct attributes and references and then reference it from
	// the parent node in the namespace if applicable.

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					// you can use whatever node id you want here, whether it's numeric, string, guid, etc...
					node.WithID(ua.NewNumericNodeID(nodeNS.ID(), 12345)),
					node.WithBrowseName(nodeNS.NewQualifiedName("MyBrowseName")),
				),
				node.WithValue(12.34),
			),
		))

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewNumericNodeID(nodeNS.ID(), 100)),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadWriteVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead, ua.AccessLevelExTypeCurrentWrite),
				node.WithValue(12.34),
			),
		),
	)

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewNumericNodeID(nodeNS.ID(), 105)),
					node.WithBrowseName(nodeNS.NewQualifiedName("ReadOnlyVariable")),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeCurrentRead),
				node.WithValue(9.87),
			),
		),
	)

	nodeNSObjectsFolder.AddComponent(
		nodeNS.AddNode(
			node.NewVariableNode(
				node.WithBase(
					node.WithID(ua.NewNumericNodeID(nodeNS.ID(), 102)),
					node.WithBrowseName(&ua.QualifiedName{NamespaceIndex: nodeNS.ID(), Name: "NoAccessVariable"}),
				),
				node.WithAccessLevels(ua.AccessLevelExTypeNone),
				node.WithValue(9.87),
			),
		),
	)

	// simulate a background process updating the data in the namespace.
	go func() {
		updates := 0
		num := 42
		time.Sleep(time.Second * 10)
		for {
			updates++
			num++

			// get the current value of the variable
			lastValue := var1.Value().Value.Value().(float32)
			// and change it
			lastValue += 1

			// wrap the new value in a DataValue and use that to update the Value attribute of the node
			val := values.DataValueFromVariant(ua.MustVariant(lastValue))
			var1.SetAttribute(ctx, ua.AttributeIDValue, val)

			// we also need to let the node namespace know that the value has changed so it can trigger the change notification
			// and send the updated value to any subscribed clients.
			nodeNS.ChangeNotification(ctx, var1.ID())

			time.Sleep(time.Second)
		}
	}()

	// simulate monitoring one of the namespaces for change events.
	// this is how you would be notified when a write to a node
	// occurs through the opc ua server
	go func() {
		for {
			changedID := <-nodeNS.ExternalNotification
			node := nodeNS.Node(changedID)
			if variable, ok := node.(types.VariableNode); ok {
				value := variable.Value().Value.Value()

				ualog.Info(ctx, "value changed",
					ualog.String("key", changedID.String()),
					ualog.Any("value", value),
				)
			}
		}
	}()

	// catch ctrl-c and gracefully shutdown the server.
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	defer signal.Stop(sigch)

	ualog.Info(ctx, "press ctrl-c to exit")

	<-sigch

	ualog.Info(ctx, "shutting down the server ...")
}

func fatal(ctx context.Context, reason string, err error) {
	ualog.Error(ctx, "FATAL: "+reason, ualog.Err(err))
	time.Sleep(time.Second)
	os.Exit(1)
}
