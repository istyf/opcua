// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
//
// This example program shows how to create a simple OPC UA server with data backed by a map.
// This allows you to easily create a server with a simple data model that can be updated from
// other parts of your application.  This example also shows how to monitor the data for changes
// and how to trigger change notifications to clients when the data changes.

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
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/server/refs"
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
	flag.Parse()

	ctx := ualog.New(context.Background(), ualog.WithHandler(slog.NewJSONHandler(os.Stdout, nil)))

	var opts []server.Option

	// Set your security options.
	opts = append(opts,
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		/*
			These security modes are not implemented yet.
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
		fatal(ctx, "unable to get host name", err)
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
		err = os.WriteFile(*certfile, c, 0)
		if err != nil {
			fatal(ctx, "problem writing certificate", err)
		}
		err = os.WriteFile(*keyfile, k, 0)
		if err != nil {
			fatal(ctx, "problem writing key", err)
		}
	}

	var cert []byte
	if *gencert || (*certfile != "" && *keyfile != "") {
		ualog.Info(ctx, "loading certificate and key from files",
			ualog.String("cert", *certfile), ualog.String("key", *keyfile),
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

	// Create some map namespaces.  These are backed by go map[string]any
	// which may be more convenient for some use cases than the NodeNamespace which requires
	// your application's data structure to match the opcua node model.
	myMapNamespace1 := server.NewMapNamespace(s, "MyTestNamespace")
	ualog.Info(ctx, "map namespace 1 added", ualog.Uint32("index", uint32(myMapNamespace1.ID())))
	myMapNamespace2 := server.NewMapNamespace(s, "SomeOtherNamespace")
	ualog.Info(ctx, "map namespace 2 added", ualog.Uint32("index", uint32(myMapNamespace1.ID())))

	// fill them with data.
	setNS1Value := myMapNamespace1.ValueUpdater(ctx)

	setNS1Value("Tag1", 123.4)
	setNS1Value("Tag2", 42)
	setNS1Value("Tag3.Tag4", "some string")
	setNS1Value("Tag5", true)
	setNS1Value("Tag6", time.Now())

	setNS2Value := myMapNamespace2.ValueUpdater(ctx)

	setNS2Value("Tag7", 56.78)
	setNS2Value("Tag8", 92)
	setNS2Value("Tag9", "different string")
	setNS2Value("Tag10", false)
	setNS2Value("Tag11", time.Now().Add(time.Hour))

	// simulate a background process updating the data in the map namespace.
	go func() {
		updates := 0
		num := 42
		tag5 := true
		time.Sleep(time.Second * 10)
		for {
			updates++
			num++

			setNS1Value("Tag2", num)

			if updates == 10 {
				// or you can do it with the built-in functions.
				// which handles the locking and triggering
				tag5 = !tag5
				myMapNamespace1.SetValue(ctx, "Tag5", tag5)
				updates = 0
			}
			time.Sleep(time.Second)
		}
	}()

	// simulate monitoring one of the namespaces for change events.
	// this is how you would be notified when a write to the map
	// occurs through the opc ua server
	go func() {
		for {
			changedKey := <-myMapNamespace2.ExternalNotification
			ualog.Info(ctx, "value changed",
				ualog.String("key", changedKey),
				ualog.Any("value", myMapNamespace2.GetValue(changedKey)),
			)
		}
	}()

	// add the namespaces to the server. If you want them to show up in a browse, you'll
	// also have to add a reference to them (probably from the object node).
	rootNS, _ := s.Namespace(0)

	// then we add the namespace to the server and add a reference to it from the object node.
	// the object node of the map namespace is a virtual node that contains all the "nodes" for each
	// map key
	rootObjectsFolder := rootNS.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
	refs.AddOrganizesRefDescs(rootObjectsFolder, myMapNamespace1.Objects())
	refs.AddHasComponentRefDescs(rootObjectsFolder, myMapNamespace2.Objects())

	// Start the server
	// Note that you can add namespaces before or after starting the server.
	if err := s.Start(ctx); err != nil {
		fatal(ctx, "unable to start server", err)
	}
	defer s.Close(ctx)

	// catch ctrl-c and gracefully shutdown the server.
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	defer signal.Stop(sigch)

	ualog.Info(ctx, "press ctrl-c to exit")

	<-sigch

	ualog.Info(ctx, "shutting down the server...")
}

func fatal(ctx context.Context, reason string, err error) {
	ualog.Error(ctx, "FATAL: "+reason, ualog.Err(err))
	time.Sleep(time.Second)
	os.Exit(1)
}
