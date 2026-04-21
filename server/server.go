// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/schema"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uapolicy"
)

//go:generate go run ../cmd/predefined-nodes/main.go

const defaultListenAddr = "opc.tcp://localhost:0"

// serverImpl is a high-level OPC-UA Server
type serverImpl struct {
	url string

	cfg *serverConfig

	importDeprecatedNodeSetNodes bool

	mu         sync.Mutex
	status     *ua.ServerStatusDataType
	endpoints  []*ua.EndpointDescription
	namespaces []types.NameSpace
	closeOnce  sync.Once
	runCancel  context.CancelFunc
	runWG      sync.WaitGroup

	l  *uacp.Listener
	cb *channelBroker
	sb *sessionBroker

	// nextSecureChannelID uint32

	// Service Handlers are methods called to respond to service requests from clients
	// All services should have a method here.
	handlers map[int]services.Handler

	attributeService      *services.AttributeService
	discoveryService      *services.DiscoveryService
	methodService         *services.MethodService
	nodeManagementService *services.NodeManagementService
	queryService          *services.QueryService
	sessionService        *services.SessionService
	viewService           *services.ViewService
	SubscriptionService   *services.SubscriptionService
	MonitoredItemService  *services.MonitoredItemService
}

// New returns an initialized OPC-UA server.
// Call Start() afterwards to begin listening and serving connections
func New(ctx context.Context, opts ...Option) types.Server {
	cfg := &serverConfig{
		cap:                       capabilities,
		applicationName:           "GOPCUA",               // override with the ServerName option
		manufacturerName:          "The gopcua Team",      // override with the ManufacturerName option
		productName:               "gopcua OPC/UA Server", // override with the ProductName option
		softwareVersion:           "0.0.0-dev",            // override with the SoftwareVersion option
		channelBrokerCloseTimeout: defaultChannelBrokerCloseTimeout,
		methodCallMiddleware:      func(fn types.MethodFunc) types.MethodFunc { return fn },
	}

	for _, opt := range opts {
		opt(ctx, cfg)
	}

	url := ""
	if len(cfg.endpoints) != 0 {
		url = cfg.endpoints[0]
	}

	s := &serverImpl{
		url:        url,
		cfg:        cfg,
		cb:         newChannelBroker(),
		sb:         newSessionBroker(),
		handlers:   make(map[int]services.Handler),
		namespaces: []types.NameSpace{},
		status: &ua.ServerStatusDataType{
			StartTime:   time.Now(),
			CurrentTime: time.Now(),
			State:       ua.ServerStateSuspended,
			BuildInfo: &ua.BuildInfo{
				ProductURI:       "https://github.com/gopcua/opcua",
				ManufacturerName: cfg.manufacturerName,
				ProductName:      cfg.productName,
				SoftwareVersion:  "0.0.0-dev",
				BuildNumber:      "",
				BuildDate:        time.Time{},
			},
			SecondsTillShutdown: 0,
			ShutdownReason:      ua.NewLocalizedText(""),
		},
	}

	// this nodeset is pre-compiled into the binary and contains a known set of nodes
	// so it should *always* work ok.
	var nodes schema.UANodeSet
	xml.Unmarshal(schema.OpcUaNodeSet2, &nodes)

	if nodes.NamespaceUris == nil || len(nodes.NamespaceUris.Uri) == 0 {
		nodes.NamespaceUris = &schema.UriTable{
			Uri: []string{"http://opcfoundation.org/UA/"},
		}
	}

	s.ImportNodeSet(ctx, &nodes)
	ns := s.namespaces[0]
	serverNode := ns.Node(ua.NewNumericNodeID(0, id.Server))

	WireupNamespacesArrayNodeValue(s, ns)
	WireupServerStatusNodesValues(s, serverNode, ns)
	WireupServerCapabilityNodeValue(s, ns)

	return s
}

func (s *serverImpl) Config() types.ServerConfig {
	return s.cfg
}

func (s *serverImpl) NewSession(timeout time.Duration, serverNonce []byte, remoteCert []byte) types.Session {
	return s.sb.NewSession(timeout, serverNonce, remoteCert)
}

func (s *serverImpl) Session(ctx context.Context, hdr *ua.RequestHeader) types.Session {
	return s.sb.Session(ctx, hdr.AuthenticationToken)
}

func (s *serverImpl) Subscription(id types.SubscriptionID) (*services.Subscription, bool) {
	return s.SubscriptionService.Get(id)
}

func (s *serverImpl) Namespace(id int) (types.NameSpace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id < len(s.namespaces) {
		return s.namespaces[id], nil
	}
	return nil, fmt.Errorf("namespace %d not found", id)
}

func (s *serverImpl) Namespaces() []types.NameSpace {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.namespaces
}

func (s *serverImpl) ChangeNotification(ctx context.Context, n *ua.NodeID) {
	s.MonitoredItemService.ChangeNotification(ctx, n)
}

func (s *serverImpl) DeleteSubscription(id types.SubscriptionID) {
	s.MonitoredItemService.DeleteSub(id)
}

// for now, the address space of the server is split up into namespaces.
// this means that when we look up a node, we need to ask the specific namespace
// it belongs to for it instead of just a general lookup by ID
//
// the refRoot and refObjects flags can be used to automatically add a reference to the new Namespaces
// root or objects object respectively to the namespace 0
func (s *serverImpl) AddNamespace(ns types.NameSpace) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx := slices.Index(s.namespaces, ns); idx >= 0 {
		return idx
	}
	ns.SetID(uint16(len(s.namespaces)))
	s.namespaces = append(s.namespaces, ns)

	if ns.ID() == 0 {
		return 0
	}

	return len(s.namespaces) - 1
}

func (s *serverImpl) Endpoints() []*ua.EndpointDescription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.endpoints)
}

// Status returns the current server status.
func (s *serverImpl) Status() *ua.ServerStatusDataType {
	status := new(ua.ServerStatusDataType)
	s.mu.Lock()
	*status = *s.status
	s.mu.Unlock()
	status.CurrentTime = time.Now()
	return status
}

// URLs returns opc endpoint that the server is listening on.
func (s *serverImpl) URLs() []string {
	return s.Config().Endpoints()
}

// Start initializes and starts a Server listening on addr
// If s was not initialized with NewServer(), addr defaults
// to localhost:0 to let the OS select a random port
func (s *serverImpl) Start(ctx context.Context) error {
	var err error

	if len(s.Config().Endpoints()) == 0 {
		return fmt.Errorf("cannot start server: no endpoints defined")
	}
	if err := validateConfiguredSecureEndpoints(s.cfg); err != nil {
		return err
	}

	// Register all service handlers
	s.initHandlers()

	if s.url == "" {
		s.url = defaultListenAddr
	}
	s.l, err = uacp.Listen(ctx, s.url, nil)
	if err != nil {
		return err
	}

	ualog.Info(ctx, "started listening", ualog.Any("urls", s.URLs()))

	s.initEndpoints()
	s.setServerState(ua.ServerStateRunning)

	if s.cb == nil {
		s.cb = newChannelBroker()
	}

	runCtx, runCancel := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.runCancel = runCancel
	s.mu.Unlock()

	s.runWG.Add(2)
	go func() {
		defer s.runWG.Done()
		s.acceptAndRegister(runCtx, s.l)
	}()
	go func() {
		defer s.runWG.Done()
		s.monitorConnections(runCtx)
	}()

	return nil
}

func validateConfiguredSecureEndpoints(cfg *serverConfig) error {
	for _, sec := range cfg.enabledSec {
		switch {
		case sec.secPolicy == SecurityPolicyNone && sec.secMode != ua.MessageSecurityModeNone:
			return fmt.Errorf(
				"cannot start server: invalid secure endpoint config: security policy %q cannot be used with %q",
				sec.secPolicy.URI(),
				sec.secMode,
			)
		case sec.secPolicy != SecurityPolicyNone &&
			sec.secMode != ua.MessageSecurityModeSign &&
			sec.secMode != ua.MessageSecurityModeSignAndEncrypt:
			return fmt.Errorf(
				"cannot start server: invalid secure endpoint config: security policy %q can only be used with %q or %q",
				sec.secPolicy.URI(),
				ua.MessageSecurityModeSign,
				ua.MessageSecurityModeSignAndEncrypt,
			)
		case sec.secPolicy == SecurityPolicyNone:
			continue
		case len(cfg.certificate) == 0:
			return errors.New("cannot start server: secure endpoints require a certificate")
		case cfg.privateKey == nil:
			return errors.New("cannot start server: secure endpoints require a private key")
		}
	}
	return nil
}

func (s *serverImpl) setServerState(state ua.ServerState) {
	s.mu.Lock()
	s.status.State = state
	s.mu.Unlock()
}

func (s *serverImpl) channelBrokerCloseTimeout() time.Duration {
	if s.cfg == nil || s.cfg.channelBrokerCloseTimeout <= 0 {
		return defaultChannelBrokerCloseTimeout
	}
	return s.cfg.channelBrokerCloseTimeout
}

// Close gracefully shuts the server down by closing all open connections,
// and stops listening on all endpoints
func (s *serverImpl) Close(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		s.setServerState(ua.ServerStateShutdown)

		s.mu.Lock()
		runCancel := s.runCancel
		s.runCancel = nil
		s.mu.Unlock()
		if runCancel != nil {
			runCancel()
		}

		// Close the listener, preventing new sessions from starting
		if s.l != nil {
			_ = s.l.Close()
		}

		if s.SubscriptionService != nil {
			if stopErr := s.SubscriptionService.Shutdown(ctx); stopErr != nil && err == nil {
				err = stopErr
			}
		}

		// Shut down all secure channels and UACP connections
		if s.cb != nil {
			if closeErr := s.cb.Close(ctx, s.channelBrokerCloseTimeout()); closeErr != nil && err == nil {
				err = closeErr
			}
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.runWG.Wait()
		}()

		select {
		case <-done:
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
		}
	})

	return err
}

func (s *serverImpl) CloseSession(ctx context.Context, authToken *ua.NodeID) error {
	return s.sb.Close(ctx, authToken)
}

type temporary interface {
	Temporary() bool
}

func (s *serverImpl) acceptAndRegister(ctx context.Context, l *uacp.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c, err := l.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				switch x := err.(type) {
				case *net.OpError:
					ualog.Warn(ctx, "listener stopped accepting", ualog.Err(err))
					return
				case temporary:
					if x.Temporary() {
						continue
					}
				default:
					ualog.Error(ctx, "error accepting connection", ualog.Err(err))
					continue
				}
			}

			go s.cb.RegisterConn(ctx, l.Endpoint(), c, s.Config().Certificate(), s.Config().PrivateKey(), slices.Clone(s.cfg.enabledSec))

			ualog.Info(ctx, "registered connection",
				ualog.String("remote", c.RemoteAddr().String()),
			)
		}
	}
}

// monitorConnections reads messages off the secure channel connection and
// sends the message to the service handler
func (s *serverImpl) monitorConnections(ctx context.Context) {

	for ctx.Err() == nil {
		msg := s.cb.ReadMessage(ctx)
		if msg == nil {
			continue // ctx is likely done, ctx.Err will be non-nil
		}
		if msg.Err != nil {
			ualog.Error(ctx, "error received",
				ualog.String("func", "monitorConnections"),
				ualog.Err(msg.Err),
			)
			if msg.SecureChannelID != 0 {
				s.cb.CloseSecureChannel(ctx, msg.SecureChannelID)
			}
			continue
		}
		if resp := msg.Response(); resp != nil {
			ualog.Error(ctx, "server received response", ualog.Any("response", resp))
			if msg.SecureChannelID != 0 {
				s.cb.CloseSecureChannel(ctx, msg.SecureChannelID)
			}
			continue
		}

		ualog.Debug(ctx, "received message",
			ualog.String("func", "monitorConnections"),
			ualog.Any("request", msg.Request()),
		)

		s.cb.mu.RLock()
		sc, ok := s.cb.s[msg.SecureChannelID]
		s.cb.mu.RUnlock()
		if !ok {
			// if the secure channel ID is 0, this is probably a open secure channel request.
			if msg.SecureChannelID != 0 {
				ualog.Error(ctx, "unknown secure channel",
					ualog.Uint64("channel_id", uint64(msg.SecureChannelID)),
				)
			}
			continue
		}

		// todo: should this be delegated to another goroutine in case handling this hangs?
		s.handleService(ctx, sc, msg.RequestID, msg.Request())
	}
}

// initEndpoints builds the endpoint list from the server's configuration
func (s *serverImpl) initEndpoints() {
	var endpoints []*ua.EndpointDescription
	for _, sec := range s.cfg.enabledSec {
		for _, url := range s.cfg.endpoints {
			secLevel := uapolicy.SecurityLevel(sec.secPolicy.URI(), sec.secMode)

			ep := &ua.EndpointDescription{
				EndpointURL:   url, // todo: be able to listen on multiple adapters
				SecurityLevel: secLevel,
				Server: &ua.ApplicationDescription{
					ApplicationURI:      s.cfg.applicationURI,
					ProductURI:          "urn:github.com:gopcua:server",
					ApplicationName:     ua.NewLocalizedText(s.cfg.applicationName),
					ApplicationType:     ua.ApplicationTypeServer,
					GatewayServerURI:    "",
					DiscoveryProfileURI: "",
					DiscoveryURLs:       s.URLs(),
				},
				ServerCertificate:   s.cfg.certificate,
				SecurityMode:        sec.secMode,
				SecurityPolicyURI:   sec.secPolicy.URI(),
				TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
			}

			for _, auth := range s.cfg.enabledAuth {
				for _, authSec := range s.cfg.enabledSec {
					if auth.tokenType == ua.UserTokenTypeAnonymous {
						authSec.secPolicy = SecurityPolicyNone
					}

					if auth.tokenType != ua.UserTokenTypeAnonymous && authSec.secPolicy == SecurityPolicyNone {
						continue
					}

					policyID := strings.ToLower(
						strings.TrimPrefix(auth.tokenType.String(), "UserTokenType") +
							"_" +
							strings.TrimPrefix(authSec.secPolicy.URI(), "http://opcfoundation.org/UA/SecurityPolicy#"),
					)

					var dup bool
					for _, uit := range ep.UserIdentityTokens {
						if uit.PolicyID == policyID {
							dup = true
							break
						}
					}

					if dup {
						continue
					}

					tok := &ua.UserTokenPolicy{
						PolicyID:          policyID,
						TokenType:         auth.tokenType,
						IssuedTokenType:   "",
						IssuerEndpointURL: "",
						SecurityPolicyURI: authSec.secPolicy.URI(),
					}

					ep.UserIdentityTokens = append(ep.UserIdentityTokens, tok)
				}
			}
			endpoints = append(endpoints, ep)
		}
	}

	s.mu.Lock()
	s.endpoints = endpoints
	s.mu.Unlock()
}

func (s *serverImpl) Node(nid *ua.NodeID) types.Node {
	ns := int(nid.Namespace())
	if ns < len(s.namespaces) {
		return s.namespaces[ns].Node(nid)
	}
	return nil
}
