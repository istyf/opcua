package services

import (
	"context"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

func TestCreateSubscriptionRevisesPublishingInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		minimum   time.Duration
		requested float64
		want      float64
	}{
		{name: "negative uses default fastest supported", requested: -1, want: defaultMinSupportedPublishingIntervalMS},
		{name: "zero uses default fastest supported", requested: 0, want: defaultMinSupportedPublishingIntervalMS},
		{name: "below default minimum clamps to fastest supported", requested: 250, want: defaultMinSupportedPublishingIntervalMS},
		{name: "above default minimum is preserved", requested: 1500, want: 1500},
		{name: "configured minimum is used for zero request", minimum: 200 * time.Millisecond, requested: 0, want: 200},
		{name: "configured minimum clamps positive request", minimum: 200 * time.Millisecond, requested: 150, want: 200},
		{name: "configured minimum preserves larger request", minimum: 200 * time.Millisecond, requested: 350, want: 350},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := newSubscriptionTestSession()
			backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
				minSubscriptionPublishingInterval: tt.minimum,
			})
			service := NewSubscriptionService(backend)
			sc := newTestSecureChannel(t)

			req := newCreateSubscriptionRequest(session, 10)
			req.RequestedPublishingInterval = tt.requested

			resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			if !ok {
				t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
			}
			if createResp.RevisedPublishingInterval != tt.want {
				t.Fatalf("expected revised publishing interval %v, got %v", tt.want, createResp.RevisedPublishingInterval)
			}

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
	}
}

func TestCreateSubscriptionRevisesMaxKeepAliveCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		minimum   uint32
		requested uint32
		want      uint32
	}{
		{name: "zero uses default smallest supported", requested: 0, want: DefaultMinSubscriptionMaxKeepAliveCount},
		{name: "below default minimum clamps to default", requested: 1, want: DefaultMinSubscriptionMaxKeepAliveCount},
		{name: "configured minimum is used for zero request", minimum: 3, requested: 0, want: 3},
		{name: "configured minimum clamps smaller request", minimum: 3, requested: 1, want: 3},
		{name: "configured minimum preserves larger request", minimum: 3, requested: 5, want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := newSubscriptionTestSession()
			backend := newSubscriptionTestBackend(session, subscriptionTestConfigOptions{
				minSubscriptionMaxKeepAliveCount: tt.minimum,
			})
			service := NewSubscriptionService(backend)
			sc := newTestSecureChannel(t)

			req := newCreateSubscriptionRequest(session, 12)
			req.RequestedMaxKeepAliveCount = tt.requested

			resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}

			createResp, ok := resp.(*ua.CreateSubscriptionResponse)
			if !ok {
				t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
			}
			if createResp.RevisedMaxKeepAliveCount != tt.want {
				t.Fatalf("expected revised max keepalive count %d, got %d", tt.want, createResp.RevisedMaxKeepAliveCount)
			}

			service.DeleteSubscription(t.Context(), types.SubscriptionID(createResp.SubscriptionID))
		})
	}
}

func TestCreateSubscriptionRejectsMissingSession(t *testing.T) {
	t.Parallel()

	backend := newSubscriptionTestBackend(nil)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       11,
			AuthenticationToken: ua.NewNumericNodeID(1, 999),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
	if resp != nil {
		t.Fatalf("expected nil response, got %T", resp)
	}
	if err != ua.StatusBadSessionIDInvalid {
		t.Fatalf("expected %v, got %v", ua.StatusBadSessionIDInvalid, err)
	}
	if got := len(service.subs); got != 0 {
		t.Fatalf("expected no subscriptions to be created, got %d", got)
	}
}

func TestCreateSubscriptionCreatesSubscriptionForValidSession(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       22,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	resp, err := service.CreateSubscription(t.Context(), sc, req, 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	createResp, ok := resp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", resp)
	}
	if createResp.SubscriptionID == 0 {
		t.Fatal("expected non-zero subscription ID")
	}
	if createResp.ResponseHeader == nil || createResp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("expected status %v, got %#v", ua.StatusOK, createResp.ResponseHeader)
	}

	sub, ok := service.Get(types.SubscriptionID(createResp.SubscriptionID))
	if !ok {
		t.Fatal("expected subscription to be registered")
	}
	if sub.session != session {
		t.Fatal("expected created subscription to keep the resolved session")
	}

	service.DeleteSubscription(t.Context(), sub.ID)
}

func TestCreateSubscriptionPanicsWithoutSecureChannel(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)

	req := &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       33,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected CreateSubscription to panic when secure channel is nil")
		}
	}()

	_, _ = service.CreateSubscription(t.Context(), nil, req, 1)
}

func TestCreateSubscriptionDoesNotReuseDeletedIDs(t *testing.T) {
	t.Parallel()

	session := newSubscriptionTestSession()
	backend := newSubscriptionTestBackend(session)
	service := NewSubscriptionService(backend)
	sc := newTestSecureChannel(t)

	firstResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 44), 1)
	if err != nil {
		t.Fatalf("create first subscription: %v", err)
	}
	firstCreateResp, ok := firstResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", firstResp)
	}

	firstID := types.SubscriptionID(firstCreateResp.SubscriptionID)
	service.DeleteSubscription(t.Context(), firstID)

	secondResp, err := service.CreateSubscription(t.Context(), sc, newCreateSubscriptionRequest(session, 45), 2)
	if err != nil {
		t.Fatalf("create second subscription: %v", err)
	}
	secondCreateResp, ok := secondResp.(*ua.CreateSubscriptionResponse)
	if !ok {
		t.Fatalf("expected CreateSubscriptionResponse, got %T", secondResp)
	}

	if secondCreateResp.SubscriptionID == firstCreateResp.SubscriptionID {
		t.Fatalf("expected a new subscription id, got reused id %d", secondCreateResp.SubscriptionID)
	}
	if secondCreateResp.SubscriptionID <= firstCreateResp.SubscriptionID {
		t.Fatalf("expected monotonic subscription ids, got first=%d second=%d", firstCreateResp.SubscriptionID, secondCreateResp.SubscriptionID)
	}

	service.DeleteSubscription(t.Context(), types.SubscriptionID(secondCreateResp.SubscriptionID))
}

type subscriptionTestBackend struct {
	handlers map[int]Handler
	session  types.Session
	cfg      types.ServerConfig
}

type subscriptionTestConfigOptions struct {
	minSubscriptionPublishingInterval time.Duration
	minSubscriptionMaxKeepAliveCount  uint32
}

func newSubscriptionTestBackend(session types.Session, options ...subscriptionTestConfigOptions) *subscriptionTestBackend {
	cfg := subscriptionTestConfig{
		minSubscriptionPublishingInterval: DefaultMinSubscriptionPublishingInterval,
		minSubscriptionMaxKeepAliveCount:  DefaultMinSubscriptionMaxKeepAliveCount,
	}
	if len(options) != 0 {
		if options[0].minSubscriptionPublishingInterval > 0 {
			cfg.minSubscriptionPublishingInterval = options[0].minSubscriptionPublishingInterval
		}
		if options[0].minSubscriptionMaxKeepAliveCount > 0 {
			cfg.minSubscriptionMaxKeepAliveCount = options[0].minSubscriptionMaxKeepAliveCount
		}
	}

	return &subscriptionTestBackend{
		handlers: make(map[int]Handler),
		session:  session,
		cfg:      cfg,
	}
}

func (b *subscriptionTestBackend) RegisterHandler(typeID int, h Handler) {
	b.handlers[typeID] = h
}

func (b *subscriptionTestBackend) Namespace(int) (types.NameSpace, error) {
	return nil, nil
}

func (b *subscriptionTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
}

func (b *subscriptionTestBackend) DeleteSubscription(types.SubscriptionID) {}

func (b *subscriptionTestBackend) Config() types.ServerConfig {
	return b.cfg
}

type subscriptionTestSession struct {
	authToken    *ua.NodeID
	id           *ua.NodeID
	locales      []string
	remoteCert   []byte
	serverNonce  []byte
	timeoutMs    float64
	publishQueue chan types.PubReq
}

func newSubscriptionTestSession() *subscriptionTestSession {
	return &subscriptionTestSession{
		authToken:    ua.NewNumericNodeID(1, 101),
		id:           ua.NewNumericNodeID(1, 202),
		timeoutMs:    60000,
		publishQueue: make(chan types.PubReq, 1),
	}
}

func (s *subscriptionTestSession) AuthTokenID() *ua.NodeID {
	return s.authToken
}

func (s *subscriptionTestSession) ID() *ua.NodeID {
	return s.id
}

func (s *subscriptionTestSession) Locales() []string {
	return s.locales
}

func (s *subscriptionTestSession) SetLocales(locales []string) {
	s.locales = locales
}

func (s *subscriptionTestSession) RemoteCertificate() []byte {
	return s.remoteCert
}

func (s *subscriptionTestSession) ServerNonce() []byte {
	return s.serverNonce
}

func (s *subscriptionTestSession) SetServerNonce(nonce []byte) {
	s.serverNonce = nonce
}

func (s *subscriptionTestSession) TimeOutInMillis() float64 {
	return s.timeoutMs
}

func (s *subscriptionTestSession) IsSameAs(other types.Session) bool {
	return other != nil && s.authToken.String() == other.AuthTokenID().String()
}

func (s *subscriptionTestSession) PublishRequestChannel() chan types.PubReq {
	return s.publishQueue
}

type subscriptionTestConfig struct {
	minSubscriptionPublishingInterval time.Duration
	minSubscriptionMaxKeepAliveCount  uint32
}

func (cfg subscriptionTestConfig) Certificate() []byte {
	return nil
}

func (cfg subscriptionTestConfig) Endpoints() []string {
	return nil
}

func (cfg subscriptionTestConfig) PrivateKey() *rsa.PrivateKey {
	return nil
}

func (cfg subscriptionTestConfig) ApplicationURI() string {
	return ""
}

func (cfg subscriptionTestConfig) ManufacturerName() string {
	return ""
}

func (cfg subscriptionTestConfig) ProductName() string {
	return ""
}

func (cfg subscriptionTestConfig) SoftwareVersion() string {
	return ""
}

func (cfg subscriptionTestConfig) MaxNodesPerRead() uint32 {
	return 0
}

func (cfg subscriptionTestConfig) MinSubscriptionPublishingInterval() time.Duration {
	return cfg.minSubscriptionPublishingInterval
}

func (cfg subscriptionTestConfig) MinSubscriptionMaxKeepAliveCount() uint32 {
	return cfg.minSubscriptionMaxKeepAliveCount
}

func (cfg subscriptionTestConfig) MethodCallMiddleware() types.MethodMiddleware {
	return func(fn types.MethodFunc) types.MethodFunc {
		return fn
	}
}

func newCreateSubscriptionRequest(session *subscriptionTestSession, handle uint32) *ua.CreateSubscriptionRequest {
	return &ua.CreateSubscriptionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       handle,
			AuthenticationToken: session.AuthTokenID(),
		},
		RequestedPublishingInterval: 250,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
	}
}

func newTestSecureChannel(t *testing.T) *uasc.SecureChannel {
	t.Helper()

	sc, err := uasc.NewSecureChannel(
		"opc.tcp://127.0.0.1:4840",
		&uacp.Conn{TCPConn: new(net.TCPConn)},
		&uasc.Config{
			SecurityPolicyURI: ua.SecurityPolicyURINone,
			SecurityMode:      ua.MessageSecurityModeNone,
		},
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("new secure channel: %v", err)
	}

	return sc
}
