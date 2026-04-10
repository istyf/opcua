package services

import (
	"context"
	"net"
	"testing"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

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

	resp, err := service.CreateSubscription(context.Background(), sc, req, 1)
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

	resp, err := service.CreateSubscription(context.Background(), sc, req, 1)
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

	service.DeleteSubscription(context.Background(), sub.ID)
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

	_, _ = service.CreateSubscription(context.Background(), nil, req, 1)
}

type subscriptionTestBackend struct {
	handlers map[int]Handler
	session  types.Session
}

func newSubscriptionTestBackend(session types.Session) *subscriptionTestBackend {
	return &subscriptionTestBackend{
		handlers: make(map[int]Handler),
		session:  session,
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
