package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

func TestActivateSessionStoresAuthenticatedUser(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	authenticated := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
	}
	session := newSessionServiceTestSession()
	backend := &sessionServiceTestBackend{
		session: session,
		endpoints: []*ua.EndpointDescription{{
			UserIdentityTokens: []*ua.UserTokenPolicy{{
				PolicyID:          "username_basic256sha256",
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			}},
		}},
		cfg: sessionServiceTestConfig{
			privateKey: serverKey,
			authenticator: func(_ context.Context, req *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				if req.SessionID == nil || req.SessionID.String() != session.ID().String() {
					t.Fatalf("expected session id %q, got %#v", session.ID(), req.SessionID)
				}
				if req.AuthenticationToken == nil || req.AuthenticationToken.String() != session.AuthTokenID().String() {
					t.Fatalf("expected auth token %q, got %#v", session.AuthTokenID(), req.AuthenticationToken)
				}
				if req.UserName != "alice" {
					t.Fatalf("expected username %q, got %q", "alice", req.UserName)
				}
				if req.Password != "secret" {
					t.Fatalf("expected password %q, got %q", "secret", req.Password)
				}
				return authenticated, nil
			},
		},
	}

	service := NewSessionService(backend, nil)
	sc := newSessionServiceTestSecureChannel(t)

	req := &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       42,
			AuthenticationToken: session.AuthTokenID(),
		},
		LocaleIDs:       []string{"sv-SE"},
		ClientSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			PolicyID:            "username_basic256sha256",
			UserName:            "alice",
			Password:            encryptSessionServiceTestPassword(t, serverKey, ua.SecurityPolicyURIBasic256Sha256, "secret", session.ServerNonce()),
			EncryptionAlgorithm: mustSessionServiceDecryptOnlyAlgorithm(t, serverKey, ua.SecurityPolicyURIBasic256Sha256).EncryptionURI(),
		}),
	}

	resp, err := service.ActivateSession(t.Context(), sc, req, 0)
	if err != nil {
		t.Fatalf("activate session: %v", err)
	}

	activateResp, ok := resp.(*ua.ActivateSessionResponse)
	if !ok {
		t.Fatalf("expected *ua.ActivateSessionResponse, got %T", resp)
	}
	if activateResp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("expected service result %v, got %v", ua.StatusOK, activateResp.ResponseHeader.ServiceResult)
	}
	if !session.Activated() {
		t.Fatal("expected session to be marked activated")
	}
	if session.AuthenticatedUser() != authenticated {
		t.Fatalf("expected authenticated user %#v, got %#v", authenticated, session.AuthenticatedUser())
	}
	if len(session.Locales()) == 0 || session.Locales()[0] != "sv-SE" {
		t.Fatalf("expected locales to be updated, got %#v", session.Locales())
	}
	if string(session.ServerNonce()) == string([]byte("12345678901234567890123456789012")) {
		t.Fatal("expected server nonce to rotate on activation")
	}
}

func TestActivateSessionAnonymousClearsAuthenticatedUser(t *testing.T) {
	t.Parallel()

	session := newSessionServiceTestSession()
	session.SetAuthenticatedUser(&auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
	})

	backend := &sessionServiceTestBackend{
		session: session,
		endpoints: []*ua.EndpointDescription{{
			UserIdentityTokens: []*ua.UserTokenPolicy{{
				PolicyID:          "anonymous_none",
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			}},
		}},
		cfg: sessionServiceTestConfig{},
	}

	service := NewSessionService(backend, nil)
	sc := newSessionServiceTestSecureChannel(t)

	req := &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       7,
			AuthenticationToken: session.AuthTokenID(),
		},
		ClientSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.AnonymousIdentityToken{
			PolicyID: "anonymous_none",
		}),
	}

	resp, err := service.ActivateSession(t.Context(), sc, req, 0)
	if err != nil {
		t.Fatalf("activate session: %v", err)
	}

	if _, ok := resp.(*ua.ActivateSessionResponse); !ok {
		t.Fatalf("expected *ua.ActivateSessionResponse, got %T", resp)
	}
	if session.AuthenticatedUser() != nil {
		t.Fatalf("expected anonymous activation to clear authenticated user, got %#v", session.AuthenticatedUser())
	}
	if !session.Activated() {
		t.Fatal("expected session to remain activated after anonymous activation")
	}
}

func TestActivateSessionAnonymousSucceedsAlongsideUserNamePolicy(t *testing.T) {
	t.Parallel()

	session := newSessionServiceTestSession()
	backend := &sessionServiceTestBackend{
		session: session,
		endpoints: []*ua.EndpointDescription{{
			UserIdentityTokens: []*ua.UserTokenPolicy{
				{
					PolicyID:          "anonymous_none",
					TokenType:         ua.UserTokenTypeAnonymous,
					SecurityPolicyURI: ua.SecurityPolicyURINone,
				},
				{
					PolicyID:          "username_basic256sha256",
					TokenType:         ua.UserTokenTypeUserName,
					SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
				},
			},
		}},
		cfg: sessionServiceTestConfig{
			authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				t.Fatal("did not expect anonymous activation to call the username authenticator")
				return nil, nil
			},
		},
	}

	service := NewSessionService(backend, nil)
	sc := newSessionServiceTestSecureChannel(t)

	req := &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       8,
			AuthenticationToken: session.AuthTokenID(),
		},
		ClientSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.AnonymousIdentityToken{
			PolicyID: "anonymous_none",
		}),
	}

	resp, err := service.ActivateSession(t.Context(), sc, req, 0)
	if err != nil {
		t.Fatalf("activate session: %v", err)
	}

	activateResp, ok := resp.(*ua.ActivateSessionResponse)
	if !ok {
		t.Fatalf("expected *ua.ActivateSessionResponse, got %T", resp)
	}
	if activateResp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("expected service result %v, got %v", ua.StatusOK, activateResp.ResponseHeader.ServiceResult)
	}
	if !session.Activated() {
		t.Fatal("expected session to be marked activated")
	}
	if session.AuthenticatedUser() != nil {
		t.Fatalf("expected anonymous activation to leave authenticated user unset, got %#v", session.AuthenticatedUser())
	}
}

func TestActivateSessionReactivationReplacesAuthenticatedUser(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	users := map[string]*auth.AuthenticatedUser{
		"alice": {UserName: "alice", Subject: "user:alice"},
		"bob":   {UserName: "bob", Subject: "user:bob"},
	}

	session := newSessionServiceTestSession()
	backend := &sessionServiceTestBackend{
		session: session,
		endpoints: []*ua.EndpointDescription{{
			UserIdentityTokens: []*ua.UserTokenPolicy{{
				PolicyID:          "username_basic256sha256",
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			}},
		}},
		cfg: sessionServiceTestConfig{
			privateKey: serverKey,
			authenticator: func(_ context.Context, req *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				return users[req.UserName], nil
			},
		},
	}

	service := NewSessionService(backend, nil)
	sc := newSessionServiceTestSecureChannel(t)
	decryptOnly := mustSessionServiceDecryptOnlyAlgorithm(t, serverKey, ua.SecurityPolicyURIBasic256Sha256)

	activate := func(t *testing.T, userName, password string) {
		t.Helper()

		req := &ua.ActivateSessionRequest{
			RequestHeader: &ua.RequestHeader{
				RequestHandle:       99,
				AuthenticationToken: session.AuthTokenID(),
			},
			ClientSignature: &ua.SignatureData{},
			UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            userName,
				Password:            encryptSessionServiceTestPassword(t, serverKey, ua.SecurityPolicyURIBasic256Sha256, password, session.ServerNonce()),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			}),
		}

		if _, err := service.ActivateSession(t.Context(), sc, req, 0); err != nil {
			t.Fatalf("activate session as %s: %v", userName, err)
		}
	}

	activate(t, "alice", "first-secret")
	if session.AuthenticatedUser() != users["alice"] {
		t.Fatalf("expected first activation to store %#v, got %#v", users["alice"], session.AuthenticatedUser())
	}

	activate(t, "bob", "second-secret")
	if session.AuthenticatedUser() != users["bob"] {
		t.Fatalf("expected reactivation to replace authenticated user with %#v, got %#v", users["bob"], session.AuthenticatedUser())
	}
}

type sessionServiceTestBackend struct {
	cfg       sessionServiceTestConfig
	endpoints []*ua.EndpointDescription
	session   *sessionServiceTestSession
}

func (*sessionServiceTestBackend) RegisterHandler(int, Handler) {}

func (b *sessionServiceTestBackend) Endpoints() []*ua.EndpointDescription { return b.endpoints }

func (b *sessionServiceTestBackend) Config() types.ServerConfig { return b.cfg }

func (*sessionServiceTestBackend) NewSession(time.Duration, []byte, []byte) types.Session { return nil }

func (b *sessionServiceTestBackend) Session(context.Context, *ua.RequestHeader) types.Session {
	return b.session
}

func (*sessionServiceTestBackend) CloseSession(context.Context, *ua.NodeID) error { return nil }

type sessionServiceTestSession struct {
	authToken *ua.NodeID
	id        *ua.NodeID
	locales   []string
	nonce     []byte
	active    bool
	user      *auth.AuthenticatedUser
}

func newSessionServiceTestSession() *sessionServiceTestSession {
	return &sessionServiceTestSession{
		authToken: ua.NewNumericNodeID(1, 101),
		id:        ua.NewNumericNodeID(1, 202),
		locales:   []string{"en"},
		nonce:     []byte("12345678901234567890123456789012"),
	}
}

func (s *sessionServiceTestSession) AuthTokenID() *ua.NodeID     { return s.authToken }
func (s *sessionServiceTestSession) ID() *ua.NodeID              { return s.id }
func (s *sessionServiceTestSession) Locales() []string           { return s.locales }
func (s *sessionServiceTestSession) SetLocales(locales []string) { s.locales = locales }
func (s *sessionServiceTestSession) RemoteCertificate() []byte   { return nil }
func (s *sessionServiceTestSession) ServerNonce() []byte         { return s.nonce }
func (s *sessionServiceTestSession) SetServerNonce(nonce []byte) { s.nonce = nonce }
func (s *sessionServiceTestSession) TimeOutInMillis() float64    { return 60000 }
func (s *sessionServiceTestSession) Activated() bool             { return s.active }
func (s *sessionServiceTestSession) SetActivated(active bool)    { s.active = active }
func (s *sessionServiceTestSession) IsSameAs(other types.Session) bool {
	return other != nil && s.authToken.String() == other.AuthTokenID().String()
}
func (s *sessionServiceTestSession) AuthenticatedUser() *auth.AuthenticatedUser { return s.user }
func (s *sessionServiceTestSession) PublishRequestChannel() chan types.PubReq   { return nil }
func (s *sessionServiceTestSession) SetAuthenticatedUser(user *auth.AuthenticatedUser) {
	s.user = user
}

type sessionServiceTestConfig struct {
	privateKey    *rsa.PrivateKey
	authenticator auth.UserNameAuthenticator
}

func (cfg sessionServiceTestConfig) Certificate() []byte         { return nil }
func (cfg sessionServiceTestConfig) Endpoints() []string         { return nil }
func (cfg sessionServiceTestConfig) PrivateKey() *rsa.PrivateKey { return cfg.privateKey }
func (cfg sessionServiceTestConfig) UserNameAuthenticator() auth.UserNameAuthenticator {
	return cfg.authenticator
}
func (cfg sessionServiceTestConfig) ApplicationURI() string                           { return "" }
func (cfg sessionServiceTestConfig) ManufacturerName() string                         { return "" }
func (cfg sessionServiceTestConfig) ProductName() string                              { return "" }
func (cfg sessionServiceTestConfig) SoftwareVersion() string                          { return "" }
func (cfg sessionServiceTestConfig) MaxNodesPerRead() uint32                          { return 0 }
func (cfg sessionServiceTestConfig) MaxBrowseOperationsPerCall() uint32               { return 0 }
func (cfg sessionServiceTestConfig) MaxBrowseContinuationPoints() uint32              { return 0 }
func (cfg sessionServiceTestConfig) MaxSubscriptions() uint32                         { return 0 }
func (cfg sessionServiceTestConfig) MaxSubscriptionsPerSession() uint32               { return 0 }
func (cfg sessionServiceTestConfig) MaxSubscriptionOperationsPerCall() uint32         { return 0 }
func (cfg sessionServiceTestConfig) MinSubscriptionPublishingInterval() time.Duration { return 0 }
func (cfg sessionServiceTestConfig) MinSubscriptionMaxKeepAliveCount() uint32         { return 0 }
func (cfg sessionServiceTestConfig) MinSubscriptionLifetimeCount() uint32             { return 0 }
func (cfg sessionServiceTestConfig) MethodCallMiddleware() types.MethodMiddleware     { return nil }

func newSessionServiceTestSecureChannel(t *testing.T) *uasc.SecureChannel {
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

func mustSessionServiceDecryptOnlyAlgorithm(t *testing.T, privateKey *rsa.PrivateKey, policyURI string) *uapolicy.EncryptionAlgorithm {
	t.Helper()

	algo, err := uapolicy.Asymmetric(policyURI, privateKey, nil)
	if err != nil {
		t.Fatalf("build decrypt-only algorithm: %v", err)
	}
	return algo
}

func encryptSessionServiceTestPassword(t *testing.T, privateKey *rsa.PrivateKey, policyURI, password string, nonce []byte) []byte {
	t.Helper()

	algo, err := uapolicy.Asymmetric(policyURI, nil, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("build encrypt-only algorithm: %v", err)
	}

	secret := make([]byte, 4)
	binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
	secret = append(secret, []byte(password)...)
	secret = append(secret, nonce...)

	encrypted, err := algo.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt password: %v", err)
	}

	return encrypted
}
