package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActivateSessionStoresAuthenticatedUser(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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
				require.NotNil(t, req.SessionID)
				require.NotNil(t, req.AuthenticationToken)
				assert.Equal(t, session.ID().String(), req.SessionID.String())
				assert.Equal(t, session.AuthTokenID().String(), req.AuthenticationToken.String())
				assert.Equal(t, "alice", req.UserName)
				assert.Equal(t, "secret", req.Password)
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
	require.NoError(t, err)

	activateResp, ok := resp.(*ua.ActivateSessionResponse)
	require.True(t, ok, "expected *ua.ActivateSessionResponse, got %T", resp)
	assert.Equal(t, ua.StatusOK, activateResp.ResponseHeader.ServiceResult)
	assert.True(t, session.Activated())
	assert.Same(t, authenticated, session.AuthenticatedUser())
	require.NotEmpty(t, session.Locales())
	assert.Equal(t, "sv-SE", session.Locales()[0])
	assert.NotEqual(t, string([]byte("12345678901234567890123456789012")), string(session.ServerNonce()))
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
	require.NoError(t, err)

	require.IsType(t, &ua.ActivateSessionResponse{}, resp)
	assert.Nil(t, session.AuthenticatedUser())
	assert.True(t, session.Activated())
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
				assert.Fail(t, "did not expect anonymous activation to call the username authenticator")
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
	require.NoError(t, err)

	activateResp, ok := resp.(*ua.ActivateSessionResponse)
	require.True(t, ok, "expected *ua.ActivateSessionResponse, got %T", resp)
	assert.Equal(t, ua.StatusOK, activateResp.ResponseHeader.ServiceResult)
	assert.True(t, session.Activated())
	assert.Nil(t, session.AuthenticatedUser())
}

func TestActivateSessionReactivationReplacesAuthenticatedUser(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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

		_, err := service.ActivateSession(t.Context(), sc, req, 0)
		require.NoError(t, err)
	}

	activate(t, "alice", "first-secret")
	assert.Same(t, users["alice"], session.AuthenticatedUser())

	activate(t, "bob", "second-secret")
	assert.Same(t, users["bob"], session.AuthenticatedUser())
}

func TestActivateSessionRejectsFailurePaths(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		backend *sessionServiceTestBackend
		req     *ua.ActivateSessionRequest
		wantErr error
	}{
		{
			name: "missing session",
			backend: &sessionServiceTestBackend{
				endpoints: []*ua.EndpointDescription{{
					UserIdentityTokens: []*ua.UserTokenPolicy{{
						PolicyID:          "anonymous_none",
						TokenType:         ua.UserTokenTypeAnonymous,
						SecurityPolicyURI: ua.SecurityPolicyURINone,
					}},
				}},
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       1,
					AuthenticationToken: ua.NewNumericNodeID(1, 999),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.AnonymousIdentityToken{
					PolicyID: "anonymous_none",
				}),
			},
			wantErr: ua.StatusBadSessionIDInvalid,
		},
		{
			name: "no username authenticator configured",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
				endpoints: []*ua.EndpointDescription{{
					UserIdentityTokens: []*ua.UserTokenPolicy{{
						PolicyID:          "username_none",
						TokenType:         ua.UserTokenTypeUserName,
						SecurityPolicyURI: ua.SecurityPolicyURINone,
					}},
				}},
				cfg: sessionServiceTestConfig{},
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       2,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
					PolicyID: "username_none",
					UserName: "alice",
					Password: []byte("secret"),
				}),
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "invalid credentials",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
				endpoints: []*ua.EndpointDescription{{
					UserIdentityTokens: []*ua.UserTokenPolicy{{
						PolicyID:          "username_none",
						TokenType:         ua.UserTokenTypeUserName,
						SecurityPolicyURI: ua.SecurityPolicyURINone,
					}},
				}},
				cfg: sessionServiceTestConfig{
					authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
						return nil, auth.ErrInvalidCredentials
					},
				},
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       3,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
					PolicyID: "username_none",
					UserName: "alice",
					Password: []byte("secret"),
				}),
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "malformed token",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       4,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature:   &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(nil),
			},
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "unsupported token type",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       5,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.X509IdentityToken{
					PolicyID:        "x509_basic256sha256",
					CertificateData: []byte("cert"),
				}),
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "unknown token policy",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
				endpoints: []*ua.EndpointDescription{{
					UserIdentityTokens: []*ua.UserTokenPolicy{{
						PolicyID:          "username_none",
						TokenType:         ua.UserTokenTypeUserName,
						SecurityPolicyURI: ua.SecurityPolicyURINone,
					}},
				}},
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       6,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
					PolicyID: "username_unknown",
					UserName: "alice",
					Password: []byte("secret"),
				}),
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "decryption failure",
			backend: &sessionServiceTestBackend{
				session: newSessionServiceTestSession(),
				endpoints: []*ua.EndpointDescription{{
					UserIdentityTokens: []*ua.UserTokenPolicy{{
						PolicyID:          "username_basic256sha256",
						TokenType:         ua.UserTokenTypeUserName,
						SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
					}},
				}},
				cfg: sessionServiceTestConfig{
					privateKey: serverKey,
					authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
						assert.Fail(t, "did not expect malformed encrypted password to call authenticator")
						return nil, nil
					},
				},
			},
			req: &ua.ActivateSessionRequest{
				RequestHeader: &ua.RequestHeader{
					RequestHandle:       7,
					AuthenticationToken: ua.NewNumericNodeID(1, 101),
				},
				ClientSignature: &ua.SignatureData{},
				UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
					PolicyID:            "username_basic256sha256",
					UserName:            "alice",
					Password:            []byte("not-encrypted"),
					EncryptionAlgorithm: mustSessionServiceDecryptOnlyAlgorithm(t, serverKey, ua.SecurityPolicyURIBasic256Sha256).EncryptionURI(),
				}),
			},
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := NewSessionService(tt.backend, nil)
			sc := newSessionServiceTestSecureChannel(t)

			_, err := service.ActivateSession(t.Context(), sc, tt.req, 0)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestActivateSessionRejectsBadClientSignature(t *testing.T) {
	t.Parallel()

	serverCert, serverKey := mustSessionServiceTestCertificate(t, "urn:gopcua:test:server")
	clientCert, _ := mustSessionServiceTestCertificate(t, "urn:gopcua:test:client")

	session := newSessionServiceTestSession()
	session.remoteCert = clientCert

	backend := &sessionServiceTestBackend{
		session: session,
		endpoints: []*ua.EndpointDescription{{
			UserIdentityTokens: []*ua.UserTokenPolicy{{
				PolicyID:          "anonymous_none",
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			}},
		}},
	}

	service := NewSessionService(backend, serverCert)
	sc := newSessionServiceTestSecureChannelWithConfig(t, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSign,
		Certificate:       serverCert,
		LocalKey:          serverKey,
	})

	req := &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       10,
			AuthenticationToken: session.AuthTokenID(),
		},
		ClientSignature: &ua.SignatureData{Signature: []byte("bad-signature")},
		UserIdentityToken: ua.NewExtensionObject(&ua.AnonymousIdentityToken{
			PolicyID: "anonymous_none",
		}),
	}

	_, err := service.ActivateSession(t.Context(), sc, req, 0)
	assert.Equal(t, ua.StatusBadSecurityChecksFailed, err)
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
	if b.session == nil {
		return nil
	}
	return b.session
}

func (*sessionServiceTestBackend) CloseSession(context.Context, *ua.NodeID) error { return nil }

type sessionServiceTestSession struct {
	authToken  *ua.NodeID
	id         *ua.NodeID
	locales    []string
	nonce      []byte
	remoteCert []byte
	active     bool
	user       *auth.AuthenticatedUser
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
func (s *sessionServiceTestSession) RemoteCertificate() []byte   { return s.remoteCert }
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

	return newSessionServiceTestSecureChannelWithConfig(t, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
	})
}

func newSessionServiceTestSecureChannelWithConfig(t *testing.T, cfg *uasc.Config) *uasc.SecureChannel {
	t.Helper()

	sc, err := uasc.NewSecureChannel(
		"opc.tcp://127.0.0.1:4840",
		&uacp.Conn{TCPConn: new(net.TCPConn)},
		cfg,
		make(chan error, 1),
	)
	require.NoError(t, err)
	return sc
}

func mustSessionServiceDecryptOnlyAlgorithm(t *testing.T, privateKey *rsa.PrivateKey, policyURI string) *uapolicy.EncryptionAlgorithm {
	t.Helper()

	algo, err := uapolicy.Asymmetric(policyURI, privateKey, nil)
	require.NoError(t, err)
	return algo
}

func encryptSessionServiceTestPassword(t *testing.T, privateKey *rsa.PrivateKey, policyURI, password string, nonce []byte) []byte {
	t.Helper()

	algo, err := uapolicy.Asymmetric(policyURI, nil, &privateKey.PublicKey)
	require.NoError(t, err)

	secret := make([]byte, 4)
	binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
	secret = append(secret, []byte(password)...)
	secret = append(secret, nonce...)

	encrypted, err := algo.Encrypt(secret)
	require.NoError(t, err)

	return encrypted
}

func mustSessionServiceTestCertificate(t *testing.T, uri string) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: uri,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return der, priv
}
