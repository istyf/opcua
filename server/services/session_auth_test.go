package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeUserIdentityToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		token   *ua.ExtensionObject
		want    any
		wantErr error
	}{
		{
			name:    "nil token is invalid",
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
		{
			name:    "empty extension object is invalid",
			token:   ua.NewExtensionObject(nil),
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "anonymous token is accepted",
			token: ua.NewExtensionObject(&ua.AnonymousIdentityToken{
				PolicyID: "anonymous_none",
			}),
			want: &ua.AnonymousIdentityToken{
				PolicyID: "anonymous_none",
			},
		},
		{
			name: "username token is accepted",
			token: ua.NewExtensionObject(&ua.UserNameIdentityToken{
				PolicyID: "username_basic256sha256",
				UserName: "alice",
				Password: []byte("secret"),
			}),
			want: &ua.UserNameIdentityToken{
				PolicyID: "username_basic256sha256",
				UserName: "alice",
				Password: []byte("secret"),
			},
		},
		{
			name: "x509 token is rejected",
			token: ua.NewExtensionObject(&ua.X509IdentityToken{
				PolicyID:        "x509_basic256sha256",
				CertificateData: []byte("cert"),
			}),
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "issued token is rejected",
			token: ua.NewExtensionObject(&ua.IssuedIdentityToken{
				PolicyID:  "issued_basic256sha256",
				TokenData: []byte("token"),
			}),
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name:    "unknown token payload is invalid",
			token:   ua.NewExtensionObject(struct{}{}),
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeUserIdentityToken(tt.token)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			switch want := tt.want.(type) {
			case *ua.AnonymousIdentityToken:
				gotToken, ok := got.(*ua.AnonymousIdentityToken)
				require.True(t, ok, "expected anonymous token, got %T", got)
				assert.Equal(t, *want, *gotToken)
			case *ua.UserNameIdentityToken:
				gotToken, ok := got.(*ua.UserNameIdentityToken)
				require.True(t, ok, "expected username token, got %T", got)
				assert.Equal(t, want.PolicyID, gotToken.PolicyID)
				assert.Equal(t, want.UserName, gotToken.UserName)
				assert.Equal(t, string(want.Password), string(gotToken.Password))
			default:
				require.Failf(t, "unsupported test expectation type", "%T", tt.want)
			}
		})
	}
}

func TestResolveUserTokenPolicy(t *testing.T) {
	t.Parallel()

	endpoints := []*ua.EndpointDescription{
		{
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
		},
		{
			UserIdentityTokens: []*ua.UserTokenPolicy{
				{
					PolicyID:          "username_aes128",
					TokenType:         ua.UserTokenTypeUserName,
					SecurityPolicyURI: ua.SecurityPolicyURIAes128Sha256RsaOaep,
				},
			},
		},
	}

	tests := []struct {
		name    string
		token   any
		wantID  string
		wantErr error
	}{
		{
			name: "anonymous token matches advertised policy",
			token: &ua.AnonymousIdentityToken{
				PolicyID: "anonymous_none",
			},
			wantID: "anonymous_none",
		},
		{
			name: "username token matches advertised policy",
			token: &ua.UserNameIdentityToken{
				PolicyID: "username_basic256sha256",
				UserName: "alice",
			},
			wantID: "username_basic256sha256",
		},
		{
			name: "empty policy id is invalid",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
			},
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "unknown policy id is rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID: "username_unknown",
				UserName: "alice",
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "policy id with wrong token type is rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID: "anonymous_none",
				UserName: "alice",
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "unsupported decoded token type is invalid",
			token: &ua.X509IdentityToken{
				PolicyID: "x509_basic256sha256",
			},
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveUserTokenPolicy(tt.token, endpoints)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantID, got.PolicyID)
		})
	}
}

func TestDecodeUserNamePassword(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverNonce := []byte("12345678901234567890123456789012")

	encrypt := func(t *testing.T, policyURI, password string, nonce []byte) []byte {
		t.Helper()

		algo, err := uapolicy.Asymmetric(policyURI, nil, &serverKey.PublicKey)
		require.NoError(t, err)

		secret := make([]byte, 4)
		binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
		secret = append(secret, []byte(password)...)
		secret = append(secret, nonce...)

		encrypted, err := algo.Encrypt(secret)
		require.NoError(t, err)

		return encrypted
	}

	tests := []struct {
		name        string
		token       *ua.UserNameIdentityToken
		policyURI   string
		privateKey  *rsa.PrivateKey
		serverNonce []byte
		want        string
		wantErr     error
	}{
		{
			name: "none policy uses plaintext password bytes",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: []byte("secret"),
			},
			policyURI:   ua.SecurityPolicyURINone,
			serverNonce: serverNonce,
			want:        "secret",
		},
		{
			name: "encrypted password is decrypted and nonce verified",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: encrypt(t, ua.SecurityPolicyURIBasic256Sha256, "secret", serverNonce),
			},
			policyURI:   ua.SecurityPolicyURIBasic256Sha256,
			privateKey:  serverKey,
			serverNonce: serverNonce,
			want:        "secret",
		},
		{
			name: "missing private key is invalid",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: []byte("secret"),
			},
			policyURI:   ua.SecurityPolicyURIBasic256Sha256,
			serverNonce: serverNonce,
			wantErr:     ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "malformed encrypted payload is invalid",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: encrypt(t, ua.SecurityPolicyURIBasic256Sha256, "secret", serverNonce)[:8],
			},
			policyURI:   ua.SecurityPolicyURIBasic256Sha256,
			privateKey:  serverKey,
			serverNonce: serverNonce,
			wantErr:     ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "nonce mismatch is rejected",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: encrypt(t, ua.SecurityPolicyURIBasic256Sha256, "secret", serverNonce),
			},
			policyURI:   ua.SecurityPolicyURIBasic256Sha256,
			privateKey:  serverKey,
			serverNonce: []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
			wantErr:     ua.StatusBadNonceInvalid,
		},
		{
			name: "unsupported policy is rejected",
			token: &ua.UserNameIdentityToken{
				UserName: "alice",
				Password: []byte("secret"),
			},
			policyURI:   "http://example.invalid/unsupported",
			privateKey:  serverKey,
			serverNonce: serverNonce,
			wantErr:     ua.StatusBadIdentityTokenRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeUserNamePassword(tt.token, tt.policyURI, tt.privateKey, tt.serverNonce)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveUserTokenSecurityPolicyURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		policy           *ua.UserTokenPolicy
		secureChannelURI string
		want             string
		wantErr          error
	}{
		{
			name: "explicit token policy uri is used",
			policy: &ua.UserTokenPolicy{
				PolicyID:          "username_basic256sha256",
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			},
			secureChannelURI: ua.SecurityPolicyURIAes128Sha256RsaOaep,
			want:             ua.SecurityPolicyURIBasic256Sha256,
		},
		{
			name: "empty token policy uri falls back to secure channel policy",
			policy: &ua.UserTokenPolicy{
				PolicyID:  "username_default",
				TokenType: ua.UserTokenTypeUserName,
			},
			secureChannelURI: ua.SecurityPolicyURIBasic256Sha256,
			want:             ua.SecurityPolicyURIBasic256Sha256,
		},
		{
			name: "none token policy uri is allowed explicitly",
			policy: &ua.UserTokenPolicy{
				PolicyID:          "anonymous_none",
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			},
			secureChannelURI: ua.SecurityPolicyURIBasic256Sha256,
			want:             ua.SecurityPolicyURINone,
		},
		{
			name:             "nil policy is invalid",
			secureChannelURI: ua.SecurityPolicyURIBasic256Sha256,
			wantErr:          ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "empty effective policy is invalid",
			policy: &ua.UserTokenPolicy{
				PolicyID:  "username_default",
				TokenType: ua.UserTokenTypeUserName,
			},
			wantErr: ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "unsupported explicit token policy uri is rejected",
			policy: &ua.UserTokenPolicy{
				PolicyID:          "username_custom",
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: "http://example.invalid/unsupported",
			},
			secureChannelURI: ua.SecurityPolicyURIBasic256Sha256,
			wantErr:          ua.StatusBadIdentityTokenRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveUserTokenSecurityPolicyURI(tt.policy, tt.secureChannelURI)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateUserNameEncryptionAlgorithm(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	basic256sha256, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, serverKey, nil)
	require.NoError(t, err)

	tests := []struct {
		name       string
		token      *ua.UserNameIdentityToken
		policyURI  string
		privateKey *rsa.PrivateKey
		wantErr    error
	}{
		{
			name: "none policy requires empty encryption algorithm",
			token: &ua.UserNameIdentityToken{
				EncryptionAlgorithm: "",
			},
			policyURI: ua.SecurityPolicyURINone,
		},
		{
			name: "none policy rejects non-empty encryption algorithm",
			token: &ua.UserNameIdentityToken{
				EncryptionAlgorithm: "plain",
			},
			policyURI: ua.SecurityPolicyURINone,
			wantErr:   ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "secure policy requires matching encryption algorithm uri",
			token: &ua.UserNameIdentityToken{
				EncryptionAlgorithm: basic256sha256.EncryptionURI(),
			},
			policyURI:  ua.SecurityPolicyURIBasic256Sha256,
			privateKey: serverKey,
		},
		{
			name: "secure policy rejects mismatched encryption algorithm uri",
			token: &ua.UserNameIdentityToken{
				EncryptionAlgorithm: "http://example.invalid/algorithm",
			},
			policyURI:  ua.SecurityPolicyURIBasic256Sha256,
			privateKey: serverKey,
			wantErr:    ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "secure policy without private key is invalid",
			token: &ua.UserNameIdentityToken{
				EncryptionAlgorithm: basic256sha256.EncryptionURI(),
			},
			policyURI: ua.SecurityPolicyURIBasic256Sha256,
			wantErr:   ua.StatusBadIdentityTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateUserNameEncryptionAlgorithm(tt.token, tt.policyURI, tt.privateKey)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestValidateUserNameIdentityToken(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverNonce := []byte("12345678901234567890123456789012")
	endpoints := []*ua.EndpointDescription{
		{
			UserIdentityTokens: []*ua.UserTokenPolicy{
				{
					PolicyID:          "username_basic256sha256",
					TokenType:         ua.UserTokenTypeUserName,
					SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
				},
			},
		},
	}

	encrypt := func(t *testing.T, password string, nonce []byte) []byte {
		t.Helper()

		algo, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, nil, &serverKey.PublicKey)
		require.NoError(t, err)

		secret := make([]byte, 4)
		binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
		secret = append(secret, []byte(password)...)
		secret = append(secret, nonce...)

		encrypted, err := algo.Encrypt(secret)
		require.NoError(t, err)

		return encrypted
	}

	decryptOnly, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, serverKey, nil)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		token                  *ua.UserNameIdentityToken
		secureChannelPolicyURI string
		privateKey             *rsa.PrivateKey
		serverNonce            []byte
		want                   string
		wantErr                error
	}{
		{
			name: "valid encrypted username token is accepted",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			secureChannelPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			privateKey:             serverKey,
			serverNonce:            serverNonce,
			want:                   "secret",
		},
		{
			name: "unknown policy id is rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_unknown",
				UserName:            "alice",
				Password:            []byte("secret"),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			secureChannelPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			privateKey:             serverKey,
			serverNonce:            serverNonce,
			wantErr:                ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "mismatched encryption algorithm is invalid",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: "http://example.invalid/algorithm",
			},
			secureChannelPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			privateKey:             serverKey,
			serverNonce:            serverNonce,
			wantErr:                ua.StatusBadIdentityTokenInvalid,
		},
		{
			name: "nonce mismatch is rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			secureChannelPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			privateKey:             serverKey,
			serverNonce:            []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
			wantErr:                ua.StatusBadNonceInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateUserNameIdentityToken(tt.token, endpoints, tt.secureChannelPolicyURI, tt.privateKey, tt.serverNonce)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthenticateUserIdentity(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverNonce := []byte("12345678901234567890123456789012")
	endpoints := []*ua.EndpointDescription{
		{
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
		},
	}

	encrypt := func(t *testing.T, password string, nonce []byte) []byte {
		t.Helper()

		algo, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, nil, &serverKey.PublicKey)
		require.NoError(t, err)

		secret := make([]byte, 4)
		binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
		secret = append(secret, []byte(password)...)
		secret = append(secret, nonce...)

		encrypted, err := algo.Encrypt(secret)
		require.NoError(t, err)

		return encrypted
	}

	decryptOnly, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, serverKey, nil)
	require.NoError(t, err)

	session := new(sessionAuthTestSession)
	expectedUser := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
		Roles: []*ua.NodeID{
			ua.NewNumericNodeID(0, id.WellKnownRole_Anonymous),
		},
		Attributes: map[string]any{
			"tenant": "factory-a",
		},
	}

	tests := []struct {
		name          string
		token         any
		authenticator auth.UserNameAuthenticator
		want          *auth.AuthenticatedUser
		wantErr       error
	}{
		{
			name: "anonymous token bypasses authenticator",
			token: &ua.AnonymousIdentityToken{
				PolicyID: "anonymous_none",
			},
		},
		{
			name: "username token calls authenticator with decoded password",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			authenticator: func(_ context.Context, req *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				require.NotNil(t, req.SessionID)
				require.NotNil(t, req.AuthenticationToken)
				assert.Equal(t, session.ID().String(), req.SessionID.String())
				assert.Equal(t, session.AuthTokenID().String(), req.AuthenticationToken.String())
				assert.Equal(t, "alice", req.UserName)
				assert.Equal(t, "secret", req.Password)
				return expectedUser, nil
			},
			want: expectedUser,
		},
		{
			name: "username token without authenticator is rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "invalid credentials are rejected",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				return nil, auth.ErrInvalidCredentials
			},
			wantErr: ua.StatusBadIdentityTokenRejected,
		},
		{
			name: "backend unavailable maps to resource unavailable",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				return nil, auth.ErrBackendUnavailable
			},
			wantErr: ua.StatusBadResourceUnavailable,
		},
		{
			name: "unexpected authenticator errors map to internal error",
			token: &ua.UserNameIdentityToken{
				PolicyID:            "username_basic256sha256",
				UserName:            "alice",
				Password:            encrypt(t, "secret", serverNonce),
				EncryptionAlgorithm: decryptOnly.EncryptionURI(),
			},
			authenticator: func(context.Context, *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
				return nil, errors.New("database exploded")
			},
			wantErr: ua.StatusBadInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := authenticateUserIdentity(
				t.Context(),
				session,
				tt.token,
				endpoints,
				ua.SecurityPolicyURIBasic256Sha256,
				serverKey,
				serverNonce,
				tt.authenticator,
			)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			assert.Same(t, tt.want, got)
		})
	}
}

func TestStatusCodeForUserNameAuthenticatorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "nil passes through", wantErr: nil},
		{name: "invalid credentials", err: auth.ErrInvalidCredentials, wantErr: ua.StatusBadIdentityTokenRejected},
		{name: "unsupported authentication", err: auth.ErrUnsupportedAuthentication, wantErr: ua.StatusBadIdentityTokenRejected},
		{name: "backend unavailable", err: auth.ErrBackendUnavailable, wantErr: ua.StatusBadResourceUnavailable},
		{name: "unexpected error", err: errors.New("boom"), wantErr: ua.StatusBadInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := statusCodeForUserNameAuthenticatorError(tt.err)
			assert.Equal(t, tt.wantErr, got)
		})
	}
}

type sessionAuthTestSession struct{}

func (*sessionAuthTestSession) AuthTokenID() *ua.NodeID                    { return ua.NewNumericNodeID(1, 1) }
func (*sessionAuthTestSession) ID() *ua.NodeID                             { return ua.NewNumericNodeID(1, 2) }
func (*sessionAuthTestSession) Locales() []string                          { return nil }
func (*sessionAuthTestSession) SetLocales([]string)                        {}
func (*sessionAuthTestSession) RemoteCertificate() []byte                  { return nil }
func (*sessionAuthTestSession) ServerNonce() []byte                        { return nil }
func (*sessionAuthTestSession) SetServerNonce([]byte)                      {}
func (*sessionAuthTestSession) TimeOutInMillis() float64                   { return 0 }
func (*sessionAuthTestSession) Activated() bool                            { return false }
func (*sessionAuthTestSession) SetActivated(bool)                          {}
func (*sessionAuthTestSession) IsSameAs(types.Session) bool                { return false }
func (*sessionAuthTestSession) AuthenticatedUser() *auth.AuthenticatedUser { return nil }
func (*sessionAuthTestSession) PublishRequestChannel() chan types.PubReq   { return nil }
