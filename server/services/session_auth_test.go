package services

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
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
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			switch want := tt.want.(type) {
			case *ua.AnonymousIdentityToken:
				gotToken, ok := got.(*ua.AnonymousIdentityToken)
				if !ok {
					t.Fatalf("expected anonymous token, got %T", got)
				}
				if *gotToken != *want {
					t.Fatalf("expected token %#v, got %#v", want, gotToken)
				}
			case *ua.UserNameIdentityToken:
				gotToken, ok := got.(*ua.UserNameIdentityToken)
				if !ok {
					t.Fatalf("expected username token, got %T", got)
				}
				if gotToken.PolicyID != want.PolicyID || gotToken.UserName != want.UserName || string(gotToken.Password) != string(want.Password) {
					t.Fatalf("expected token %#v, got %#v", want, gotToken)
				}
			default:
				t.Fatalf("unsupported test expectation type %T", tt.want)
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
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got == nil {
				t.Fatal("expected matching user token policy, got nil")
			}
			if got.PolicyID != tt.wantID {
				t.Fatalf("expected policy %q, got %q", tt.wantID, got.PolicyID)
			}
		})
	}
}

func TestDecodeUserNamePassword(t *testing.T) {
	t.Parallel()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	serverNonce := []byte("12345678901234567890123456789012")

	encrypt := func(t *testing.T, policyURI, password string, nonce []byte) []byte {
		t.Helper()

		algo, err := uapolicy.Asymmetric(policyURI, nil, &serverKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to build encrypt-only algorithm: %v", err)
		}

		secret := make([]byte, 4)
		binary.LittleEndian.PutUint32(secret, uint32(len(password)+len(nonce)))
		secret = append(secret, []byte(password)...)
		secret = append(secret, nonce...)

		encrypted, err := algo.Encrypt(secret)
		if err != nil {
			t.Fatalf("failed to encrypt test password: %v", err)
		}

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
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected password %q, got %q", tt.want, got)
			}
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
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected policy uri %q, got %q", tt.want, got)
			}
		})
	}
}
