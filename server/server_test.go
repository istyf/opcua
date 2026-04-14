package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/ua"
)

func TestStartContextCancellationClosesServer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	srv := &serverImpl{
		cb: newChannelBroker(),
		status: &ua.ServerStatusDataType{
			State: ua.ServerStateRunning,
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.closeOnStartContextDone(ctx)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for start-context shutdown goroutine")
	}

	if got := srv.Status().State; got != ua.ServerStateShutdown {
		t.Fatalf("expected server state %v after start-context cancellation, got %v", ua.ServerStateShutdown, got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{
		cb: newChannelBroker(),
		status: &ua.ServerStatusDataType{
			State: ua.ServerStateRunning,
		},
	}

	if err := srv.Close(t.Context()); err != nil {
		t.Fatalf("first close returned error: %v", err)
	}
	if err := srv.Close(t.Context()); err != nil {
		t.Fatalf("second close returned error: %v", err)
	}

	if got := srv.Status().State; got != ua.ServerStateShutdown {
		t.Fatalf("expected server state %v after repeated close, got %v", ua.ServerStateShutdown, got)
	}
}

func TestValidateConfiguredSecureEndpoints(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name    string
		cfg     *serverConfig
		wantErr string
	}{
		{
			name: "none security does not require certificate or key",
			cfg: &serverConfig{
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURINone,
					secMode:   ua.MessageSecurityModeNone,
				}},
			},
		},
		{
			name: "none security with sign mode is rejected",
			cfg: &serverConfig{
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURINone,
					secMode:   ua.MessageSecurityModeSign,
				}},
			},
			wantErr: `cannot start server: invalid secure endpoint config: security policy "http://opcfoundation.org/UA/SecurityPolicy#None" cannot be used with "MessageSecurityModeSign"`,
		},
		{
			name: "secure policy with none mode is rejected",
			cfg: &serverConfig{
				certificate: []byte("cert"),
				privateKey:  key,
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURIBasic256Sha256,
					secMode:   ua.MessageSecurityModeNone,
				}},
			},
			wantErr: `cannot start server: invalid secure endpoint config: security policy "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256" can only be used with "MessageSecurityModeSign" or "MessageSecurityModeSignAndEncrypt"`,
		},
		{
			name: "secure endpoint without certificate is rejected",
			cfg: &serverConfig{
				privateKey: key,
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURIBasic256Sha256,
					secMode:   ua.MessageSecurityModeSignAndEncrypt,
				}},
			},
			wantErr: "cannot start server: secure endpoints require a certificate",
		},
		{
			name: "secure endpoint without private key is rejected",
			cfg: &serverConfig{
				certificate: []byte("cert"),
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURIBasic256Sha256,
					secMode:   ua.MessageSecurityModeSignAndEncrypt,
				}},
			},
			wantErr: "cannot start server: secure endpoints require a private key",
		},
		{
			name: "secure endpoint with certificate and key is allowed",
			cfg: &serverConfig{
				certificate: []byte("cert"),
				privateKey:  key,
				enabledSec: []security{{
					secPolicy: ua.SecurityPolicyURIBasic256Sha256,
					secMode:   ua.MessageSecurityModeSignAndEncrypt,
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfiguredSecureEndpoints(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestValidateEnabledSecureChannelPolicy(t *testing.T) {
	t.Parallel()

	validate := validateEnabledSecureChannelPolicy([]security{
		{secPolicy: ua.SecurityPolicyURINone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: ua.SecurityPolicyURIBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
	})

	if err := validate(ua.SecurityPolicyURINone); err != nil {
		t.Fatalf("expected none policy to be accepted, got %v", err)
	}
	if err := validate(ua.SecurityPolicyURIBasic256Sha256); err != nil {
		t.Fatalf("expected Basic256Sha256 policy to be accepted, got %v", err)
	}
	if err := validate(ua.SecurityPolicyURIBasic256); err != ua.StatusBadSecurityPolicyRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityPolicyRejected, err)
	}
	if err := validate(ua.SecurityPolicyURIAes256Sha256RsaPss); err != ua.StatusBadSecurityPolicyRejected {
		t.Fatalf("expected globally supported but disabled policy to return %v, got %v", ua.StatusBadSecurityPolicyRejected, err)
	}
}

func TestValidateEnabledSecureChannelMode(t *testing.T) {
	t.Parallel()

	validate := validateEnabledSecureChannelMode([]security{
		{secPolicy: ua.SecurityPolicyURINone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: ua.SecurityPolicyURIBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
	})

	if err := validate(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone); err != nil {
		t.Fatalf("expected none mode to be accepted, got %v", err)
	}
	if err := validate(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt); err != nil {
		t.Fatalf("expected configured secure mode to be accepted, got %v", err)
	}
	if err := validate(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign); err != ua.StatusBadSecurityModeRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityModeRejected, err)
	}
	if err := validate(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSignAndEncrypt); err != ua.StatusBadSecurityModeRejected {
		t.Fatalf("expected %v, got %v", ua.StatusBadSecurityModeRejected, err)
	}
	if err := validate(ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt); err != ua.StatusBadSecurityModeRejected {
		t.Fatalf("expected globally supported but disabled mode to return %v, got %v", ua.StatusBadSecurityModeRejected, err)
	}
}

func TestEnableSecuritySkipsDuplicates(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	ctx := context.Background()

	EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)
	EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)
	EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)

	if len(cfg.enabledSec) != 1 {
		t.Fatalf("expected 1 enabled security entry after duplicate registrations, got %d", len(cfg.enabledSec))
	}

	entry := cfg.enabledSec[0]
	if entry.secPolicy != ua.SecurityPolicyURIBasic256Sha256 {
		t.Fatalf("expected policy %q, got %q", ua.SecurityPolicyURIBasic256Sha256, entry.secPolicy)
	}
	if entry.secMode != ua.MessageSecurityModeSignAndEncrypt {
		t.Fatalf("expected mode %v, got %v", ua.MessageSecurityModeSignAndEncrypt, entry.secMode)
	}
}

func TestEnableSecurityRejectsUnsupportedServerPolicy(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	ctx := t.Context()

	EnableSecurity("Basic128Rsa15", ua.MessageSecurityModeSign)(ctx, cfg)

	if len(cfg.enabledSec) != 0 {
		t.Fatalf("expected deprecated server policy registration to be ignored, got %d entries", len(cfg.enabledSec))
	}
}

func TestEnableAuthModeSkipsDuplicates(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}

	EnableAuthMode(ua.UserTokenTypeAnonymous)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeAnonymous)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeUserName)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeUserName)(t.Context(), cfg)

	if len(cfg.enabledAuth) != 2 {
		t.Fatalf("expected 2 enabled auth modes after duplicate registrations, got %d", len(cfg.enabledAuth))
	}
	if cfg.enabledAuth[0].tokenType != ua.UserTokenTypeAnonymous {
		t.Fatalf("expected first auth mode %v, got %v", ua.UserTokenTypeAnonymous, cfg.enabledAuth[0].tokenType)
	}
	if cfg.enabledAuth[1].tokenType != ua.UserTokenTypeUserName {
		t.Fatalf("expected second auth mode %v, got %v", ua.UserTokenTypeUserName, cfg.enabledAuth[1].tokenType)
	}
}

func TestWithUserNameAuthenticator(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	authErr := errors.New("auth failed")
	expected := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
		Attributes: map[string]any{
			"department": "ops",
		},
	}
	authenticator := func(_ context.Context, req *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
		if req == nil {
			t.Fatal("expected request to be forwarded to authenticator")
		}
		return expected, authErr
	}

	WithUserNameAuthenticator(authenticator)(t.Context(), cfg)

	if cfg.userNameAuthenticator == nil {
		t.Fatal("expected username authenticator to be stored on config")
	}

	result, err := cfg.userNameAuthenticator(t.Context(), &auth.UserNameAuthenticationRequest{
		UserName: "alice",
		Password: "secret",
	})
	if !errors.Is(err, authErr) {
		t.Fatalf("expected authenticator error %v, got %v", authErr, err)
	}
	if result != expected {
		t.Fatalf("expected authenticator result %#v, got %#v", expected, result)
	}
}

func TestInitEndpointsAdvertisesConfiguredAuthModes(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{
		cfg: &serverConfig{
			applicationURI:  "urn:gopcua:test:server",
			applicationName: "Test Server",
			certificate:     []byte("cert"),
			endpoints:       []string{"opc.tcp://localhost:4840"},
			enabledSec: []security{
				{secPolicy: ua.SecurityPolicyURINone, secMode: ua.MessageSecurityModeNone},
				{secPolicy: ua.SecurityPolicyURIBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
			},
			enabledAuth: []authMode{
				{tokenType: ua.UserTokenTypeAnonymous},
				{tokenType: ua.UserTokenTypeUserName},
			},
		},
	}

	srv.initEndpoints()

	endpoints := srv.Endpoints()
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	for _, ep := range endpoints {
		policies := make(map[string]*ua.UserTokenPolicy, len(ep.UserIdentityTokens))
		for _, token := range ep.UserIdentityTokens {
			policies[token.PolicyID] = token
		}

		anonymous, ok := policies["anonymous_none"]
		if !ok {
			t.Fatalf("expected endpoint %s/%s to advertise anonymous_none", ep.SecurityPolicyURI, ep.SecurityMode)
		}
		if anonymous.TokenType != ua.UserTokenTypeAnonymous {
			t.Fatalf("expected anonymous policy token type %v, got %v", ua.UserTokenTypeAnonymous, anonymous.TokenType)
		}
		if anonymous.SecurityPolicyURI != ua.SecurityPolicyURINone {
			t.Fatalf("expected anonymous policy URI %q, got %q", ua.SecurityPolicyURINone, anonymous.SecurityPolicyURI)
		}

		userName, ok := policies["username_basic256sha256"]
		if !ok {
			t.Fatalf("expected endpoint %s/%s to advertise username_basic256sha256", ep.SecurityPolicyURI, ep.SecurityMode)
		}
		if userName.TokenType != ua.UserTokenTypeUserName {
			t.Fatalf("expected username policy token type %v, got %v", ua.UserTokenTypeUserName, userName.TokenType)
		}
		if userName.SecurityPolicyURI != ua.SecurityPolicyURIBasic256Sha256 {
			t.Fatalf("expected username policy URI %q, got %q", ua.SecurityPolicyURIBasic256Sha256, userName.SecurityPolicyURI)
		}
		if _, exists := policies["username_none"]; exists {
			t.Fatalf("did not expect endpoint %s/%s to advertise username_none", ep.SecurityPolicyURI, ep.SecurityMode)
		}
	}
}

func TestInitEndpointsOmitsUserNameWithoutSecurePolicy(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{
		cfg: &serverConfig{
			applicationURI:  "urn:gopcua:test:server",
			applicationName: "Test Server",
			endpoints:       []string{"opc.tcp://localhost:4840"},
			enabledSec: []security{
				{secPolicy: ua.SecurityPolicyURINone, secMode: ua.MessageSecurityModeNone},
			},
			enabledAuth: []authMode{
				{tokenType: ua.UserTokenTypeAnonymous},
				{tokenType: ua.UserTokenTypeUserName},
			},
		},
	}

	srv.initEndpoints()

	endpoints := srv.Endpoints()
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if len(endpoints[0].UserIdentityTokens) != 1 {
		t.Fatalf("expected only anonymous auth to be advertised, got %d user token policies", len(endpoints[0].UserIdentityTokens))
	}
	if endpoints[0].UserIdentityTokens[0].PolicyID != "anonymous_none" {
		t.Fatalf("expected only anonymous_none policy, got %q", endpoints[0].UserIdentityTokens[0].PolicyID)
	}
}
