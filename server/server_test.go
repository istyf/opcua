package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/ua"
)

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
	ctx := context.Background()

	EnableSecurity("Basic128Rsa15", ua.MessageSecurityModeSign)(ctx, cfg)

	if len(cfg.enabledSec) != 0 {
		t.Fatalf("expected deprecated server policy registration to be ignored, got %d entries", len(cfg.enabledSec))
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
	auth := func(_ context.Context, req *UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
		if req == nil {
			t.Fatal("expected request to be forwarded to authenticator")
		}
		return expected, authErr
	}

	WithUserNameAuthenticator(auth)(t.Context(), cfg)

	if cfg.userNameAuthenticator == nil {
		t.Fatal("expected username authenticator to be stored on config")
	}

	result, err := cfg.userNameAuthenticator(t.Context(), &UserNameAuthenticationRequest{
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
