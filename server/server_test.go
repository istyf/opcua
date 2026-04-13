package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

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
