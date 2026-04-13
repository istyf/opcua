package services

import (
	"testing"

	"github.com/gopcua/opcua/ua"
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
