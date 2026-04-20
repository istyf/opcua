package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureChannelConnectMatrix(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	srv := newSecureChannelIntegrationServer(t, ctx, allSecureChannelMatrixEntries())
	defer srv.close(t.Context())

	endpoints := mustGetEndpoints(t, ctx, srv.endpoint)

	tests := []struct {
		name   string
		policy string
		mode   ua.MessageSecurityMode
	}{
		{name: "basic256-sign", policy: "Basic256", mode: ua.MessageSecurityModeSign},
		{name: "basic256-signandencrypt", policy: "Basic256", mode: ua.MessageSecurityModeSignAndEncrypt},
		{name: "basic256sha256-sign", policy: "Basic256Sha256", mode: ua.MessageSecurityModeSign},
		{name: "basic256sha256-signandencrypt", policy: "Basic256Sha256", mode: ua.MessageSecurityModeSignAndEncrypt},
		{name: "aes128-sha256-rsaoaep-sign", policy: "Aes128_Sha256_RsaOaep", mode: ua.MessageSecurityModeSign},
		{name: "aes128-sha256-rsaoaep-signandencrypt", policy: "Aes128_Sha256_RsaOaep", mode: ua.MessageSecurityModeSignAndEncrypt},
		{name: "aes256-sha256-rsapss-sign", policy: "Aes256_Sha256_RsaPss", mode: ua.MessageSecurityModeSign},
		{name: "aes256-sha256-rsapss-signandencrypt", policy: "Aes256_Sha256_RsaPss", mode: ua.MessageSecurityModeSignAndEncrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := opcua.SelectEndpoint(endpoints, tt.policy, tt.mode)
			require.NoError(t, err)

			c, err := opcua.NewClient(ep.EndpointURL,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(srv.clientCert),
				opcua.PrivateKey(srv.clientKey),
				opcua.AutoReconnect(false),
			)
			require.NoError(t, err)

			require.NoError(t, c.Connect(ctx))
			require.NoError(t, c.Close(ctx))
		})
	}
}

func TestSecureChannelConnectRejectsDisabledPolicyOrMode(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	srv := newSecureChannelIntegrationServer(t, ctx, []security{
		{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
	})
	defer srv.close(t.Context())

	tests := []struct {
		name   string
		policy string
		mode   ua.MessageSecurityMode
	}{
		{
			name:   "disabled policy is rejected",
			policy: "Basic256",
			mode:   ua.MessageSecurityModeSignAndEncrypt,
		},
		{
			name:   "disabled mode is rejected",
			policy: "Basic256Sha256",
			mode:   ua.MessageSecurityModeSign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &ua.EndpointDescription{
				EndpointURL:       srv.endpoint,
				ServerCertificate: srv.serverCert,
				SecurityPolicyURI: ua.FormatSecurityPolicyURI(tt.policy),
				SecurityMode:      tt.mode,
				UserIdentityTokens: []*ua.UserTokenPolicy{{
					PolicyID:          "anonymous_none",
					TokenType:         ua.UserTokenTypeAnonymous,
					SecurityPolicyURI: ua.SecurityPolicyURINone,
				}},
			}

			c, err := opcua.NewClient(ep.EndpointURL,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(srv.clientCert),
				opcua.PrivateKey(srv.clientKey),
				opcua.AutoReconnect(false),
			)
			require.NoError(t, err)
			err = c.Connect(ctx)
			if err == nil {
				_ = c.Close(ctx)
				require.FailNowf(t, "expected connect to fail", "%s/%s", tt.policy, tt.mode)
			}
			assert.False(t, strings.Contains(err.Error(), "StatusBadTimeout"), "expected prompt rejection for %s/%s, got timeout: %v", tt.policy, tt.mode, err)
		})
	}
}

func TestGetEndpointsAdvertisesOnlyConfiguredServeableSecurityCombinations(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	enabled := []security{
		{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSign},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
		{secPolicy: SecurityPolicyAes128Sha256RsaOaep, secMode: ua.MessageSecurityModeSignAndEncrypt},
	}
	srv := newSecureChannelIntegrationServer(t, ctx, enabled)
	defer srv.close(t.Context())

	endpoints := mustGetEndpoints(t, ctx, srv.endpoint)

	got := make(map[string]bool)
	for _, ep := range endpoints {
		key := fmt.Sprintf("%s|%s", ep.SecurityPolicyURI, ep.SecurityMode)
		got[key] = true
		if ep.SecurityPolicyURI == ua.SecurityPolicyURINone {
			continue
		}
		assert.NotEmpty(t, ep.ServerCertificate, "expected secure endpoint %s/%s to advertise a certificate", ep.SecurityPolicyURI, ep.SecurityMode)
	}

	want := map[string]bool{
		fmt.Sprintf("%s|%s", ua.SecurityPolicyURINone, ua.MessageSecurityModeNone):                          true,
		fmt.Sprintf("%s|%s", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign):                true,
		fmt.Sprintf("%s|%s", ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt):      true,
		fmt.Sprintf("%s|%s", ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.MessageSecurityModeSignAndEncrypt): true,
	}

	require.Len(t, got, len(want), "%#v", got)
	for key := range want {
		assert.True(t, got[key], "missing expected endpoint %s", key)
	}
}

type secureChannelIntegrationServer struct {
	clientCert []byte
	clientKey  *rsa.PrivateKey
	endpoint   string
	server     types.Server
	serverCert []byte
}

func newSecureChannelIntegrationServer(t *testing.T, ctx context.Context, enabled []security) *secureChannelIntegrationServer {
	t.Helper()

	port := reserveTestPort(t)
	endpoint := fmt.Sprintf("opc.tcp://localhost:%d", port)
	serverCert, serverKey := mustGenerateTestCertificate(t, fmt.Sprintf("localhost,127.0.0.1,urn:gopcua:test:server:%d", port), 2048)
	clientCert, clientKey := mustGenerateTestCertificate(t, "localhost,127.0.0.1,urn:gopcua:test:client", 2048)

	opts := []Option{
		EndPoint("localhost", port),
		Certificate(serverCert),
		PrivateKey(serverKey),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	for _, sec := range enabled {
		opts = append(opts, EnableSecurity(sec.secPolicy, sec.secMode))
	}

	s := New(ctx, opts...)
	require.NoError(t, s.Start(ctx))

	return &secureChannelIntegrationServer{
		clientCert: clientCert,
		clientKey:  clientKey,
		endpoint:   endpoint,
		server:     s,
		serverCert: serverCert,
	}
}

func (s *secureChannelIntegrationServer) close(ctx context.Context) {
	_ = s.server.Close(ctx)
}

func mustGetEndpoints(t *testing.T, ctx context.Context, endpoint string) []*ua.EndpointDescription {
	t.Helper()

	endpoints, err := opcua.GetEndpoints(ctx, endpoint, opcua.AutoReconnect(false))
	require.NoError(t, err)
	return endpoints
}

func allSecureChannelMatrixEntries() []security {
	return []security{
		{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: SecurityPolicyBasic256, secMode: ua.MessageSecurityModeSign},
		{secPolicy: SecurityPolicyBasic256, secMode: ua.MessageSecurityModeSignAndEncrypt},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSign},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
		{secPolicy: SecurityPolicyAes128Sha256RsaOaep, secMode: ua.MessageSecurityModeSign},
		{secPolicy: SecurityPolicyAes128Sha256RsaOaep, secMode: ua.MessageSecurityModeSignAndEncrypt},
		{secPolicy: SecurityPolicyAes256Sha256RsaPss, secMode: ua.MessageSecurityModeSign},
		{secPolicy: SecurityPolicyAes256Sha256RsaPss, secMode: ua.MessageSecurityModeSignAndEncrypt},
	}
}

func reserveTestPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	addr, ok := l.Addr().(*net.TCPAddr)
	require.True(t, ok, "unexpected listener address type %T", l.Addr())
	return addr.Port
}

func mustGenerateTestCertificate(t *testing.T, hosts string, rsaBits int) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	require.NoError(t, err)

	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gopcua SecureChannel Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	for host := range strings.SplitSeq(hosts, ",") {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
		if uri, err := url.Parse(host); err == nil {
			template.URIs = append(template.URIs, uri)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	return der, priv
}
