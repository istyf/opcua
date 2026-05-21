package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{
		cb: newChannelBroker(),
		status: &ua.ServerStatusDataType{
			State: ua.ServerStateRunning,
		},
	}

	require.NoError(t, srv.Close(t.Context()))
	require.NoError(t, srv.Close(t.Context()))
	assert.Equal(t, ua.ServerStateShutdown, srv.Status().State)
}

func TestValidateConfiguredSecureEndpoints(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		cfg     *serverConfig
		wantErr string
	}{
		{
			name: "none security does not require certificate or key",
			cfg: &serverConfig{
				enabledSec: []security{{
					secPolicy: SecurityPolicyNone,
					secMode:   ua.MessageSecurityModeNone,
				}},
			},
		},
		{
			name: "none security with sign mode is rejected",
			cfg: &serverConfig{
				enabledSec: []security{{
					secPolicy: SecurityPolicyNone,
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
					secPolicy: SecurityPolicyBasic256Sha256,
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
					secPolicy: SecurityPolicyBasic256Sha256,
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
					secPolicy: SecurityPolicyBasic256Sha256,
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
					secPolicy: SecurityPolicyBasic256Sha256,
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
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error())
		})
	}
}

func TestValidateEnabledSecureChannelPolicy(t *testing.T) {
	t.Parallel()

	validate := validateEnabledSecureChannelPolicy([]security{
		{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
	})

	assert.NoError(t, validate(SecurityPolicyNone.URI()))
	assert.NoError(t, validate(SecurityPolicyBasic256Sha256.URI()))
	assert.Equal(t, ua.StatusBadSecurityPolicyRejected, validate(SecurityPolicyBasic256.URI()))
	assert.Equal(t, ua.StatusBadSecurityPolicyRejected, validate(SecurityPolicyAes256Sha256RsaPss.URI()))
}

func TestValidateEnabledSecureChannelMode(t *testing.T) {
	t.Parallel()

	validate := validateEnabledSecureChannelMode([]security{
		{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
		{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
	})

	assert.NoError(t, validate(SecurityPolicyNone.URI(), ua.MessageSecurityModeNone))
	assert.NoError(t, validate(SecurityPolicyBasic256Sha256.URI(), ua.MessageSecurityModeSignAndEncrypt))
	assert.Equal(t, ua.StatusBadSecurityModeRejected, validate(SecurityPolicyBasic256Sha256.URI(), ua.MessageSecurityModeSign))
	assert.Equal(t, ua.StatusBadSecurityModeRejected, validate(SecurityPolicyBasic256.URI(), ua.MessageSecurityModeSignAndEncrypt))
	assert.Equal(t, ua.StatusBadSecurityModeRejected, validate(SecurityPolicyAes256Sha256RsaPss.URI(), ua.MessageSecurityModeSignAndEncrypt))
}

func TestSecurityPolicyURI(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ua.SecurityPolicyURIBasic256Sha256, SecurityPolicyBasic256Sha256.URI())
}

func TestEnableSecuritySkipsDuplicates(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	ctx := t.Context()

	EnableSecurity(SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)
	EnableSecurity(SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)
	EnableSecurity(SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)(ctx, cfg)

	require.Len(t, cfg.enabledSec, 1)

	entry := cfg.enabledSec[0]
	assert.Equal(t, SecurityPolicyBasic256Sha256, entry.secPolicy)
	assert.Equal(t, ua.MessageSecurityModeSignAndEncrypt, entry.secMode)
}

func TestEnableSecurityRejectsUnsupportedServerPolicy(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	ctx := t.Context()

	EnableSecurity(SecurityPolicyBasic128Rsa15, ua.MessageSecurityModeSign)(ctx, cfg)

	assert.Empty(t, cfg.enabledSec)
}

func TestEnableAuthModeSkipsDuplicates(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}

	EnableAuthMode(ua.UserTokenTypeAnonymous)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeAnonymous)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeUserName)(t.Context(), cfg)
	EnableAuthMode(ua.UserTokenTypeUserName)(t.Context(), cfg)

	require.Len(t, cfg.enabledAuth, 2)
	assert.Equal(t, ua.UserTokenTypeAnonymous, cfg.enabledAuth[0].tokenType)
	assert.Equal(t, ua.UserTokenTypeUserName, cfg.enabledAuth[1].tokenType)
}

func TestWithUserNameAuthenticator(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	authErr := errors.New("auth failed")
	expected := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
		Roles: []*ua.NodeID{
			ua.NewNumericNodeID(0, id.WellKnownRole_Anonymous),
		},
		Attributes: map[string]any{
			"department": "ops",
		},
	}
	authenticator := func(_ context.Context, req *auth.UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error) {
		require.NotNil(t, req)
		return expected, authErr
	}

	WithUserNameAuthenticator(authenticator)(t.Context(), cfg)

	require.NotNil(t, cfg.userNameAuthenticator)

	result, err := cfg.userNameAuthenticator(t.Context(), &auth.UserNameAuthenticationRequest{
		UserName: "alice",
		Password: "secret",
	})
	assert.ErrorIs(t, err, authErr)
	assert.Same(t, expected, result)
}

func TestServiceFaultFromRecoveredPanicReturnsUnexpectedError(t *testing.T) {
	t.Parallel()

	resp := serviceFaultFromRecoveredPanic(t.Context(), "boom")
	fault, ok := resp.(*ua.ServiceFault)
	require.True(t, ok, "expected *ua.ServiceFault, got %T", resp)
	require.NotNil(t, fault.ResponseHeader)
	assert.Equal(t, ua.StatusBadUnexpectedError, fault.ResponseHeader.ServiceResult)
}

func TestTLSCertificateSetsLeafPrivateKeyAndAdvertisedChain(t *testing.T) {
	t.Parallel()

	leafDER, leafKey, chain := mustServerTestCertificateChain(t)
	cfg := &serverConfig{}

	TLSCertificate(tls.Certificate{
		Certificate: chain,
		PrivateKey:  leafKey,
		Leaf:        mustServerTestParseCertificate(t, leafDER),
	})(t.Context(), cfg)

	require.Equal(t, leafDER, cfg.Certificate())
	require.Equal(t, leafKey, cfg.PrivateKey())
	require.Equal(t, bytesJoin(chain), cfg.AdvertisedCertificate())
	assert.NotEmpty(t, cfg.ApplicationURI())
}

func TestCertificateKeepsLeafAsAdvertisedCertificate(t *testing.T) {
	t.Parallel()

	leafDER, _, _ := mustServerTestCertificateChain(t)
	cfg := &serverConfig{}

	Certificate(leafDER)(t.Context(), cfg)

	require.Equal(t, leafDER, cfg.Certificate())
	require.Equal(t, leafDER, cfg.AdvertisedCertificate())
	assert.NotEmpty(t, cfg.ApplicationURI())
}

func bytesJoin(chunks [][]byte) []byte {
	var out []byte
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	return out
}

func mustServerTestCertificateChain(t *testing.T) ([]byte, *rsa.PrivateKey, [][]byte) {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert := mustServerTestParseCertificate(t, rootDER)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		URIs:         []*url.URL{{Scheme: "urn", Opaque: "gopcua:test:server"}},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	return leafDER, leafKey, [][]byte{leafDER, rootDER}
}

func mustServerTestParseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestWithAuthorizationContextDecorator(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}
	decorator := func(ctx context.Context, user *auth.AuthenticatedUser) context.Context {
		return ctx
	}

	WithAuthorizationContextDecorator(decorator)(t.Context(), cfg)

	require.NotNil(t, cfg.AuthorizationContextDecorator())
	assert.NotNil(t, cfg.authContextDecorator)
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
				{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
				{secPolicy: SecurityPolicyBasic256Sha256, secMode: ua.MessageSecurityModeSignAndEncrypt},
			},
			enabledAuth: []authMode{
				{tokenType: ua.UserTokenTypeAnonymous},
				{tokenType: ua.UserTokenTypeUserName},
			},
		},
	}

	srv.initEndpoints()

	endpoints := srv.Endpoints()
	require.Len(t, endpoints, 2)

	for _, ep := range endpoints {
		policies := make(map[string]*ua.UserTokenPolicy, len(ep.UserIdentityTokens))
		for _, token := range ep.UserIdentityTokens {
			policies[token.PolicyID] = token
		}

		anonymous, ok := policies["anonymous_none"]
		require.True(t, ok, "expected endpoint %s/%s to advertise anonymous_none", ep.SecurityPolicyURI, ep.SecurityMode)
		assert.Equal(t, ua.UserTokenTypeAnonymous, anonymous.TokenType)
		assert.Equal(t, ua.SecurityPolicyURINone, anonymous.SecurityPolicyURI)

		userName, ok := policies["username_basic256sha256"]
		require.True(t, ok, "expected endpoint %s/%s to advertise username_basic256sha256", ep.SecurityPolicyURI, ep.SecurityMode)
		assert.Equal(t, ua.UserTokenTypeUserName, userName.TokenType)
		assert.Equal(t, ua.SecurityPolicyURIBasic256Sha256, userName.SecurityPolicyURI)
		_, exists := policies["username_none"]
		assert.False(t, exists)
	}
}

func TestWireupServerCapabilityNodeValueAdvertisesConfiguredLimits(t *testing.T) {
	t.Parallel()

	srv := New(t.Context(),
		MaxBrowseOperationsPerCall(12),
		MaxMethodOperationsPerCall(13),
		MaxBrowseContinuationPoints(14),
		MaxSubscriptions(15),
		MaxSubscriptionsPerSession(16),
	).(*serverImpl)

	ns, err := srv.Namespace(0)
	require.NoError(t, err)

	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead, uint32(32))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse, uint32(12))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall, uint32(13))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxBrowseContinuationPoints, uint16(14))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxSubscriptions, uint32(15))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxSubscriptionsPerSession, uint32(16))
}

func TestWireupServerCapabilityNodeValueAdvertisesUnlimitedLimitsAsTypeMax(t *testing.T) {
	t.Parallel()

	srv := New(t.Context()).(*serverImpl)

	ns, err := srv.Namespace(0)
	require.NoError(t, err)

	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall, uint32(math.MaxUint32))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse, uint32(math.MaxUint32))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxBrowseContinuationPoints, uint16(math.MaxUint16))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxSubscriptions, uint32(math.MaxUint32))
	assertServerCapabilityValue(t, ns, id.Server_ServerCapabilities_MaxSubscriptionsPerSession, uint32(math.MaxUint32))
}

func TestChannelBrokerCloseTimeoutOption(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{}

	ChannelBrokerCloseTimeout(3*time.Second)(t.Context(), cfg)
	assert.Equal(t, 3*time.Second, cfg.channelBrokerCloseTimeout)

	ChannelBrokerCloseTimeout(0)(t.Context(), cfg)
	assert.Equal(t, defaultChannelBrokerCloseTimeout, cfg.channelBrokerCloseTimeout)
}

func assertServerCapabilityValue(t *testing.T, ns types.NameSpace, nodeID uint32, want any) {
	t.Helper()

	n := ns.Node(ua.NewNumericNodeID(0, nodeID))
	require.NotNil(t, n)

	v, ok := n.(types.VariableNode)
	require.True(t, ok, "expected variable node for i=%d", nodeID)

	dv := v.Value()
	require.NotNil(t, dv)
	require.NotNil(t, dv.Value)
	assert.Equal(t, want, dv.Value.Value())
}

func TestInitEndpointsOmitsUserNameWithoutSecurePolicy(t *testing.T) {
	t.Parallel()

	srv := &serverImpl{
		cfg: &serverConfig{
			applicationURI:  "urn:gopcua:test:server",
			applicationName: "Test Server",
			endpoints:       []string{"opc.tcp://localhost:4840"},
			enabledSec: []security{
				{secPolicy: SecurityPolicyNone, secMode: ua.MessageSecurityModeNone},
			},
			enabledAuth: []authMode{
				{tokenType: ua.UserTokenTypeAnonymous},
				{tokenType: ua.UserTokenTypeUserName},
			},
		},
	}

	srv.initEndpoints()

	endpoints := srv.Endpoints()
	require.Len(t, endpoints, 1)
	require.Len(t, endpoints[0].UserIdentityTokens, 1)
	assert.Equal(t, "anonymous_none", endpoints[0].UserIdentityTokens[0].PolicyID)
}

func TestResolvedEndpointURLsRewritesConfiguredPorts(t *testing.T) {
	t.Parallel()

	got := resolvedEndpointURLs([]string{
		"opc.tcp://localhost:0",
		"opc.tcp://example.com:4840/path",
	}, 51234)

	assert.Equal(t, []string{
		"opc.tcp://localhost:51234",
		"opc.tcp://example.com:51234/path",
	}, got)
}

func TestStartWithPortZeroPublishesResolvedPort(t *testing.T) {
	ctx := t.Context()

	srv := New(ctx,
		EndPoint("localhost", 0),
		EnableSecurity(SecurityPolicyNone, ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)

	err := srv.Start(ctx)
	if err != nil && strings.Contains(err.Error(), "operation not permitted") {
		t.Skipf("listener bind not permitted in this environment: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, srv.Close(context.WithoutCancel(ctx)))
	})

	port := srv.PortNumber()
	require.Positive(t, port)

	endpoints := srv.Endpoints()
	require.NotEmpty(t, endpoints)

	for _, ep := range endpoints {
		assert.Contains(t, ep.EndpointURL, fmt.Sprintf(":%d", port))
		assert.NotContains(t, ep.EndpointURL, ":0")
	}

	for _, url := range srv.(*serverImpl).URLs() {
		assert.Contains(t, url, fmt.Sprintf(":%d", port))
		assert.False(t, strings.HasSuffix(url, ":0"))
	}
}
