// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/services"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
)

var supportedServerSecurityPolicies = []SecurityPolicy{
	SecurityPolicyNone,
	SecurityPolicyBasic256,
	SecurityPolicyBasic256Sha256,
	SecurityPolicyAes128Sha256RsaOaep,
	SecurityPolicyAes256Sha256RsaPss,
}

// Option is an option function type to modify the configuration.
type Option func(context.Context, *serverConfig)

// PrivateKey sets the RSA private key in the secure channel configuration.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(_ context.Context, s *serverConfig) {
		s.privateKey = key
	}
}

// EndPointHostName adds an additional endpoint to the server based on the host name
func EndPoint(host string, port int) Option {
	return func(_ context.Context, s *serverConfig) {
		if s.endpoints == nil {
			s.endpoints = make([]string, 0)
		}
		ep := fmt.Sprintf("opc.tcp://%s:%d", host, port)
		s.endpoints = append(s.endpoints, ep)
	}
}

// Certificate sets the client X509 certificate in the secure channel configuration
// and also detects and sets the ApplicationURI from the URI within the certificate
func Certificate(cert []byte) Option {
	return func(_ context.Context, s *serverConfig) {
		s.certificate = cert

		// Extract the application URI from the certificate.
		var appURI string
		x509cert, err := x509.ParseCertificate(cert)
		if err == nil && len(x509cert.URIs) > 0 {
			appURI = x509cert.URIs[0].String()
		}

		s.applicationURI = appURI
	}
}

// EnableSecurity registers a new endpoint security mode to the server.
// This will also register the security policy against each enabled auth mode
// Use the typed SecurityPolicy constants from this package.
func EnableSecurity(secPolicy SecurityPolicy, secMode ua.MessageSecurityMode) Option {
	return func(ctx context.Context, s *serverConfig) {
		secPolicyURI := secPolicy.URI()

		ss := uapolicy.SupportedPolicies()
		ok := slices.Contains(ss, secPolicyURI)
		if !ok {
			ualog.Error(ctx, "unable to add endpoint security mode to config",
				ualog.String(ualog.ErrorKey, "unsupported policy"),
				ualog.String("policy", secPolicyURI),
			)
			return
		}
		if !slices.Contains(supportedServerSecurityPolicies, secPolicy) {
			ualog.Error(ctx, "unable to add endpoint security mode to config",
				ualog.String(ualog.ErrorKey, "unsupported server policy"),
				ualog.String("policy", secPolicyURI),
			)
			return
		}

		for _, sec := range s.enabledSec {
			if sec.secPolicy == secPolicy && sec.secMode == secMode {
				ualog.Warn(ctx, "security policy already exists, skipping")
				return
			}
		}

		sec := security{
			secPolicy: secPolicy,
			secMode:   secMode,
		}

		s.enabledSec = append(s.enabledSec, sec)
	}
}

// EnableAuthMode registers a new user authentication mode to the server.
// All AuthModes except Anonymous require encryption by default, so EnableSecurity()
// must also be called with at least one non-"None" SecurityPolicy
func EnableAuthMode(tokenType ua.UserTokenType) Option {
	return func(ctx context.Context, s *serverConfig) {

		for _, a := range s.enabledAuth {
			if a.tokenType == tokenType {
				ualog.Warn(ctx, "auth mode already registered, skipping",
					ualog.String("mode", tokenType.String()),
				)
				return
			}
		}

		a := authMode{
			tokenType: tokenType,
		}

		s.enabledAuth = append(s.enabledAuth, a)
	}
}

// WithUserNameAuthenticator registers the callback used to verify decoded
// username/password credentials during ActivateSession.
//
// The callback receives the decoded credentials together with the session
// identifiers for the activation attempt. On success, the returned user
// context is stored on the activated session and can be read back through the
// session interface. This option does not assign OPC UA roles yet; that will
// come in later authorization work.
func WithUserNameAuthenticator(authenticator auth.UserNameAuthenticator) Option {
	return func(_ context.Context, s *serverConfig) {
		s.userNameAuthenticator = authenticator
	}
}

// WithAuthorizationContextDecorator registers the callback used to enrich
// request contexts for application method handlers using the authenticated user
// stored on the current session.
//
// The decorator is optional. When set, it is applied immediately before
// method dispatch and receives the session's authenticated user, which may be
// nil for anonymous or unauthenticated sessions.
func WithAuthorizationContextDecorator(decorator auth.AuthorizationContextDecorator) Option {
	return func(_ context.Context, s *serverConfig) {
		s.authContextDecorator = decorator
	}
}

func defaultChannelConfig() *uasc.Config {
	return &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
	}
}

func ServerName(name string) Option {
	return func(_ context.Context, s *serverConfig) {
		s.applicationName = name
	}
}

func ManufacturerName(name string) Option {
	return func(_ context.Context, s *serverConfig) {
		s.manufacturerName = name
	}
}

func ProductName(name string) Option {
	return func(_ context.Context, s *serverConfig) {
		s.productName = name
	}
}

func SoftwareVersion(name string) Option {
	return func(_ context.Context, s *serverConfig) {
		s.softwareVersion = name
	}
}

// MaxBrowseOperationsPerCall limits the number of nodes a Browse request may
// include. A value of 0 disables the limit.
func MaxBrowseOperationsPerCall(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxBrowseOperationsPerCall = count
	}
}

// MaxMethodOperationsPerCall limits the number of methods a Call request may
// include. A value of 0 disables the limit.
func MaxMethodOperationsPerCall(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxMethodOperationsPerCall = count
	}
}

// MaxBrowseContinuationPoints limits the number of browse continuation points
// that may be held by the server at one time. A value of 0 disables the limit.
func MaxBrowseContinuationPoints(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxBrowseContinuationPoints = count
	}
}

// MaxSubscriptions limits the total number of subscriptions on the server.
// A value of 0 disables the limit.
func MaxSubscriptions(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxSubscriptions = count
	}
}

// MaxSubscriptionsPerSession limits the number of subscriptions owned by a
// single session. A value of 0 disables the limit.
func MaxSubscriptionsPerSession(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxSubscriptionsPerSession = count
	}
}

// MaxSubscriptionOperationsPerCall limits the number of subscription IDs a
// batched subscription service call may include. A value of 0 disables the
// limit.
func MaxSubscriptionOperationsPerCall(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		s.maxSubscriptionOperationsPerCall = count
	}
}

// ChannelBrokerCloseTimeout controls how long server shutdown waits for secure
// channel goroutines to exit after close has been requested. Values less than
// or equal to 0 restore the default timeout.
func ChannelBrokerCloseTimeout(timeout time.Duration) Option {
	return func(_ context.Context, s *serverConfig) {
		if timeout <= 0 {
			s.channelBrokerCloseTimeout = defaultChannelBrokerCloseTimeout
			return
		}
		s.channelBrokerCloseTimeout = timeout
	}
}

// MinSubscriptionPublishingInterval sets the smallest supported publishing
// interval for subscriptions. Values less than or equal to 0 restore the
// default minimum.
func MinSubscriptionPublishingInterval(interval time.Duration) Option {
	return func(_ context.Context, s *serverConfig) {
		if interval <= 0 {
			s.minSubscriptionPublishingInterval = services.DefaultMinSubscriptionPublishingInterval
			return
		}
		s.minSubscriptionPublishingInterval = interval
	}
}

// MinSubscriptionMaxKeepAliveCount sets the smallest supported keepalive count
// for subscriptions. A value of 0 restores the default minimum.
func MinSubscriptionMaxKeepAliveCount(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		if count == 0 {
			s.minSubscriptionMaxKeepAliveCount = services.DefaultMinSubscriptionMaxKeepAliveCount
			return
		}
		s.minSubscriptionMaxKeepAliveCount = count
	}
}

// MinSubscriptionLifetimeCount sets the smallest supported lifetime count for
// subscriptions. A value of 0 restores the default minimum.
func MinSubscriptionLifetimeCount(count uint32) Option {
	return func(_ context.Context, s *serverConfig) {
		if count == 0 {
			s.minSubscriptionLifetimeCount = services.DefaultMinSubscriptionLifetimeCount
			return
		}
		s.minSubscriptionLifetimeCount = count
	}
}

func WithMethodMiddleware(mw types.MethodMiddleware) Option {
	return func(_ context.Context, s *serverConfig) {
		s.methodCallMiddleware = mw
	}
}
