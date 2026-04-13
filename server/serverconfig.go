package server

import (
	"crypto/rsa"
	"time"

	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
)

type authMode struct {
	tokenType ua.UserTokenType
}

type security struct {
	secPolicy string
	secMode   ua.MessageSecurityMode
}

type serverConfig struct {
	privateKey     *rsa.PrivateKey
	certificate    []byte
	applicationURI string

	endpoints []string

	applicationName  string
	manufacturerName string
	productName      string
	softwareVersion  string

	enabledSec  []security
	enabledAuth []authMode

	cap ServerCapabilities

	maxBrowseContinuationPoints       uint32
	maxBrowseOperationsPerCall        uint32
	maxSubscriptions                  uint32
	maxSubscriptionsPerSession        uint32
	maxSubscriptionOperationsPerCall  uint32
	minSubscriptionPublishingInterval time.Duration
	minSubscriptionMaxKeepAliveCount  uint32
	minSubscriptionLifetimeCount      uint32

	methodCallMiddleware  types.MethodMiddleware
	userNameAuthenticator UserNameAuthenticator
}

var capabilities = ServerCapabilities{
	OperationalLimits: OperationalLimits{
		MaxNodesPerRead: 32,
	},
}

type ServerCapabilities struct {
	OperationalLimits OperationalLimits
}

type OperationalLimits struct {
	MaxNodesPerRead uint32
}

func (cfg *serverConfig) ApplicationURI() string {
	return cfg.applicationURI
}

func (cfg *serverConfig) Certificate() []byte {
	return cfg.certificate
}

func (cfg *serverConfig) PrivateKey() *rsa.PrivateKey {
	return cfg.privateKey
}

func (cfg *serverConfig) Endpoints() []string {
	return cfg.endpoints
}

func (cfg *serverConfig) ManufacturerName() string {
	return cfg.manufacturerName
}

func (cfg *serverConfig) MaxNodesPerRead() uint32 {
	return cfg.cap.OperationalLimits.MaxNodesPerRead
}

func (cfg *serverConfig) MaxBrowseOperationsPerCall() uint32 {
	return cfg.maxBrowseOperationsPerCall
}

func (cfg *serverConfig) MaxBrowseContinuationPoints() uint32 {
	return cfg.maxBrowseContinuationPoints
}

func (cfg *serverConfig) MaxSubscriptions() uint32 {
	return cfg.maxSubscriptions
}

func (cfg *serverConfig) MaxSubscriptionsPerSession() uint32 {
	return cfg.maxSubscriptionsPerSession
}

func (cfg *serverConfig) MaxSubscriptionOperationsPerCall() uint32 {
	return cfg.maxSubscriptionOperationsPerCall
}

func (cfg *serverConfig) MinSubscriptionPublishingInterval() time.Duration {
	return cfg.minSubscriptionPublishingInterval
}

func (cfg *serverConfig) MinSubscriptionMaxKeepAliveCount() uint32 {
	return cfg.minSubscriptionMaxKeepAliveCount
}

func (cfg *serverConfig) MinSubscriptionLifetimeCount() uint32 {
	return cfg.minSubscriptionLifetimeCount
}

func (cfg *serverConfig) ProductName() string {
	return cfg.productName
}

func (cfg *serverConfig) SoftwareVersion() string {
	return cfg.softwareVersion
}

func (cfg *serverConfig) MethodCallMiddleware() types.MethodMiddleware {
	return cfg.methodCallMiddleware
}
