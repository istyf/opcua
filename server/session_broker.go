package server

import (
	"context"
	"errors"
	mrand "math/rand"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/ualog"
)

const (
	sessionTimeoutMin     = 100 * time.Millisecond
	sessionTimeoutMax     = 1 * time.Hour
	sessionTimeoutDefault = 60 * time.Second
)

type session struct {
	cfg sessionConfig

	id                *ua.NodeID
	authTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte
	activated         bool
	authenticatedUser *auth.AuthenticatedUser

	PublishRequests chan types.PubReq
}

type sessionConfig struct {
	sessionTimeout time.Duration
	locales        []string
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s map[string]types.Session
}

func newSessionBroker() *sessionBroker {
	return &sessionBroker{
		s: make(map[string]types.Session),
	}
}

func (sb *sessionBroker) NewSession(timeout time.Duration, serverNonce []byte, remoteCert []byte) types.Session {
	s := &session{
		id:                ua.NewGUIDNodeID(1, uuid.New().String()),
		authTokenID:       ua.NewNumericNodeID(0, uint32(mrand.Int31())),
		serverNonce:       serverNonce,
		remoteCertificate: remoteCert,
		PublishRequests:   make(chan types.PubReq, 100),
		cfg: sessionConfig{
			locales:        []string{"en"},
			sessionTimeout: timeout,
		},
	}

	// Ensure session timeout is reasonable
	if s.cfg.sessionTimeout > sessionTimeoutMax || s.cfg.sessionTimeout < sessionTimeoutMin {
		s.cfg.sessionTimeout = sessionTimeoutDefault
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	sb.s[s.AuthTokenID().String()] = s

	return s
}

func (sb *sessionBroker) Close(ctx context.Context, authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if _, ok := sb.s[authToken.String()]; !ok {
		ualog.Error(ctx, "unable to close session",
			errors.New("error looking up session"),
			ualog.Any("token", authToken),
		)
	}
	delete(sb.s, authToken.String())

	return nil
}

func (sb *sessionBroker) Session(ctx context.Context, authToken *ua.NodeID) types.Session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil && authToken != nil {
		ualog.Warn(ctx, "unable to lookup session", ualog.Any("token", authToken))
	}

	return s
}

func (s *session) AuthTokenID() *ua.NodeID {
	return s.authTokenID
}

func (s *session) ID() *ua.NodeID {
	return s.id
}

func (s *session) IsSameAs(other types.Session) bool {
	if s == nil || other == nil || s.authTokenID == nil || other.AuthTokenID() == nil {
		return false
	}
	return s.authTokenID.String() == other.AuthTokenID().String()
}

func (s *session) Locales() []string {
	return s.cfg.locales
}

func (s *session) SetLocales(locales []string) {
	for idx := range len(locales) {
		// find out if this locale has a country or region component
		if lang, _, hasSeparator := strings.Cut(locales[idx], "-"); hasSeparator {
			// if it does, and the language is not present on its own in the locale list
			if idx == len(locales)-1 || slices.Index(locales[idx+1:], lang) == -1 {
				// we add the language to the list of locales
				locales = append(locales, lang)
			}
		}
	}

	s.cfg.locales = locales
}

func (s *session) PublishRequestChannel() chan types.PubReq {
	return s.PublishRequests
}

func (s *session) RemoteCertificate() []byte {
	return s.remoteCertificate
}

func (s *session) ServerNonce() []byte {
	return s.serverNonce
}

func (s *session) SetServerNonce(nonce []byte) {
	s.serverNonce = nonce
}

func (s *session) AuthenticatedUser() *auth.AuthenticatedUser {
	return s.authenticatedUser
}

func (s *session) SetAuthenticatedUser(user *auth.AuthenticatedUser) {
	s.authenticatedUser = user
}

func (s *session) TimeOutInMillis() float64 {
	fractions := s.cfg.sessionTimeout % time.Millisecond
	ms := s.cfg.sessionTimeout.Milliseconds()

	if fractions == 0 {
		return float64(ms)
	}

	return float64(ms) + (float64(fractions) / float64(time.Millisecond))
}

func (s *session) Activated() bool {
	return s.activated
}

func (s *session) SetActivated(activated bool) {
	s.activated = activated
}
