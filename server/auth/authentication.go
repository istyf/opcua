package auth

import (
	"context"
	"errors"

	"github.com/gopcua/opcua/ua"
)

var (
	// ErrInvalidCredentials indicates the backend rejected the supplied
	// username/password pair.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrBackendUnavailable indicates the authentication backend is
	// temporarily unavailable.
	ErrBackendUnavailable = errors.New("backend unavailable")
	// ErrUnsupportedAuthentication indicates the backend does not support the
	// requested authentication flow.
	ErrUnsupportedAuthentication = errors.New("unsupported authentication")
)

// AuthenticatedUser contains the authenticated identity information attached to
// a session after successful user authentication.
//
// This structure is intentionally focused on identity data needed by the
// server today. Extra backend-specific data can be attached through
// Attributes. Role assignment will be added later as a follow-on feature.
type AuthenticatedUser struct {
	UserName string
	Subject  string

	Attributes map[string]any
}

// UserNameAuthenticationRequest contains the decoded username and password from
// an ActivateSession request together with identifiers for the session being
// activated.
type UserNameAuthenticationRequest struct {
	// SessionID is the server-side session identifier returned by CreateSession.
	SessionID *ua.NodeID
	// AuthenticationToken is the opaque token that later requests use to bind to
	// the session.
	AuthenticationToken *ua.NodeID
	UserName            string
	Password            string
}

// UserNameAuthenticator verifies a decoded username/password pair during
// ActivateSession.
//
// Returning a non-nil error rejects the activation. On success, the callback
// returns the authenticated user context to store on the session. Role
// assignment is intentionally out of scope for this first pass and will be
// added in follow-on work.
type UserNameAuthenticator func(context.Context, *UserNameAuthenticationRequest) (*AuthenticatedUser, error)
