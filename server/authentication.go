package server

import (
	"context"

	"github.com/gopcua/opcua/server/types"
)

// AuthenticatedUser contains the authenticated identity information returned by
// a username/password authenticator.
//
// This structure is intentionally focused on identity data needed by the
// server today. Extra backend-specific data can be attached through Attributes.
// Role assignment will be added later as a follow-on feature rather than being
// folded into the initial authentication contract.
type AuthenticatedUser struct {
	UserName string
	Subject  string

	Attributes map[string]any
}

// UserNameAuthenticationRequest contains the decoded username and password from
// an ActivateSession request together with the session being activated.
type UserNameAuthenticationRequest struct {
	Session  types.Session
	UserName string
	Password string
}

// UserNameAuthenticator verifies a decoded username/password pair during
// ActivateSession.
//
// Returning a non-nil error rejects the activation. On success, the callback
// returns the authenticated user context to store on the session.
type UserNameAuthenticator func(context.Context, *UserNameAuthenticationRequest) (*AuthenticatedUser, error)
