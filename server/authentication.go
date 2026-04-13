package server

import (
	"context"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/server/types"
)

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
type UserNameAuthenticator func(context.Context, *UserNameAuthenticationRequest) (*auth.AuthenticatedUser, error)
