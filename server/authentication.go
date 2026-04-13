package server

import (
	"context"

	"github.com/gopcua/opcua/server/types"
)

// UserNameAuthenticationRequest contains the decoded username and password from
// an ActivateSession request together with the session being activated.
//
// The callback result is intentionally left opaque for now; later steps will
// define how authenticated user context is stored on sessions and exposed to
// the rest of the server.
type UserNameAuthenticationRequest struct {
	Session  types.Session
	UserName string
	Password string
}

// UserNameAuthenticator verifies a decoded username/password pair during
// ActivateSession.
//
// Returning a non-nil error rejects the activation. A successful result may
// return any backend-specific user context, which will be interpreted and
// stored by later authentication work.
type UserNameAuthenticator func(context.Context, *UserNameAuthenticationRequest) (any, error)
