package server

import (
	"testing"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
)

func TestSessionIsSameAs(t *testing.T) {
	t.Parallel()

	first := &session{authTokenID: ua.NewNumericNodeID(1, 1)}
	same := &session{authTokenID: ua.NewNumericNodeID(1, 1)}
	different := &session{authTokenID: ua.NewNumericNodeID(1, 2)}

	assert.True(t, first.IsSameAs(same))
	assert.False(t, first.IsSameAs(different))
	assert.False(t, first.IsSameAs(nil))
}

func TestSessionAuthenticatedUserZeroValue(t *testing.T) {
	t.Parallel()

	sess := &session{}

	assert.False(t, sess.Activated())
	assert.Nil(t, sess.AuthenticatedUser())
}

func TestSessionSetActivated(t *testing.T) {
	t.Parallel()

	sess := &session{}

	sess.SetActivated(true)
	assert.True(t, sess.Activated())

	sess.SetActivated(false)
	assert.False(t, sess.Activated())
}

func TestSessionSetAuthenticatedUser(t *testing.T) {
	t.Parallel()

	sess := &session{}
	first := &auth.AuthenticatedUser{
		UserName: "alice",
		Subject:  "user:alice",
	}
	second := &auth.AuthenticatedUser{
		UserName: "bob",
		Subject:  "user:bob",
	}

	sess.SetAuthenticatedUser(first)
	assert.Same(t, first, sess.AuthenticatedUser())

	sess.SetAuthenticatedUser(second)
	assert.Same(t, second, sess.AuthenticatedUser())

	sess.SetAuthenticatedUser(nil)
	assert.Nil(t, sess.AuthenticatedUser())
}
