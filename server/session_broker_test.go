package server

import (
	"testing"

	"github.com/gopcua/opcua/server/auth"
	"github.com/gopcua/opcua/ua"
)

func TestSessionIsSameAs(t *testing.T) {
	t.Parallel()

	first := &session{authTokenID: ua.NewNumericNodeID(1, 1)}
	same := &session{authTokenID: ua.NewNumericNodeID(1, 1)}
	different := &session{authTokenID: ua.NewNumericNodeID(1, 2)}

	if !first.IsSameAs(same) {
		t.Fatal("expected sessions with the same auth token to match")
	}
	if first.IsSameAs(different) {
		t.Fatal("expected sessions with different auth tokens not to match")
	}
	if first.IsSameAs(nil) {
		t.Fatal("expected nil session not to match")
	}
}

func TestSessionAuthenticatedUserZeroValue(t *testing.T) {
	t.Parallel()

	sess := &session{}

	if sess.Activated() {
		t.Fatal("expected new session to start inactive")
	}
	if sess.AuthenticatedUser() != nil {
		t.Fatalf("expected unauthenticated session to expose nil authenticated user, got %#v", sess.AuthenticatedUser())
	}
}

func TestSessionSetActivated(t *testing.T) {
	t.Parallel()

	sess := &session{}

	sess.SetActivated(true)
	if !sess.Activated() {
		t.Fatal("expected session to be active after SetActivated(true)")
	}

	sess.SetActivated(false)
	if sess.Activated() {
		t.Fatal("expected session to be inactive after SetActivated(false)")
	}
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
	if sess.AuthenticatedUser() != first {
		t.Fatalf("expected authenticated user %#v, got %#v", first, sess.AuthenticatedUser())
	}

	sess.SetAuthenticatedUser(second)
	if sess.AuthenticatedUser() != second {
		t.Fatalf("expected replacement authenticated user %#v, got %#v", second, sess.AuthenticatedUser())
	}

	sess.SetAuthenticatedUser(nil)
	if sess.AuthenticatedUser() != nil {
		t.Fatalf("expected clearing authenticated user to restore nil, got %#v", sess.AuthenticatedUser())
	}
}
