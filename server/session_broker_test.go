package server

import (
	"testing"

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
