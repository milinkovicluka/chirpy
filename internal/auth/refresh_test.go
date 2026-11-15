package auth

import (
	"encoding/hex"
	"testing"
)

func TestMakeRefreshToken(t *testing.T) {
	a := MakeRefreshToken()
	b := MakeRefreshToken()

	if len(a) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}
	if a == b {
		t.Fatal("two refresh tokens should not be equal")
	}
}
