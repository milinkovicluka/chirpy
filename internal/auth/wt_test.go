package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	token, err := MakeJWT(userID, "secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	got, err := ValidateJWT(token, "secret")
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}
	if got != userID {
		t.Fatalf("got user ID %v, want %v", got, userID)
	}
}

func TestValidateJWTRejectsBadTokens(t *testing.T) {
	userID := uuid.New()

	valid, err := MakeJWT(userID, "secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	expired, err := MakeJWT(userID, "secret", -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	tests := []struct {
		name   string
		token  string
		secret string
	}{
		{"expired token", expired, "secret"},
		{"wrong secret", valid, "wrong-secret"},
		{"garbage token", "not.a.jwt", "secret"},
		{"empty token", "", "secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateJWT(tc.token, tc.secret)
			if err == nil {
				t.Fatalf("expected an error, got user ID %v", got)
			}
			if got != uuid.Nil {
				t.Fatalf("expected uuid.Nil on error, got %v", got)
			}
		})
	}
}
