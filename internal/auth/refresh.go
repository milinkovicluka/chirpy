package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// MakeRefreshToken returns a random 256-bit token encoded as 64 hex characters.
func MakeRefreshToken() string {
	key := make([]byte, 32)
	rand.Read(key) // crypto/rand.Read never returns an error since Go 1.24
	return hex.EncodeToString(key)
}
