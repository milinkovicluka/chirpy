package auth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrNoAuthHeaderIncluded is returned when the request has no Authorization header.
var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetBearerToken extracts TOKEN_STRING from an "Authorization: Bearer TOKEN_STRING" header.
func GetBearerToken(headers http.Header) (string, error) {
	return getAuthorizationValue(headers, "Bearer")
}

// GetAPIKey extracts THE_KEY from an "Authorization: ApiKey THE_KEY" header.
func GetAPIKey(headers http.Header) (string, error) {
	return getAuthorizationValue(headers, "ApiKey")
}

// getAuthorizationValue returns the value after "<scheme> " in the Authorization header.
func getAuthorizationValue(headers http.Header, scheme string) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}

	prefix := scheme + " "
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", errors.New("malformed authorization header")
	}

	value := strings.TrimSpace(authHeader[len(prefix):])
	if value == "" {
		return "", errors.New("malformed authorization header")
	}
	return value, nil
}
