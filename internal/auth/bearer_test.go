package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		set     bool
		want    string
		wantErr bool
	}{
		{"valid", "Bearer abc.def.ghi", true, "abc.def.ghi", false},
		{"extra whitespace", "Bearer    abc.def.ghi  ", true, "abc.def.ghi", false},
		{"lowercase scheme", "bearer abc", true, "abc", false},
		{"missing header", "", false, "", true},
		{"no token", "Bearer ", true, "", true},
		{"wrong scheme", "Basic abc", true, "", true},
		{"no scheme", "abc.def.ghi", true, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.set {
				headers.Set("Authorization", tc.header)
			}
			got, err := GetBearerToken(headers)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		set     bool
		want    string
		wantErr bool
	}{
		{"valid", "ApiKey f271c81ff7084ee5b99a5091b42d486e", true, "f271c81ff7084ee5b99a5091b42d486e", false},
		{"extra whitespace", "ApiKey   abc123  ", true, "abc123", false},
		{"missing header", "", false, "", true},
		{"no key", "ApiKey ", true, "", true},
		{"bearer instead", "Bearer abc123", true, "", true},
		{"no scheme", "abc123", true, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.set {
				headers.Set("Authorization", tc.header)
			}
			got, err := GetAPIKey(headers)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
