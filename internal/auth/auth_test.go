package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   error
	}{
		{
			name:        "Valid Authorization Header",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey: "abc123",
			expectErr:   nil,
		},
		{
			name:        "Malformed Authorization Header - missing header",
			headers:     http.Header{},
			expectedKey: "",
			expectErr:   auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - no ApiKey",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey: "",
			expectErr:   auth.ErrMalformedAuthorizationHeader,
		},
		{
			name:        "Malformed Authorization Header - no value",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectErr:   auth.ErrMalformedAuthorizationHeader,
		},
		{
			name:        "Malformed Authorization Header - invalid seperator 1",
			headers:     http.Header{"Authorization": []string{"ApiKey  abc123"}},
			expectedKey: "",
			expectErr:   nil,
		},
		{
			name:        "Malformed Authorization Header - invalid seperator 2",
			headers:     http.Header{"Authorization": []string{"ApiKey**abc123"}},
			expectedKey: "",
			expectErr:   auth.ErrMalformedAuthorizationHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := auth.GetAPIKey(test.headers)
			if key != test.expectedKey {
				t.Errorf("expected key %q, got %q", test.expectedKey, key)
			}
			if !errors.Is(err, test.expectErr) {
				t.Errorf("expected error %v, got %v", test.expectErr, err)
			}
		})
	}
}
