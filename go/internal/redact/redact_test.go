package redact_test

import (
	"strings"
	"testing"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/redact"
)

func TestSecretsAreRedacted(t *testing.T) {
	secret := "THE_REAL_SECRET"
	tests := []struct {
		key   string
		value string
		want  string
	}{
		{key: "Authorization", value: "Bearer " + secret, want: "Bearer " + redact.Mask},
		{key: "SNYK_API_TOKEN", value: secret, want: redact.Mask},
		{key: "password", value: secret, want: redact.Mask},
		{key: "Set-Cookie", value: "session=" + secret, want: redact.Mask},
		{key: "SNYK_ORG_ID", value: "org-id", want: "org-id"},
	}
	for _, test := range tests {
		if got := redact.Value(test.key, test.value); got != test.want {
			t.Errorf("Value(%q) = %q, want %q", test.key, got, test.want)
		}
	}

	summary := redact.HeaderSummary(map[string]string{
		"Authorization": "Bearer " + secret,
		"Accept":        "application/json",
	})
	if strings.Contains(summary, secret) {
		t.Fatalf("HeaderSummary leaked secret: %s", summary)
	}
	if !strings.Contains(summary, "Bearer "+redact.Mask) {
		t.Fatalf("HeaderSummary did not preserve scheme + mask: %s", summary)
	}
}

func TestBodyRedactsNestedJSONAndOmitsArbitraryText(t *testing.T) {
	secret := "THE_REAL_SECRET"
	body := []byte(`{"data":{"access_token":"` + secret + `"},"ok":true}`)
	got := redact.Body(body)
	if strings.Contains(got, secret) || !strings.Contains(got, redact.Mask) {
		t.Fatalf("Body() did not safely redact JSON: %s", got)
	}

	nonJSON := redact.Body([]byte("token=" + secret))
	if strings.Contains(nonJSON, secret) || !strings.Contains(nonJSON, "omitted") {
		t.Fatalf("Body() leaked non-JSON body: %s", nonJSON)
	}
}
