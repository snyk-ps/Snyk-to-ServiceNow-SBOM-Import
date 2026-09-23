package servicenow_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/servicenow"
)

func TestUploadUsesModeSpecificSourceAndUnmodifiedBytes(t *testing.T) {
	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode   string
		source string
	}{
		{mode: config.ModeAPI, source: "SnykAPI"},
		{mode: config.ModeCLI, source: "SnykCLI"},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/sbom/core/upload" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if got := r.URL.Query().Get("businessApplicationId"); got != "app-id" {
					t.Errorf("businessApplicationId = %q", got)
				}
				if got := r.URL.Query().Get("sbomSource"); got != test.source {
					t.Errorf("sbomSource = %q, want %q", got, test.source)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer secret" {
					t.Errorf("Authorization = %q", got)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q", got)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != string(payload) {
					t.Errorf("body = %q, want %q", body, payload)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"result":"ok"}`)
			}))
			defer server.Close()

			logger := applog.New("ERROR", io.Discard)
			cfg := config.Config{
				SnowAccessToken:           "secret",
				SnowBusinessApplicationID: "app-id",
				RunMode:                   test.mode,
				HTTPTimeout:               time.Second,
			}
			client := servicenow.NewWithBaseURL(
				cfg,
				httpx.NewWithHTTPClient(server.Client(), logger),
				logger,
				server.URL,
			)
			if _, err := client.Upload(context.Background(), path); err != nil {
				t.Fatalf("Upload() error = %v", err)
			}
		})
	}
}
