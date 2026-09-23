package snyk_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

func TestGenerateMaps404ToUnsupported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	logger := applog.New("ERROR", io.Discard)
	cfg := config.Config{
		SnykAPIToken:   "token",
		SnykOrgID:      "org",
		SnykBaseURL:    server.URL,
		SnykSBOMFormat: config.DefaultSBOMFormat,
		HTTPTimeout:    time.Second,
		SSLVerify:      true,
	}
	client := snyk.New(
		cfg,
		httpx.NewWithHTTPClient(server.Client(), logger),
		logger,
	)

	_, err := client.Generate(context.Background(), "project")
	if !apperr.IsUnsupported(err) {
		t.Fatalf("Generate() error = %v, want unsupported", err)
	}
	if got := apperr.ExitCode(err); got != apperr.ExitSBOMGeneration {
		t.Fatalf("ExitCode() = %d, want %d", got, apperr.ExitSBOMGeneration)
	}
}
