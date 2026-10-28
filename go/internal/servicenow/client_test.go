package servicenow_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
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
				if _, present := r.URL.Query()["buildId"]; present {
					t.Error("buildId was present without build ID configuration")
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

func TestUploadUsesSelectedServiceNowAuthentication(t *testing.T) {
	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	token := derivedTestValue(t, "t")
	username := derivedTestValue(t, "u")
	password := derivedTestValue(t, "p")
	basicCredentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	tests := []struct {
		name       string
		authMethod string
		wantHeader string
	}{
		{
			name:       "bearer uses token when both credential sets exist",
			authMethod: config.SnowAuthBearer,
			wantHeader: "Bearer " + token,
		},
		{
			name:       "basic uses username and password when both credential sets exist",
			authMethod: config.SnowAuthBasic,
			wantHeader: "Basic " + basicCredentials,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != test.wantHeader {
					t.Errorf("Authorization = %q, want %q", got, test.wantHeader)
				}
				if got := r.URL.Query().Get("businessApplicationId"); got != "app-id" {
					t.Errorf("businessApplicationId = %q, want app-id", got)
				}
				if got := r.URL.Query().Get("sbomSource"); got != "SnykCLI" {
					t.Errorf("sbomSource = %q, want SnykCLI", got)
				}
				for _, credential := range []string{token, username, password} {
					if strings.Contains(r.URL.String(), credential) {
						t.Errorf("URL contains credential %q", credential)
					}
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != string(payload) {
					t.Errorf("body = %q, want %q", body, payload)
				}
				for _, credential := range []string{token, username, password} {
					if strings.Contains(string(body), credential) {
						t.Errorf("body contains credential %q", credential)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"result":"ok"}`)
			}))
			defer server.Close()

			logger := applog.New("ERROR", io.Discard)
			cfg := config.Config{
				SnowAuthMethod:            test.authMethod,
				SnowAccessToken:           token,
				SnowUsername:              username,
				SnowPassword:              password,
				SnowBusinessApplicationID: "app-id",
				RunMode:                   config.ModeCLI,
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

func TestAuthenticationFailureGuidanceMatchesSelectedMethod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	token := derivedTestValue(t, "t")
	username := derivedTestValue(t, "u")
	password := derivedTestValue(t, "p")

	tests := []struct {
		name          string
		authMethod    string
		status        int
		wantVariables []string
	}{
		{
			name:          "bearer unauthorized",
			authMethod:    config.SnowAuthBearer,
			status:        http.StatusUnauthorized,
			wantVariables: []string{"SNOW_ACCESS_TOKEN"},
		},
		{
			name:          "basic forbidden",
			authMethod:    config.SnowAuthBasic,
			status:        http.StatusForbidden,
			wantVariables: []string{"SNOW_USERNAME", "SNOW_PASSWORD"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "denied", test.status)
			}))
			defer server.Close()

			logger := applog.New("ERROR", io.Discard)
			cfg := config.Config{
				SnowAuthMethod:            test.authMethod,
				SnowAccessToken:           token,
				SnowUsername:              username,
				SnowPassword:              password,
				SnowBusinessApplicationID: "app-id",
				RunMode:                   config.ModeCLI,
				HTTPTimeout:               time.Second,
			}
			client := servicenow.NewWithBaseURL(
				cfg,
				httpx.NewWithHTTPClient(server.Client(), logger),
				logger,
				server.URL,
			)
			_, err := client.Upload(context.Background(), path)
			if err == nil {
				t.Fatal("expected authentication error")
			}
			if got := apperr.ExitCode(err); got != apperr.ExitAuth {
				t.Fatalf("exit code = %d, want %d", got, apperr.ExitAuth)
			}

			var appErr *apperr.Error
			if !errors.As(err, &appErr) {
				t.Fatalf("error type = %T, want *apperr.Error", err)
			}
			for _, variable := range test.wantVariables {
				if !strings.Contains(appErr.NextStep, variable) {
					t.Errorf("NextStep = %q, want %s", appErr.NextStep, variable)
				}
			}
			for _, secret := range []string{
				cfg.SnowAccessToken,
				cfg.SnowUsername,
				cfg.SnowPassword,
			} {
				if strings.Contains(appErr.NextStep, secret) {
					t.Errorf("NextStep leaked credential %q", secret)
				}
			}
		})
	}
}

func TestUploadBuildIDResolutionAndEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                string
		environmentBuildID  string
		environmentSet      bool
		commandBuildID      string
		commandProvided     bool
		wantBuildID         string
		wantBuildIDPresent  bool
		wantRawBuildIDValue string
	}{
		{
			name: "neither input omits build ID",
		},
		{
			name:               "environment build ID",
			environmentBuildID: "environment-build",
			environmentSet:     true,
			wantBuildID:        "environment-build",
			wantBuildIDPresent: true,
		},
		{
			name:               "command line build ID",
			commandBuildID:     "command-build",
			commandProvided:    true,
			wantBuildID:        "command-build",
			wantBuildIDPresent: true,
		},
		{
			name:               "command line overrides environment",
			environmentBuildID: "environment-build",
			environmentSet:     true,
			commandBuildID:     "command-build",
			commandProvided:    true,
			wantBuildID:        "command-build",
			wantBuildIDPresent: true,
		},
		{
			name:               "explicit empty command line suppresses environment",
			environmentBuildID: "environment-build",
			environmentSet:     true,
			commandProvided:    true,
		},
		{
			name:               "whitespace command line omits build ID",
			environmentBuildID: "environment-build",
			environmentSet:     true,
			commandBuildID:     "   ",
			commandProvided:    true,
		},
		{
			name:                "special characters are encoded",
			commandBuildID:      "release 42/A&B=ready?#1",
			commandProvided:     true,
			wantBuildID:         "release 42/A&B=ready?#1",
			wantBuildIDPresent:  true,
			wantRawBuildIDValue: "release+42%2FA%26B%3Dready%3F%231",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := map[string]string{
				"SNOW_INSTANCE_SUBDOMAIN":      "instance",
				"SNOW_ACCESS_TOKEN":            "secret",
				"SNOW_BUSINESS_APPLICATION_ID": "app-id",
			}
			if test.environmentSet {
				environment["BUILD_ID"] = test.environmentBuildID
			}
			cfg, err := config.LoadWithEnvironment(
				filepath.Join(t.TempDir(), ".env"),
				environment,
			)
			if err != nil {
				t.Fatalf("LoadWithEnvironment() error = %v", err)
			}
			cfg = cfg.WithBuildIDOverride(test.commandBuildID, test.commandProvided)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				values, present := query["buildId"]
				if present != test.wantBuildIDPresent {
					t.Errorf("buildId presence = %t, want %t", present, test.wantBuildIDPresent)
				}
				if present && (len(values) != 1 || values[0] != test.wantBuildID) {
					t.Errorf("buildId = %v, want %q", values, test.wantBuildID)
				}
				if !test.wantBuildIDPresent && strings.Contains(r.URL.RawQuery, "buildId=") {
					t.Errorf("raw query unexpectedly contains buildId: %q", r.URL.RawQuery)
				}
				if test.wantRawBuildIDValue != "" &&
					!strings.Contains(r.URL.RawQuery, "buildId="+test.wantRawBuildIDValue) {
					t.Errorf(
						"raw query = %q, want encoded buildId=%s",
						r.URL.RawQuery,
						test.wantRawBuildIDValue,
					)
				}
				if got := query.Get("businessApplicationId"); got != "app-id" {
					t.Errorf("businessApplicationId = %q, want app-id", got)
				}
				if got := query.Get("sbomSource"); got != "SnykCLI" {
					t.Errorf("sbomSource = %q, want SnykCLI", got)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"result":"ok"}`)
			}))
			defer server.Close()

			logger := applog.New("ERROR", io.Discard)
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

func derivedTestValue(t *testing.T, discriminator string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(t.Name() + discriminator))
}
