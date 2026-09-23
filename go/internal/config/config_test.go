package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
)

func TestValidation(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantCode int
	}{
		{
			name: "invalid run mode",
			env: merge(snowEnv(), map[string]string{
				"RUN_MODE": "BOGUS",
			}),
			wantCode: apperr.ExitConfig,
		},
		{
			name: "invalid scope",
			env: merge(snowEnv(), map[string]string{
				"RUN_MODE":               config.ModeAPI,
				"SNOW_APPLICATION_SCOPE": "BOGUS",
			}),
			wantCode: apperr.ExitConfig,
		},
		{
			name: "API mode missing Snyk variables",
			env: merge(snowEnv(), map[string]string{
				"RUN_MODE": config.ModeAPI,
			}),
			wantCode: apperr.ExitConfig,
		},
		{
			name: "API project scope missing target and project",
			env: merge(snowEnv(), map[string]string{
				"RUN_MODE":               config.ModeAPI,
				"SNYK_API_TOKEN":         "token",
				"SNYK_ORG_ID":            "org",
				"SNOW_APPLICATION_SCOPE": config.ScopeProject,
			}),
			wantCode: apperr.ExitConfig,
		},
		{
			name: "placeholder fails",
			env: merge(snowEnv(), map[string]string{
				"RUN_MODE":               config.ModeAPI,
				"SNYK_API_TOKEN":         "MY_TOKEN",
				"SNYK_ORG_ID":            "org",
				"SNYK_TARGET_ID":         "target",
				"SNYK_PROJECT_ID":        "project",
				"SNOW_APPLICATION_SCOPE": config.ScopeProject,
			}),
			wantCode: apperr.ExitConfig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.LoadWithEnvironment(filepath.Join(t.TempDir(), ".env"), test.env)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := apperr.ExitCode(err); got != test.wantCode {
				t.Fatalf("exit code = %d, want %d (err: %v)", got, test.wantCode, err)
			}
		})
	}
}

func TestCLIModeDoesNotRequireSnykAPISettings(t *testing.T) {
	cfg, err := config.LoadWithEnvironment(
		filepath.Join(t.TempDir(), ".env"),
		merge(snowEnv(), map[string]string{"RUN_MODE": config.ModeCLI}),
	)
	if err != nil {
		t.Fatalf("LoadWithEnvironment() error = %v", err)
	}
	if cfg.RunMode != config.ModeCLI {
		t.Fatalf("RunMode = %q, want %q", cfg.RunMode, config.ModeCLI)
	}
	if cfg.SBOMSource() != "SnykCLI" {
		t.Fatalf("SBOMSource() = %q, want SnykCLI", cfg.SBOMSource())
	}
}

func TestAPIModeDefaultsAndEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	dotenv := "" +
		"RUN_MODE='SNYK_API'\n" +
		"SNYK_API_TOKEN='from-file'\n" +
		"SNYK_ORG_ID='org'\n" +
		"SNOW_APPLICATION_SCOPE='SNYK_ORG'\n" +
		"SNOW_INSTANCE_SUBDOMAIN='instance'\n" +
		"SNOW_ACCESS_TOKEN='snow-token'\n" +
		"SNOW_BUSINESS_APPLICATION_ID='app'\n" +
		"API_DRY_RUN='true'\n"
	if err := os.WriteFile(path, []byte(dotenv), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadWithEnvironment(path, map[string]string{
		"SNYK_API_TOKEN": "from-process-env",
	})
	if err != nil {
		t.Fatalf("LoadWithEnvironment() error = %v", err)
	}
	if cfg.SnykAPIToken != "from-process-env" {
		t.Fatalf("SnykAPIToken = %q, want process environment value", cfg.SnykAPIToken)
	}
	if cfg.SnykBaseURL != config.DefaultSnykBaseURL {
		t.Fatalf("SnykBaseURL = %q, want %q", cfg.SnykBaseURL, config.DefaultSnykBaseURL)
	}
	if cfg.SnykSBOMFormat != config.DefaultSBOMFormat {
		t.Fatalf("SnykSBOMFormat = %q, want %q", cfg.SnykSBOMFormat, config.DefaultSBOMFormat)
	}
	if !cfg.APIDryRun {
		t.Fatal("APIDryRun = false, want true")
	}
	if cfg.HTTPTimeout != 60*time.Second {
		t.Fatalf("HTTPTimeout = %s, want 60s", cfg.HTTPTimeout)
	}
	if cfg.SBOMSource() != "SnykAPI" {
		t.Fatalf("SBOMSource() = %q, want SnykAPI", cfg.SBOMSource())
	}
}

func snowEnv() map[string]string {
	return map[string]string{
		"SNOW_INSTANCE_SUBDOMAIN":      "instance",
		"SNOW_ACCESS_TOKEN":            "snow-token",
		"SNOW_BUSINESS_APPLICATION_ID": "app-id",
	}
}

func merge(first, second map[string]string) map[string]string {
	result := make(map[string]string, len(first)+len(second))
	for key, value := range first {
		result[key] = value
	}
	for key, value := range second {
		result[key] = value
	}
	return result
}
