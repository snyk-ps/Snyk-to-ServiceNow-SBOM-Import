package config_test

import (
	"os"
	"path/filepath"
	"strings"
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

func TestDefaultCLIModeDoesNotRequireSnykAPISettings(t *testing.T) {
	cfg, err := config.LoadWithEnvironment(
		filepath.Join(t.TempDir(), ".env"),
		snowEnv(),
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
	if cfg.SnowAuthMethod != config.SnowAuthBearer {
		t.Fatalf(
			"SnowAuthMethod = %q, want %q",
			cfg.SnowAuthMethod,
			config.SnowAuthBearer,
		)
	}
}

func TestServiceNowAuthenticationMethods(t *testing.T) {
	tests := []struct {
		name              string
		env               map[string]string
		wantMethod        string
		wantUsername      string
		wantPassword      string
		wantErrorContains []string
	}{
		{
			name:       "default bearer",
			env:        snowEnv(),
			wantMethod: config.SnowAuthBearer,
		},
		{
			name: "bearer is normalized",
			env: merge(snowCommonEnv(), map[string]string{
				"SNOW_AUTH_METHOD":  " BeArEr ",
				"SNOW_ACCESS_TOKEN": "token",
			}),
			wantMethod: config.SnowAuthBearer,
		},
		{
			name: "basic is normalized and does not require token",
			env: merge(snowCommonEnv(), map[string]string{
				"SNOW_AUTH_METHOD": "basic",
				"SNOW_USERNAME":    "service-user",
				"SNOW_PASSWORD":    "service-password",
			}),
			wantMethod:   config.SnowAuthBasic,
			wantUsername: "service-user",
			wantPassword: "service-password",
		},
		{
			name: "basic ignores inactive bearer placeholder",
			env: merge(snowCommonEnv(), map[string]string{
				"SNOW_AUTH_METHOD":  config.SnowAuthBasic,
				"SNOW_USERNAME":     "service-user",
				"SNOW_PASSWORD":     "service-password",
				"SNOW_ACCESS_TOKEN": "MY_UNUSED_TOKEN",
			}),
			wantMethod:   config.SnowAuthBasic,
			wantUsername: "service-user",
			wantPassword: "service-password",
		},
		{
			name: "bearer ignores inactive basic placeholders",
			env: merge(snowEnv(), map[string]string{
				"SNOW_USERNAME": "MY_UNUSED_USERNAME",
				"SNOW_PASSWORD": "MY_UNUSED_PASSWORD",
			}),
			wantMethod:   config.SnowAuthBearer,
			wantUsername: "MY_UNUSED_USERNAME",
			wantPassword: "MY_UNUSED_PASSWORD",
		},
		{
			name: "unsupported method",
			env: merge(snowEnv(), map[string]string{
				"SNOW_AUTH_METHOD": "OAUTH",
			}),
			wantErrorContains: []string{"SNOW_AUTH_METHOD", "BEARER", "BASIC"},
		},
		{
			name: "bearer requires token",
			env:  snowCommonEnv(),
			wantErrorContains: []string{
				"SNOW_ACCESS_TOKEN",
			},
		},
		{
			name: "basic requires username and password",
			env: merge(snowCommonEnv(), map[string]string{
				"SNOW_AUTH_METHOD": config.SnowAuthBasic,
			}),
			wantErrorContains: []string{"SNOW_USERNAME", "SNOW_PASSWORD"},
		},
		{
			name: "selected basic placeholder fails",
			env: merge(snowCommonEnv(), map[string]string{
				"SNOW_AUTH_METHOD": config.SnowAuthBasic,
				"SNOW_USERNAME":    "MY_SNOW_USERNAME",
				"SNOW_PASSWORD":    "service-password",
			}),
			wantErrorContains: []string{
				"placeholder",
				"SNOW_USERNAME",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := config.LoadWithEnvironment(
				filepath.Join(t.TempDir(), ".env"),
				test.env,
			)
			if len(test.wantErrorContains) > 0 {
				if err == nil {
					t.Fatal("expected configuration error")
				}
				if got := apperr.ExitCode(err); got != apperr.ExitConfig {
					t.Fatalf("exit code = %d, want %d", got, apperr.ExitConfig)
				}
				for _, expected := range test.wantErrorContains {
					if !strings.Contains(err.Error(), expected) {
						t.Errorf("error = %q, want substring %q", err, expected)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadWithEnvironment() error = %v", err)
			}
			if cfg.SnowAuthMethod != test.wantMethod {
				t.Errorf("SnowAuthMethod = %q, want %q", cfg.SnowAuthMethod, test.wantMethod)
			}
			if cfg.SnowUsername != test.wantUsername {
				t.Errorf("SnowUsername = %q, want %q", cfg.SnowUsername, test.wantUsername)
			}
			if cfg.SnowPassword != test.wantPassword {
				t.Errorf("SnowPassword = %q, want %q", cfg.SnowPassword, test.wantPassword)
			}
		})
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

func TestOptionalBuildIDResolution(t *testing.T) {
	tests := []struct {
		name             string
		environmentValue string
		environmentSet   bool
		commandValue     string
		commandProvided  bool
		want             string
	}{
		{name: "neither input"},
		{
			name:             "environment only",
			environmentValue: "environment-build",
			environmentSet:   true,
			want:             "environment-build",
		},
		{
			name:            "command line only",
			commandValue:    "command-build",
			commandProvided: true,
			want:            "command-build",
		},
		{
			name:             "command line overrides environment",
			environmentValue: "environment-build",
			environmentSet:   true,
			commandValue:     "command-build",
			commandProvided:  true,
			want:             "command-build",
		},
		{
			name:             "explicit empty command line suppresses environment",
			environmentValue: "environment-build",
			environmentSet:   true,
			commandProvided:  true,
		},
		{
			name:             "whitespace environment is unavailable",
			environmentValue: "   ",
			environmentSet:   true,
		},
		{
			name:             "whitespace command line is unavailable",
			environmentValue: "environment-build",
			environmentSet:   true,
			commandValue:     "   ",
			commandProvided:  true,
		},
		{
			name:             "optional build ID is not placeholder validated",
			environmentValue: "MY_BUILD_ID",
			environmentSet:   true,
			want:             "MY_BUILD_ID",
		},
		{
			name:            "internal spaces and special characters are preserved",
			commandValue:    "release 42/A&B",
			commandProvided: true,
			want:            "release 42/A&B",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := snowEnv()
			if test.environmentSet {
				environment["BUILD_ID"] = test.environmentValue
			}
			cfg, err := config.LoadWithEnvironment(
				filepath.Join(t.TempDir(), ".env"),
				environment,
			)
			if err != nil {
				t.Fatalf("LoadWithEnvironment() error = %v", err)
			}

			cfg = cfg.WithBuildIDOverride(test.commandValue, test.commandProvided)
			if cfg.BuildID != test.want {
				t.Fatalf("BuildID = %q, want %q", cfg.BuildID, test.want)
			}
		})
	}
}

func TestBuildIDDoesNotMakeBusinessApplicationOptional(t *testing.T) {
	_, err := config.LoadWithEnvironment(
		filepath.Join(t.TempDir(), ".env"),
		map[string]string{
			"SNOW_INSTANCE_SUBDOMAIN": "instance",
			"SNOW_ACCESS_TOKEN":       "snow-token",
			"BUILD_ID":                "build-42",
		},
	)
	if err == nil {
		t.Fatal("expected missing SNOW_BUSINESS_APPLICATION_ID error")
	}
	if !strings.Contains(err.Error(), "SNOW_BUSINESS_APPLICATION_ID") {
		t.Fatalf("error = %q, want SNOW_BUSINESS_APPLICATION_ID", err)
	}
}

func snowEnv() map[string]string {
	return merge(snowCommonEnv(), map[string]string{
		"SNOW_ACCESS_TOKEN": "snow-token",
	})
}

func snowCommonEnv() map[string]string {
	return map[string]string{
		"SNOW_INSTANCE_SUBDOMAIN":      "instance",
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
