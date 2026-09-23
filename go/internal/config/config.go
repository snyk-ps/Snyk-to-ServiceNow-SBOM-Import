// Package config loads .env/environment settings and enforces mode/scope rules.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
)

const (
	ModeAPI = "SNYK_API"
	ModeCLI = "SNYK_CLI"

	ScopeProject = "SNYK_PROJECT"
	ScopeTarget  = "SNYK_TARGET"
	ScopeOrg     = "SNYK_ORG"

	DefaultSBOMFormat  = "cyclonedx1.6+json"
	DefaultSnykBaseURL = "https://api.snyk.io/rest"
	DefaultDebugLevel  = "INFO"
	DefaultHTTPTimeout = 60 * time.Second
)

var (
	validRunModes = []string{ModeAPI, ModeCLI}
	validScopes   = []string{ScopeProject, ScopeTarget, ScopeOrg}

	snowRequired = []string{
		"SNOW_INSTANCE_SUBDOMAIN",
		"SNOW_ACCESS_TOKEN",
		"SNOW_BUSINESS_APPLICATION_ID",
	}
	apiRequired = []string{
		"SNYK_API_TOKEN",
		"SNYK_ORG_ID",
	}
	scopeRequired = map[string][]string{
		ScopeProject: {"SNYK_TARGET_ID", "SNYK_PROJECT_ID"},
		ScopeTarget:  {"SNYK_TARGET_ID"},
		ScopeOrg:     {},
	}
	truthy = map[string]struct{}{
		"true": {}, "1": {}, "yes": {}, "on": {}, "y": {}, "t": {},
	}
)

// Config is the immutable runtime configuration after validation.
type Config struct {
	SnykAPIToken       string
	SnykOrgID          string
	SnykTargetID       string
	SnykProjectID      string
	SnykBaseURL        string
	SnykRESTAPIVersion string
	SnykSBOMFormat     string

	SnowInstanceSubdomain     string
	SnowAccessToken           string
	SnowBusinessApplicationID string
	SnowApplicationScope      string

	RunMode string

	DebugLevel  string
	APIDryRun   bool
	HTTPTimeout time.Duration
	SSLVerify   bool
	CABundle    string
}

// SnowBaseURL returns the ServiceNow instance origin.
func (c Config) SnowBaseURL() string {
	return "https://" + c.SnowInstanceSubdomain + ".service-now.com"
}

// SBOMSource returns the ServiceNow source marker for the run mode.
func (c Config) SBOMSource() string {
	if c.RunMode == ModeCLI {
		return "SnykCLI"
	}
	return "SnykAPI"
}

// Load reads .env in the current directory, overlays the process environment,
// applies defaults, and validates the result.
func Load() (Config, error) {
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			environment[key] = value
		}
	}
	return LoadWithEnvironment(".env", environment)
}

// LoadWithEnvironment allows deterministic tests while retaining normal .env semantics.
func LoadWithEnvironment(dotEnvPath string, environment map[string]string) (Config, error) {
	values, err := readDotEnv(dotEnvPath)
	if err != nil {
		return Config{}, err
	}
	for key, value := range environment {
		values[key] = value // process environment wins
	}

	runMode := strings.ToUpper(get(values, "RUN_MODE", ModeAPI))
	if !contains(validRunModes, runMode) {
		return Config{}, &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  fmt.Sprintf("Invalid RUN_MODE: %q.", runMode),
			Op:       "load_config",
			NextStep: "Set RUN_MODE to one of: " + strings.Join(validRunModes, ", ") + ".",
		}
	}

	scope := strings.ToUpper(get(values, "SNOW_APPLICATION_SCOPE", ScopeProject))
	if !contains(validScopes, scope) {
		return Config{}, &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  fmt.Sprintf("Invalid SNOW_APPLICATION_SCOPE: %q.", scope),
			Op:       "load_config",
			NextStep: "Set SNOW_APPLICATION_SCOPE to one of: " + strings.Join(validScopes, ", ") + ".",
		}
	}

	required := append([]string{}, snowRequired...)
	if runMode == ModeAPI {
		required = append(required, apiRequired...)
		required = append(required, scopeRequired[scope]...)
	}
	if missing := missingKeys(values, required); len(missing) > 0 {
		context := "RUN_MODE " + runMode
		if runMode == ModeAPI {
			context += " / scope " + scope
		}
		return Config{}, &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "Missing required configuration variable(s) for " + context + ": " + strings.Join(missing, ", "),
			Op:       "load_config",
			NextStep: "Set the listed variable(s) in .env or the process environment.",
		}
	}

	timeoutSeconds, err := strconv.ParseFloat(get(values, "HTTP_TIMEOUT_SECONDS", "60"), 64)
	if err != nil || timeoutSeconds <= 0 {
		return Config{}, &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  fmt.Sprintf("HTTP_TIMEOUT_SECONDS must be a positive number, got %q.", values["HTTP_TIMEOUT_SECONDS"]),
			Op:       "load_config",
			NextStep: "Set HTTP_TIMEOUT_SECONDS to a positive numeric value.",
			Cause:    err,
		}
	}

	cfg := Config{
		SnykAPIToken:       get(values, "SNYK_API_TOKEN", ""),
		SnykOrgID:          get(values, "SNYK_ORG_ID", ""),
		SnykTargetID:       get(values, "SNYK_TARGET_ID", ""),
		SnykProjectID:      get(values, "SNYK_PROJECT_ID", ""),
		SnykBaseURL:        get(values, "SNYK_BASE_URL", DefaultSnykBaseURL),
		SnykRESTAPIVersion: get(values, "SNYK_REST_API_VERSION", ""),
		SnykSBOMFormat:     get(values, "SNYK_SBOM_FORMAT", DefaultSBOMFormat),

		SnowInstanceSubdomain:     get(values, "SNOW_INSTANCE_SUBDOMAIN", ""),
		SnowAccessToken:           get(values, "SNOW_ACCESS_TOKEN", ""),
		SnowBusinessApplicationID: get(values, "SNOW_BUSINESS_APPLICATION_ID", ""),
		SnowApplicationScope:      scope,

		RunMode: runMode,

		DebugLevel:  get(values, "DEBUG_LEVEL", DefaultDebugLevel),
		APIDryRun:   parseBool(values["API_DRY_RUN"], false),
		HTTPTimeout: time.Duration(timeoutSeconds * float64(time.Second)),
		SSLVerify:   parseBool(values["SSL_VERIFY"], true),
		CABundle:    get(values, "CA_BUNDLE", ""),
	}

	if err := rejectPlaceholders(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func rejectPlaceholders(cfg Config) error {
	checks := make(map[string]string)
	if cfg.RunMode == ModeAPI {
		checks["SNYK_API_TOKEN"] = cfg.SnykAPIToken
		checks["SNYK_ORG_ID"] = cfg.SnykOrgID
		for _, name := range scopeRequired[cfg.SnowApplicationScope] {
			switch name {
			case "SNYK_TARGET_ID":
				checks[name] = cfg.SnykTargetID
			case "SNYK_PROJECT_ID":
				checks[name] = cfg.SnykProjectID
			}
		}
	}

	uploadWillHappen := !(cfg.RunMode == ModeAPI && cfg.APIDryRun)
	if uploadWillHappen {
		checks["SNOW_INSTANCE_SUBDOMAIN"] = cfg.SnowInstanceSubdomain
		checks["SNOW_ACCESS_TOKEN"] = cfg.SnowAccessToken
		checks["SNOW_BUSINESS_APPLICATION_ID"] = cfg.SnowBusinessApplicationID
	}

	placeholders := make([]string, 0)
	for _, name := range append(append([]string{}, apiRequired...), append(scopeRequired[ScopeProject], snowRequired...)...) {
		if value, ok := checks[name]; ok && strings.HasPrefix(value, "MY_") {
			placeholders = append(placeholders, name)
		}
	}
	if len(placeholders) == 0 {
		return nil
	}
	return &apperr.Error{
		Kind:     apperr.KindConfig,
		Message:  "Configuration still contains placeholder value(s): " + strings.Join(placeholders, ", "),
		Op:       "load_config",
		NextStep: "Replace the placeholder(s) in .env with real values and save the file.",
	}
}

func readDotEnv(path string) (map[string]string, error) {
	result := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "Unable to read .env file.",
			Op:       "load_config",
			URL:      path,
			Detail:   err.Error(),
			NextStep: "Verify the .env file is readable.",
			Cause:    err,
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, rawValue, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, &apperr.Error{
				Kind:    apperr.KindConfig,
				Message: fmt.Sprintf("Invalid .env assignment at line %d.", lineNumber),
				Op:      "load_config",
				URL:     path,
			}
		}
		key = strings.TrimSpace(key)
		value, err := parseDotEnvValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, &apperr.Error{
				Kind:    apperr.KindConfig,
				Message: fmt.Sprintf("Invalid .env value for %s at line %d.", key, lineNumber),
				Op:      "load_config",
				URL:     path,
				Detail:  err.Error(),
				Cause:   err,
			}
		}
		result[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, &apperr.Error{
			Kind:    apperr.KindConfig,
			Message: "Unable to parse .env file.",
			Op:      "load_config",
			URL:     path,
			Detail:  err.Error(),
			Cause:   err,
		}
	}
	return result, nil
}

func parseDotEnvValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if raw[0] == '\'' {
		end := strings.LastIndex(raw[1:], "'")
		if end < 0 {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		return raw[1 : end+1], nil
	}
	if raw[0] == '"' {
		end := strings.LastIndex(raw[1:], "\"")
		if end < 0 {
			return "", fmt.Errorf("unterminated double-quoted value")
		}
		return strconv.Unquote(raw[:end+2])
	}
	if index := inlineCommentIndex(raw); index >= 0 {
		raw = raw[:index]
	}
	return strings.TrimSpace(raw), nil
}

func inlineCommentIndex(value string) int {
	for index, r := range value {
		if r == '#' && index > 0 {
			previous := value[index-1]
			if previous == ' ' || previous == '\t' {
				return index
			}
		}
	}
	return -1
}

func get(values map[string]string, key, fallback string) string {
	if value, ok := values[key]; ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func parseBool(value string, fallback bool) bool {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	_, ok := truthy[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

func missingKeys(values map[string]string, keys []string) []string {
	missing := make([]string, 0)
	for _, key := range keys {
		if strings.TrimSpace(values[key]) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
