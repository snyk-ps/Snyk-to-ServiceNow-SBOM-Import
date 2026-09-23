// Package redact masks secrets before they reach log output.
package redact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const Mask = "************"

var secretPatterns = []string{
	"token",
	"password",
	"passwd",
	"authorization",
	"auth",
	"secret",
	"api_key",
	"api-key",
	"apikey",
	"access_token",
	"bearer",
	"cookie",
	"credential",
}

// SensitiveKey reports whether a key is likely to identify a secret.
func SensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range secretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// Value masks a value when its key is sensitive. Authorization schemes remain
// visible so logs are useful without exposing credentials.
func Value(key, value string) string {
	if !SensitiveKey(key) {
		return value
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) == 2 {
		switch strings.ToLower(parts[0]) {
		case "bearer", "token", "basic":
			return parts[0] + " " + Mask
		}
	}
	return Mask
}

// Headers returns a redacted copy of the header map.
func Headers(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))
	for key, value := range headers {
		result[key] = Value(key, value)
	}
	return result
}

// HeaderSummary returns a deterministic, values-redacted representation.
func HeaderSummary(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	redacted := Headers(headers)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", key, redacted[key]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// Any recursively redacts values in JSON-like maps and slices.
func Any(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if SensitiveKey(key) {
				result[key] = Mask
			} else {
				result[key] = Any(item)
			}
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = Any(item)
		}
		return result
	default:
		return value
	}
}

// Body returns a safe representation of a response body. JSON values are
// recursively redacted; non-JSON bodies are omitted because arbitrary text can
// contain credentials that cannot be identified reliably.
func Body(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return fmt.Sprintf("<non-JSON response body omitted; %d bytes>", len(body))
	}
	redacted, err := json.Marshal(Any(value))
	if err != nil {
		return fmt.Sprintf("<response body omitted; %d bytes>", len(body))
	}
	return string(redacted)
}
