// Package sbomfile persists generated SBOMs to timestamped JSON files.
package sbomfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

// Write writes the document bytes unmodified and returns the absolute path.
func Write(document snyk.Document, projectID, root string, logger *applog.Logger) (string, error) {
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return "", &apperr.Error{
				Kind:    apperr.KindSBOMGeneration,
				Message: "Unable to determine the SBOM output directory.",
				Op:      "sbomfile.write",
				Detail:  err.Error(),
				Cause:   err,
			}
		}
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", &apperr.Error{
			Kind:    apperr.KindSBOMGeneration,
			Message: "Unable to resolve the SBOM output directory.",
			Op:      "sbomfile.write",
			URL:     root,
			Detail:  err.Error(),
			Cause:   err,
		}
	}

	name := fmt.Sprintf(
		"%s-snyk-%s-sbom.json",
		time.Now().UTC().Format("20060102T150405Z"),
		sanitizeProjectID(projectID),
	)
	path := filepath.Join(absoluteRoot, name)
	if err := os.WriteFile(path, document.Content, 0o600); err != nil {
		return "", &apperr.Error{
			Kind:     apperr.KindSBOMGeneration,
			Message:  "Failed to write SBOM file to disk.",
			Op:       "sbomfile.write",
			URL:      path,
			Detail:   err.Error(),
			NextStep: "Verify write permissions and available disk space for the target directory.",
			Cause:    err,
		}
	}
	if logger != nil {
		logger.Info("SBOM written to %s (%d bytes)", path, len(document.Content))
	}
	return path, nil
}

func sanitizeProjectID(projectID string) string {
	var builder strings.Builder
	for _, value := range projectID {
		if unicode.IsLetter(value) || unicode.IsDigit(value) || value == '-' || value == '_' || value == '.' {
			builder.WriteRune(value)
		} else {
			builder.WriteByte('_')
		}
	}
	result := strings.TrimLeft(builder.String(), ".")
	if result == "" {
		return "unknown-project"
	}
	return result
}
