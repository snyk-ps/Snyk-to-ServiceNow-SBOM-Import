// Package climode validates and uploads an SBOM produced by the Snyk CLI.
package climode

import (
	"context"
	"os"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
)

type Uploader interface {
	Upload(context.Context, string) (map[string]any, error)
}

// ValidateFile checks the SBOM path before any network call.
func ValidateFile(path string) error {
	if path == "" {
		return &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "SNYK_CLI mode requires --sbom-file-path.",
			Op:       "cli_mode",
			NextStep: "Provide the path to the Snyk CLI SBOM file: --sbom-file-path <file>.",
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &apperr.Error{
				Kind:     apperr.KindConfig,
				Message:  "SBOM file not found: " + path,
				Op:       "cli_mode",
				NextStep: "Provide an existing SBOM file path via --sbom-file-path.",
				Cause:    err,
			}
		}
		return &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "Unable to inspect SBOM file: " + path,
			Op:       "cli_mode",
			Detail:   err.Error(),
			NextStep: "Verify file permissions for the SBOM file.",
			Cause:    err,
		}
	}
	if !info.Mode().IsRegular() {
		return &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "SBOM path is not a file: " + path,
			Op:       "cli_mode",
			NextStep: "Provide a path to a regular SBOM file, not a directory.",
		}
	}
	if info.Size() == 0 {
		return &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "SBOM file is empty: " + path,
			Op:       "cli_mode",
			NextStep: "Provide a non-empty SBOM file produced by the Snyk CLI.",
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return &apperr.Error{
			Kind:     apperr.KindConfig,
			Message:  "SBOM file is not readable: " + path,
			Op:       "cli_mode",
			Detail:   err.Error(),
			NextStep: "Verify file permissions for the SBOM file.",
			Cause:    err,
		}
	}
	return file.Close()
}

// Run validates and uploads the supplied file.
func Run(
	ctx context.Context,
	cfg config.Config,
	path string,
	uploader Uploader,
	logger *applog.Logger,
) error {
	if err := ValidateFile(path); err != nil {
		return err
	}
	if cfg.APIDryRun {
		logger.Warn("API_DRY_RUN is ignored in SNYK_CLI mode; proceeding with upload.")
	}
	logger.Info("Uploading Snyk CLI SBOM file: %s", path)
	if _, err := uploader.Upload(ctx, path); err != nil {
		return err
	}
	logger.Info("Complete: SBOM %s uploaded to ServiceNow.", path)
	return nil
}
