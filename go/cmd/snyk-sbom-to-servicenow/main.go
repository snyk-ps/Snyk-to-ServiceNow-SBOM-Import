package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/climode"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/scope"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/servicenow"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

var version = "2.1.0"

type commandOptions struct {
	sbomFilePath    string
	buildID         string
	buildIDProvided bool
	showVersion     bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, err := parseCommandOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return apperr.ExitSuccess
		}
		return apperr.ExitConfig
	}
	if options.showVersion {
		fmt.Fprintf(stdout, "snyk-sbom-to-servicenow %s\n", version)
		return apperr.ExitSuccess
	}

	bootstrap := applog.New("INFO", stderr)
	cfg, err := config.Load()
	if err != nil {
		logError(bootstrap, "Configuration error", err)
		return apperr.ExitCode(err)
	}
	cfg = cfg.WithBuildIDOverride(options.buildID, options.buildIDProvided)
	logger := applog.New(cfg.DebugLevel, stderr)

	httpClient, err := httpx.New(cfg.HTTPTimeout, cfg.SSLVerify, cfg.CABundle, logger)
	if err != nil {
		logError(logger, "Configuration error", err)
		return apperr.ExitCode(err)
	}
	snykClient := snyk.New(cfg, httpClient, logger)
	serviceNowClient := servicenow.New(cfg, httpClient, logger)

	if cfg.RunMode == config.ModeCLI {
		logger.Info("Starting SBOM upload (mode=SNYK_CLI)")
		if err := climode.Run(ctx, cfg, options.sbomFilePath, serviceNowClient, logger); err != nil {
			logError(logger, errorName(err), err)
			return apperr.ExitCode(err)
		}
		return apperr.ExitSuccess
	}

	logger.Info(
		"Starting SBOM export (mode=SNYK_API, scope=%s, org=%s, format=%s, api_dry_run=%t)",
		cfg.SnowApplicationScope,
		cfg.SnykOrgID,
		cfg.SnykSBOMFormat,
		cfg.APIDryRun,
	)
	runner := scope.New(cfg, snykClient, snykClient, serviceNowClient, logger)
	summary, err := runner.Run(ctx)
	if err != nil {
		logError(logger, errorName(err), err)
		return apperr.ExitCode(err)
	}
	return summary.ExitCode()
}

func parseCommandOptions(args []string, output io.Writer) (commandOptions, error) {
	flags := flag.NewFlagSet("snyk-sbom-to-servicenow", flag.ContinueOnError)
	flags.SetOutput(output)

	var options commandOptions
	flags.StringVar(
		&options.sbomFilePath,
		"sbom-file-path",
		"",
		"path to the SBOM file to upload (required when RUN_MODE=SNYK_CLI)",
	)
	flags.StringVar(
		&options.buildID,
		"buildid",
		"",
		"optional ServiceNow build ID (overrides BUILD_ID, including when empty)",
	)
	flags.BoolVar(&options.showVersion, "version", false, "print the version and exit")

	if err := flags.Parse(args); err != nil {
		return commandOptions{}, err
	}
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "buildid" {
			options.buildIDProvided = true
		}
	})
	return options, nil
}

func logError(logger *applog.Logger, prefix string, err error) {
	var appErr *apperr.Error
	if errors.As(err, &appErr) {
		logger.Error("%s:\n%s", prefix, appErr.Report())
		return
	}
	logger.Error("%s: %s", prefix, err)
}

func errorName(err error) string {
	var appErr *apperr.Error
	if !errors.As(err, &appErr) {
		return "Unexpected error"
	}
	switch appErr.Kind {
	case apperr.KindConfig:
		return "ConfigError"
	case apperr.KindAuth:
		return "AuthError"
	case apperr.KindSBOMGeneration:
		return "SbomGenerationError"
	case apperr.KindUnsupported:
		return "SbomUnsupportedError"
	case apperr.KindUpload:
		return "UploadError"
	default:
		return "Unexpected error"
	}
}
