// Package scope orchestrates discovery and per-project API-mode processing.
package scope

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/sbomfile"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

type Discoverer interface {
	DiscoverProject() []snyk.Project
	DiscoverProjectsForTarget(context.Context) ([]snyk.Project, error)
	DiscoverProjectsForOrg(context.Context) ([]snyk.Project, error)
	DiscoverTargets(context.Context) ([]snyk.Target, error)
}

type Generator interface {
	Generate(context.Context, string) (snyk.Document, error)
}

type Uploader interface {
	Upload(context.Context, string) (map[string]any, error)
}

type Writer func(snyk.Document, string, string, *applog.Logger) (string, error)

type ProjectResult struct {
	Project   snyk.Project
	Generated bool
	Uploaded  bool
	OK        bool
	Skipped   bool
	Elapsed   time.Duration
	Err       error
}

type Summary struct {
	Scope              string
	DryRun             bool
	TargetsDiscovered  *int
	ProjectsDiscovered int
	SBOMsGenerated     int
	Succeeded          int
	Skipped            int
	Failed             int
	Elapsed            time.Duration
}

// ExitCode returns 4 only for genuine per-project failures; unsupported skips
// never fail the run.
func (s Summary) ExitCode() int {
	if s.Failed > 0 {
		return apperr.ExitUpload
	}
	return apperr.ExitSuccess
}

func (s Summary) String() string {
	lines := []string{
		"Processing summary:",
		"  Scope: " + s.Scope,
	}
	if s.TargetsDiscovered != nil {
		lines = append(lines, fmt.Sprintf("  Targets discovered: %d", *s.TargetsDiscovered))
	}
	successLabel := "Successful uploads"
	if s.DryRun {
		successLabel = "Skipped (dry-run)"
	}
	lines = append(lines,
		fmt.Sprintf("  Projects discovered: %d", s.ProjectsDiscovered),
		fmt.Sprintf("  SBOMs generated: %d", s.SBOMsGenerated),
		fmt.Sprintf("  %s: %d", successLabel, s.Succeeded),
		fmt.Sprintf("  Skipped (unsupported): %d", s.Skipped),
		fmt.Sprintf("  Failed: %d", s.Failed),
		"  Elapsed time: "+formatElapsed(s.Elapsed),
	)
	return strings.Join(lines, "\n")
}

type Runner struct {
	config     config.Config
	discovery  Discoverer
	generator  Generator
	uploader   Uploader
	writer     Writer
	outputRoot string
	logger     *applog.Logger
}

func New(
	cfg config.Config,
	discovery Discoverer,
	generator Generator,
	uploader Uploader,
	logger *applog.Logger,
) *Runner {
	return &Runner{
		config:    cfg,
		discovery: discovery,
		generator: generator,
		uploader:  uploader,
		writer:    sbomfile.Write,
		logger:    logger,
	}
}

// WithWriter replaces file persistence (primarily for deterministic tests).
func (r *Runner) WithWriter(writer Writer) *Runner {
	r.writer = writer
	return r
}

// WithOutputRoot selects the directory for generated SBOM files.
func (r *Runner) WithOutputRoot(root string) *Runner {
	r.outputRoot = root
	return r
}

func (r *Runner) Run(ctx context.Context) (Summary, error) {
	started := time.Now()
	projects, targetsDiscovered, err := r.discover(ctx)
	if err != nil {
		return Summary{}, err
	}
	total := len(projects)
	suffix := ""
	if targetsDiscovered != nil {
		suffix = fmt.Sprintf(" across %d target(s)", *targetsDiscovered)
	}
	r.logger.Info("Scope %s: discovered %d project(s)%s", r.config.SnowApplicationScope, total, suffix)

	results := make([]ProjectResult, 0, total)
	for index, project := range projects {
		r.logger.Info(
			"Processing Project %d of %d | project=%s (%s) | target=%s",
			index+1,
			total,
			project.Name,
			project.ProjectID,
			valueOr(project.TargetID, "-"),
		)
		result, fatal := r.processOne(ctx, project)
		if fatal != nil {
			return Summary{}, fatal
		}
		status := "OK"
		switch {
		case result.Skipped:
			status = "SKIPPED (unsupported)"
		case !result.OK:
			status = "FAILED (" + result.Err.Error() + ")"
		case r.config.APIDryRun:
			status = "OK (dry-run, upload skipped)"
		}
		r.logger.Info(
			"Result: %s | format=%s | elapsed=%.1fs",
			status,
			r.config.SnykSBOMFormat,
			result.Elapsed.Seconds(),
		)
		results = append(results, result)
	}

	summary := Summary{
		Scope:              r.config.SnowApplicationScope,
		DryRun:             r.config.APIDryRun,
		TargetsDiscovered:  targetsDiscovered,
		ProjectsDiscovered: total,
		Elapsed:            time.Since(started),
	}
	for _, result := range results {
		if result.Generated {
			summary.SBOMsGenerated++
		}
		if result.OK {
			summary.Succeeded++
		} else if result.Skipped {
			summary.Skipped++
		} else {
			summary.Failed++
		}
	}
	r.logger.Info("%s", summary.String())
	return summary, nil
}

func (r *Runner) discover(ctx context.Context) ([]snyk.Project, *int, error) {
	switch r.config.SnowApplicationScope {
	case config.ScopeProject:
		return r.discovery.DiscoverProject(), nil, nil
	case config.ScopeTarget:
		projects, err := r.discovery.DiscoverProjectsForTarget(ctx)
		count := 1
		return projects, &count, err
	case config.ScopeOrg:
		targets, err := r.discovery.DiscoverTargets(ctx)
		if err != nil {
			return nil, nil, err
		}
		projects, err := r.discovery.DiscoverProjectsForOrg(ctx)
		count := len(targets)
		return projects, &count, err
	default:
		return nil, nil, &apperr.Error{
			Kind:    apperr.KindConfig,
			Message: "Invalid SNOW_APPLICATION_SCOPE: " + r.config.SnowApplicationScope,
			Op:      "scope.discover",
		}
	}
}

func (r *Runner) processOne(ctx context.Context, project snyk.Project) (ProjectResult, error) {
	started := time.Now()
	document, err := r.generator.Generate(ctx, project.ProjectID)
	if err != nil {
		if apperr.IsUnsupported(err) {
			r.logger.Info("Project %s skipped: %s", project.ProjectID, err)
			return ProjectResult{
				Project: project,
				Skipped: true,
				Elapsed: time.Since(started),
				Err:     err,
			}, nil
		}
		if apperr.IsKind(err, apperr.KindAuth) || apperr.IsKind(err, apperr.KindConfig) {
			return ProjectResult{}, err
		}
		r.logger.Error("Project %s failed: %s", project.ProjectID, err)
		return ProjectResult{
			Project: project,
			Elapsed: time.Since(started),
			Err:     err,
		}, nil
	}

	path, err := r.writer(document, project.ProjectID, r.outputRoot, r.logger)
	if err != nil {
		r.logger.Error("Project %s failed: %s", project.ProjectID, err)
		return ProjectResult{
			Project: project,
			Elapsed: time.Since(started),
			Err:     err,
		}, nil
	}

	if r.config.APIDryRun {
		r.logger.Info("API_DRY_RUN enabled: skipping ServiceNow upload.")
		return ProjectResult{
			Project:   project,
			Generated: true,
			OK:        true,
			Elapsed:   time.Since(started),
		}, nil
	}

	if _, err := r.uploader.Upload(ctx, path); err != nil {
		if apperr.IsKind(err, apperr.KindAuth) || apperr.IsKind(err, apperr.KindConfig) {
			return ProjectResult{}, err
		}
		r.logger.Error("Project %s failed: %s", project.ProjectID, err)
		return ProjectResult{
			Project:   project,
			Generated: true,
			Elapsed:   time.Since(started),
			Err:       err,
		}, nil
	}

	return ProjectResult{
		Project:   project,
		Generated: true,
		Uploaded:  true,
		OK:        true,
		Elapsed:   time.Since(started),
	}, nil
}

func formatElapsed(duration time.Duration) string {
	totalSeconds := int(duration.Seconds())
	minutes, seconds := totalSeconds/60, totalSeconds%60
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
