package scope_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/scope"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

func TestSummaryExitCodeAndSkipSemantics(t *testing.T) {
	projects := []snyk.Project{
		{OrgID: "org", TargetID: "target", ProjectID: "ok", Name: "ok"},
		{OrgID: "org", TargetID: "target", ProjectID: "skip", Name: "skip"},
		{OrgID: "org", TargetID: "target", ProjectID: "fail", Name: "fail"},
	}
	discovery := stubDiscovery{projects: projects}
	generator := stubGenerator{results: map[string]error{
		"skip": &apperr.Error{Kind: apperr.KindUnsupported, Message: "unsupported"},
		"fail": &apperr.Error{Kind: apperr.KindSBOMGeneration, Message: "generation failed"},
	}}
	runner := scope.New(
		apiConfig(),
		discovery,
		generator,
		stubUploader{},
		applog.New("ERROR", io.Discard),
	).WithWriter(stubWriter)

	summary, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.Succeeded != 1 || summary.Skipped != 1 || summary.Failed != 1 {
		t.Fatalf("summary = %+v, want succeeded=1 skipped=1 failed=1", summary)
	}
	if summary.ExitCode() != apperr.ExitUpload {
		t.Fatalf("ExitCode() = %d, want %d", summary.ExitCode(), apperr.ExitUpload)
	}
}

func TestSkipsDoNotFailRun(t *testing.T) {
	projects := []snyk.Project{
		{OrgID: "org", TargetID: "target", ProjectID: "ok", Name: "ok"},
		{OrgID: "org", TargetID: "target", ProjectID: "skip", Name: "skip"},
	}
	runner := scope.New(
		apiConfig(),
		stubDiscovery{projects: projects},
		stubGenerator{results: map[string]error{
			"skip": &apperr.Error{Kind: apperr.KindUnsupported, Message: "unsupported"},
		}},
		stubUploader{},
		applog.New("ERROR", io.Discard),
	).WithWriter(stubWriter)

	summary, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.Skipped != 1 || summary.Failed != 0 {
		t.Fatalf("summary = %+v, want skipped=1 failed=0", summary)
	}
	if summary.ExitCode() != apperr.ExitSuccess {
		t.Fatalf("ExitCode() = %d, want %d", summary.ExitCode(), apperr.ExitSuccess)
	}
}

func TestDryRunDoesNotUpload(t *testing.T) {
	cfg := apiConfig()
	cfg.APIDryRun = true
	uploader := &countingUploader{}
	runner := scope.New(
		cfg,
		stubDiscovery{projects: []snyk.Project{{
			OrgID: "org", TargetID: "target", ProjectID: "project", Name: "project",
		}}},
		stubGenerator{},
		uploader,
		applog.New("ERROR", io.Discard),
	).WithWriter(stubWriter)

	summary, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if uploader.calls != 0 {
		t.Fatalf("uploader calls = %d, want 0", uploader.calls)
	}
	if summary.Succeeded != 1 || summary.ExitCode() != 0 {
		t.Fatalf("summary = %+v, want one successful dry-run", summary)
	}
}

type stubDiscovery struct {
	projects []snyk.Project
}

func (s stubDiscovery) DiscoverProject() []snyk.Project {
	return s.projects
}
func (s stubDiscovery) DiscoverProjectsForTarget(context.Context) ([]snyk.Project, error) {
	return s.projects, nil
}
func (s stubDiscovery) DiscoverProjectsForOrg(context.Context) ([]snyk.Project, error) {
	return s.projects, nil
}
func (s stubDiscovery) DiscoverTargets(context.Context) ([]snyk.Target, error) {
	return []snyk.Target{{TargetID: "target", Name: "target"}}, nil
}

type stubGenerator struct {
	results map[string]error
}

func (s stubGenerator) Generate(_ context.Context, projectID string) (snyk.Document, error) {
	if err := s.results[projectID]; err != nil {
		return snyk.Document{}, err
	}
	return snyk.Document{Content: []byte(`{"bomFormat":"CycloneDX"}`), Format: "cyclonedx1.6+json"}, nil
}

type stubUploader struct{}

func (stubUploader) Upload(context.Context, string) (map[string]any, error) {
	return map[string]any{}, nil
}

type countingUploader struct {
	calls int
}

func (s *countingUploader) Upload(context.Context, string) (map[string]any, error) {
	s.calls++
	return map[string]any{}, nil
}

func stubWriter(snyk.Document, string, string, *applog.Logger) (string, error) {
	return "/tmp/sbom.json", nil
}

func apiConfig() config.Config {
	return config.Config{
		SnykAPIToken:              "token",
		SnykOrgID:                 "org",
		SnykTargetID:              "target",
		SnykProjectID:             "project",
		SnykBaseURL:               config.DefaultSnykBaseURL,
		SnykSBOMFormat:            config.DefaultSBOMFormat,
		SnowInstanceSubdomain:     "instance",
		SnowAccessToken:           "snow-token",
		SnowBusinessApplicationID: "app",
		SnowApplicationScope:      config.ScopeTarget,
		RunMode:                   config.ModeAPI,
		DebugLevel:                "ERROR",
		HTTPTimeout:               time.Second,
		SSLVerify:                 true,
	}
}
