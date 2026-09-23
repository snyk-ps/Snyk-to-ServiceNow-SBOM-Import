package climode_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/climode"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
)

func TestValidateFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(t.TempDir(), "valid.json")
	if err := os.WriteFile(valid, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "missing argument", wantErr: true},
		{name: "not found", path: filepath.Join(t.TempDir(), "missing.json"), wantErr: true},
		{name: "directory", path: t.TempDir(), wantErr: true},
		{name: "empty", path: empty, wantErr: true},
		{name: "valid", path: valid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := climode.ValidateFile(test.path)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateFile() error = %v, wantErr %t", err, test.wantErr)
			}
			if err != nil && apperr.ExitCode(err) != apperr.ExitConfig {
				t.Fatalf("ExitCode() = %d, want %d", apperr.ExitCode(err), apperr.ExitConfig)
			}
		})
	}
}

func TestRunUploadsEvenWhenAPIDryRunIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	uploader := &stubUploader{}
	err := climode.Run(
		context.Background(),
		config.Config{RunMode: config.ModeCLI, APIDryRun: true},
		path,
		uploader,
		applog.New("ERROR", io.Discard),
	)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if uploader.calls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploader.calls)
	}
}

type stubUploader struct {
	calls int
}

func (s *stubUploader) Upload(context.Context, string) (map[string]any, error) {
	s.calls++
	return map[string]any{}, nil
}
