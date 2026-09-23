package sbomfile_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/sbomfile"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

func TestWriteUsesTimestampedNameAndPreservesBytes(t *testing.T) {
	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	path, err := sbomfile.Write(
		snyk.Document{Content: payload, Format: "cyclonedx1.6+json"},
		"project-id",
		t.TempDir(),
		applog.New("ERROR", io.Discard),
	)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	name := filepath.Base(path)
	if !strings.HasSuffix(name, "-snyk-project-id-sbom.json") {
		t.Fatalf("filename = %q, want timestamp-snyk-project-id-sbom.json", name)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("file bytes = %q, want %q", got, payload)
	}
}

func TestWriteSanitizesProjectIDForFilename(t *testing.T) {
	root := t.TempDir()
	path, err := sbomfile.Write(
		snyk.Document{Content: []byte(`{}`)},
		"../../outside",
		root,
		applog.New("ERROR", io.Discard),
	)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(relative, "..") || strings.Contains(relative, string(filepath.Separator)) {
		t.Fatalf("path escaped output root: %s", path)
	}
}
