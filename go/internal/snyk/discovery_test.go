package snyk_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/snyk"
)

func TestDiscoverProjectsForTargetFollowsPagination(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if requests == 1 {
			if got := r.URL.Query().Get("target_id"); got != "target" {
				t.Fatalf("target_id = %q, want target", got)
			}
			fmt.Fprintf(w, `{
				"data":[{"id":"p1","attributes":{"name":"one"},"relationships":{"target":{"data":{"id":"target"}}}}],
				"links":{"next":"/rest/orgs/org/projects?starting_after=cursor"}
			}`)
			return
		}
		fmt.Fprintf(w, `{
			"data":[{"id":"p2","attributes":{"name":"two"},"relationships":{"target":{"data":{"id":"target"}}}}],
			"links":{"next":null}
		}`)
	}))
	defer server.Close()

	logger := applog.New("ERROR", io.Discard)
	cfg := config.Config{
		SnykAPIToken:       "token",
		SnykOrgID:          "org",
		SnykTargetID:       "target",
		SnykBaseURL:        server.URL + "/rest",
		SnykRESTAPIVersion: "2026-03-25",
		HTTPTimeout:        time.Second,
		SSLVerify:          true,
	}
	client := snyk.New(cfg, httpx.NewWithHTTPClient(server.Client(), logger), logger)
	projects, err := client.DiscoverProjectsForTarget(context.Background())
	if err != nil {
		t.Fatalf("DiscoverProjectsForTarget() error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(projects) != 2 || projects[0].ProjectID != "p1" || projects[1].ProjectID != "p2" {
		t.Fatalf("projects = %+v, want p1,p2", projects)
	}
}
