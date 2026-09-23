package snyk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
)

const (
	pageLimit = 100
	maxPages  = 1000
)

type Project struct {
	OrgID     string
	TargetID  string
	ProjectID string
	Name      string
}

type Target struct {
	TargetID string
	Name     string
}

type listResponse struct {
	Data  []json.RawMessage          `json:"data"`
	Links map[string]json.RawMessage `json:"links"`
}

type projectItem struct {
	ID         string `json:"id"`
	Attributes struct {
		Name string `json:"name"`
	} `json:"attributes"`
	Relationships struct {
		Target struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"target"`
	} `json:"relationships"`
}

type targetItem struct {
	ID         string `json:"id"`
	Attributes struct {
		DisplayName      string `json:"display_name"`
		DisplayNameCamel string `json:"displayName"`
		URL              string `json:"url"`
	} `json:"attributes"`
}

// DiscoverProject returns the configured project without an API request.
func (c *Client) DiscoverProject() []Project {
	return []Project{{
		OrgID:     c.config.SnykOrgID,
		TargetID:  c.config.SnykTargetID,
		ProjectID: c.config.SnykProjectID,
		Name:      c.config.SnykProjectID,
	}}
}

// DiscoverProjectsForTarget lists all projects associated with the target.
func (c *Client) DiscoverProjectsForTarget(ctx context.Context) ([]Project, error) {
	c.logger.Debug("SNYK_TARGET_ID: %q", c.config.SnykTargetID)
	query := c.projectListQuery()
	query.Set("target_id", c.config.SnykTargetID)
	items, err := c.paginate(
		ctx,
		"/orgs/"+url.PathEscape(c.config.SnykOrgID)+"/projects",
		query,
		"snyk.discover_projects_for_target",
	)
	if err != nil {
		return nil, err
	}
	return c.parseProjects(items)
}

// DiscoverProjectsForOrg lists every project in the organization.
func (c *Client) DiscoverProjectsForOrg(ctx context.Context) ([]Project, error) {
	items, err := c.paginate(
		ctx,
		"/orgs/"+url.PathEscape(c.config.SnykOrgID)+"/projects",
		c.projectListQuery(),
		"snyk.discover_projects_for_org",
	)
	if err != nil {
		return nil, err
	}
	return c.parseProjects(items)
}

// DiscoverTargets lists every target in the organization.
func (c *Client) DiscoverTargets(ctx context.Context) ([]Target, error) {
	query := url.Values{"limit": []string{fmt.Sprint(pageLimit)}}
	if c.config.SnykRESTAPIVersion != "" {
		query.Set("version", c.config.SnykRESTAPIVersion)
	}
	items, err := c.paginate(
		ctx,
		"/orgs/"+url.PathEscape(c.config.SnykOrgID)+"/targets",
		query,
		"snyk.discover_targets",
	)
	if err != nil {
		return nil, err
	}

	targets := make([]Target, 0, len(items))
	for _, raw := range items {
		var item targetItem
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, discoveryParseError("target", err)
		}
		name := item.Attributes.DisplayName
		if name == "" {
			name = item.Attributes.DisplayNameCamel
		}
		if name == "" {
			name = item.Attributes.URL
		}
		if name == "" {
			name = item.ID
		}
		targets = append(targets, Target{TargetID: item.ID, Name: name})
	}
	return targets, nil
}

func (c *Client) projectListQuery() url.Values {
	query := url.Values{"limit": []string{fmt.Sprint(pageLimit)}}
	if c.config.SnykRESTAPIVersion != "" {
		query.Set("version", c.config.SnykRESTAPIVersion)
	}
	return query
}

func (c *Client) parseProjects(items []json.RawMessage) ([]Project, error) {
	projects := make([]Project, 0, len(items))
	for _, raw := range items {
		var item projectItem
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, discoveryParseError("project", err)
		}
		name := item.Attributes.Name
		if name == "" {
			name = item.ID
		}
		targetID := item.Relationships.Target.Data.ID
		if targetID == "" {
			targetID = c.config.SnykTargetID
		}
		projects = append(projects, Project{
			OrgID:     c.config.SnykOrgID,
			TargetID:  targetID,
			ProjectID: item.ID,
			Name:      name,
		})
	}
	return projects, nil
}

func (c *Client) paginate(
	ctx context.Context,
	path string,
	initialQuery url.Values,
	operation string,
) ([]json.RawMessage, error) {
	base := strings.TrimRight(c.config.SnykBaseURL, "/")
	currentURL := base + path
	query := initialQuery
	items := make([]json.RawMessage, 0)

	for page := 1; currentURL != ""; page++ {
		if page > maxPages {
			return nil, &apperr.Error{
				Kind:     apperr.KindSBOMGeneration,
				Message:  "Snyk pagination exceeded the safety limit.",
				Op:       operation,
				URL:      currentURL,
				NextStep: "Verify the API's links.next cursor is advancing.",
			}
		}

		response, err := c.http.Do(ctx, httpx.Request{
			Method:    http.MethodGet,
			URL:       currentURL,
			Operation: operation,
			Headers: map[string]string{
				"Authorization": "token " + c.config.SnykAPIToken,
				"Accept":        "application/vnd.api+json",
			},
			Query: query,
		})
		if err != nil {
			return nil, mapDiscoveryError(err, operation)
		}

		var payload listResponse
		if err := response.JSON(&payload); err != nil {
			return nil, &apperr.Error{
				Kind:     apperr.KindSBOMGeneration,
				Message:  "Failed to parse Snyk discovery response.",
				Op:       operation,
				URL:      response.URL,
				Status:   response.Status,
				Detail:   err.Error(),
				NextStep: "Verify the Snyk REST API version and response shape.",
				Cause:    err,
			}
		}
		items = append(items, payload.Data...)

		next, err := resolveNextURL(c.config.SnykBaseURL, payload.Links["next"])
		if err != nil {
			return nil, &apperr.Error{
				Kind:    apperr.KindSBOMGeneration,
				Message: "Invalid Snyk pagination cursor.",
				Op:      operation,
				Detail:  err.Error(),
				Cause:   err,
			}
		}
		currentURL = next
		query = nil // next already carries its own query string
	}

	c.logger.Debug("Discovery %s returned %d item(s)", operation, len(items))
	return items, nil
}

func resolveNextURL(baseURL string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var next string
	if err := json.Unmarshal(raw, &next); err != nil {
		return "", err
	}
	if next == "" {
		return "", nil
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		return "", err
	}
	if nextURL.IsAbs() {
		return nextURL.String(), nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	base.Path = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.ResolveReference(nextURL).String(), nil
}

func mapDiscoveryError(err error, operation string) error {
	var appErr *apperr.Error
	if errors.As(err, &appErr) && (appErr.Status == http.StatusUnauthorized || appErr.Status == http.StatusForbidden) {
		return &apperr.Error{
			Kind:     apperr.KindAuth,
			Message:  "Snyk authentication failed during discovery.",
			Op:       operation,
			URL:      appErr.URL,
			Status:   appErr.Status,
			Detail:   appErr.Detail,
			NextStep: "Verify SNYK_API_TOKEN and that it can access SNYK_ORG_ID.",
			Cause:    err,
		}
	}
	status, detail, targetURL := 0, err.Error(), ""
	if errors.As(err, &appErr) {
		status, detail, targetURL = appErr.Status, appErr.Detail, appErr.URL
	}
	return &apperr.Error{
		Kind:     apperr.KindSBOMGeneration,
		Message:  "Failed to enumerate Snyk resources.",
		Op:       operation,
		URL:      targetURL,
		Status:   status,
		Detail:   detail,
		NextStep: "Verify SNYK_ORG_ID / SNYK_TARGET_ID and the Snyk REST API version.",
		Cause:    err,
	}
}

func discoveryParseError(resource string, err error) error {
	return &apperr.Error{
		Kind:     apperr.KindSBOMGeneration,
		Message:  "Failed to parse discovered Snyk " + resource + ".",
		Op:       "snyk.discovery",
		Detail:   err.Error(),
		NextStep: "Verify the Snyk REST API response shape.",
		Cause:    err,
	}
}
