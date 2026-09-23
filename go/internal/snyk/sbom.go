// Package snyk implements Snyk SBOM generation and resource discovery.
package snyk

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
)

// Document is an SBOM returned by the Snyk API.
type Document struct {
	Content     []byte
	ContentType string
	Format      string
}

// Client is a Snyk REST API client.
type Client struct {
	config config.Config
	http   *httpx.Client
	logger *applog.Logger
}

func New(cfg config.Config, httpClient *httpx.Client, logger *applog.Logger) *Client {
	return &Client{config: cfg, http: httpClient, logger: logger}
}

// Generate creates an SBOM for a single project.
func (c *Client) Generate(ctx context.Context, projectID string) (Document, error) {
	endpoint := strings.TrimRight(c.config.SnykBaseURL, "/") +
		"/orgs/" + url.PathEscape(c.config.SnykOrgID) +
		"/projects/" + url.PathEscape(projectID) + "/sbom"

	query := url.Values{"format": []string{c.config.SnykSBOMFormat}}
	if c.config.SnykRESTAPIVersion != "" {
		query.Set("version", c.config.SnykRESTAPIVersion)
	}

	c.logger.Info("Generating SBOM")
	c.logger.Debug("SNYK_ORG_ID: %q", c.config.SnykOrgID)
	c.logger.Debug("SNYK_PROJECT_ID: %q", projectID)
	c.logger.Debug("SBOM_FORMAT: %q", c.config.SnykSBOMFormat)

	response, err := c.http.Do(ctx, httpx.Request{
		Method:    http.MethodGet,
		URL:       endpoint,
		Operation: "snyk.generate_sbom",
		Headers: map[string]string{
			"Authorization": "token " + c.config.SnykAPIToken,
			"Accept":        "application/vnd.api+json",
		},
		Query: query,
	})
	if err != nil {
		return Document{}, mapSBOMError(err, projectID)
	}
	if len(response.Body) == 0 {
		return Document{}, &apperr.Error{
			Kind:     apperr.KindSBOMGeneration,
			Message:  "Snyk returned an empty SBOM document.",
			Op:       "snyk.generate_sbom",
			URL:      response.URL,
			Status:   response.Status,
			NextStep: "Confirm the project has been scanned and supports SBOM generation.",
		}
	}

	contentType := response.Headers.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	document := Document{
		Content:     response.Body,
		ContentType: contentType,
		Format:      c.config.SnykSBOMFormat,
	}
	c.logger.Info("SBOM generated (%s, %d bytes)", document.Format, len(document.Content))
	c.logger.Debug("SBOM Content-Type: %q", contentType)
	c.logger.Debug("Payload Size: %d", len(document.Content))
	return document, nil
}

func mapSBOMError(err error, projectID string) error {
	var appErr *apperr.Error
	if !errors.As(err, &appErr) {
		return &apperr.Error{
			Kind:    apperr.KindSBOMGeneration,
			Message: "Failed to generate SBOM from Snyk.",
			Op:      "snyk.generate_sbom",
			Detail:  err.Error(),
			Cause:   err,
		}
	}

	switch appErr.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &apperr.Error{
			Kind:     apperr.KindAuth,
			Message:  "Snyk authentication failed.",
			Op:       appErr.Op,
			URL:      appErr.URL,
			Status:   appErr.Status,
			Detail:   appErr.Detail,
			NextStep: "Verify SNYK_API_TOKEN and that it can access SNYK_ORG_ID.",
			Cause:    err,
		}
	case http.StatusNotFound:
		return &apperr.Error{
			Kind:     apperr.KindUnsupported,
			Message:  "SBOM is not supported for this project (HTTP 404).",
			Op:       appErr.Op,
			URL:      appErr.URL,
			Status:   appErr.Status,
			Detail:   appErr.Detail,
			NextStep: "This project type does not support SBOM export; it will be skipped. If unexpected, verify SNYK_PROJECT_ID is correct.",
			Cause:    err,
		}
	default:
		return &apperr.Error{
			Kind:     apperr.KindSBOMGeneration,
			Message:  "Failed to generate SBOM from Snyk.",
			Op:       appErr.Op,
			URL:      appErr.URL,
			Status:   appErr.Status,
			Detail:   appErr.Detail,
			NextStep: "Verify SNYK_PROJECT_ID, SNYK_SBOM_FORMAT, and SNYK_REST_API_VERSION are valid for this org.",
			Cause:    err,
		}
	}
}
