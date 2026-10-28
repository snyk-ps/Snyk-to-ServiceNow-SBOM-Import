// Package servicenow uploads SBOM files to ServiceNow Vulnerability Response.
package servicenow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/config"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/httpx"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/redact"
)

const uploadPath = "api/sbom/core/upload"

// Client uploads persisted SBOM files to a ServiceNow instance.
type Client struct {
	config  config.Config
	http    *httpx.Client
	logger  *applog.Logger
	baseURL string
}

func New(cfg config.Config, httpClient *httpx.Client, logger *applog.Logger) *Client {
	return NewWithBaseURL(cfg, httpClient, logger, cfg.SnowBaseURL())
}

// NewWithBaseURL allows tests and private gateways to override the instance origin.
func NewWithBaseURL(
	cfg config.Config,
	httpClient *httpx.Client,
	logger *applog.Logger,
	baseURL string,
) *Client {
	return &Client{
		config:  cfg,
		http:    httpClient,
		logger:  logger,
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// Upload sends the file bytes unmodified to the ServiceNow SBOM API.
func (c *Client) Upload(ctx context.Context, path string) (map[string]any, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, &apperr.Error{
			Kind:     apperr.KindUpload,
			Message:  "Failed to read the persisted SBOM file for upload.",
			Op:       "servicenow.upload_sbom",
			URL:      path,
			Detail:   err.Error(),
			NextStep: "Verify the SBOM file exists and is readable.",
			Cause:    err,
		}
	}

	endpoint := c.baseURL + "/" + uploadPath
	query := url.Values{
		"businessApplicationId": []string{c.config.SnowBusinessApplicationID},
		"sbomSource":            []string{c.config.SBOMSource()},
	}
	if buildID := strings.TrimSpace(c.config.BuildID); buildID != "" {
		query.Set("buildId", buildID)
	}
	if c.logger != nil {
		c.logger.Info("Uploading SBOM to ServiceNow")
		c.logger.Debug("Upload URL: %q", endpoint)
		c.logger.Debug("SNOW_BUSINESS_APPLICATION_ID: %q", c.config.SnowBusinessApplicationID)
		c.logger.Debug("SNOW_AUTH_METHOD: %q", c.authMethod())
		c.logger.Debug("Build ID: %q", c.config.BuildID)
		c.logger.Debug("SBOM File: %q", path)
		c.logger.Debug("Payload Size: %d", len(payload))
	}

	response, err := c.http.Do(ctx, httpx.Request{
		Method:    http.MethodPost,
		URL:       endpoint,
		Operation: "servicenow.upload_sbom",
		Headers: map[string]string{
			"Authorization": c.authorizationHeader(),
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
		Query: query,
		Body:  payload,
	})
	if err != nil {
		return nil, c.mapUploadError(err)
	}

	result := make(map[string]any)
	if len(response.Body) > 0 {
		if err := json.Unmarshal(response.Body, &result); err != nil {
			result["raw"] = string(response.Body)
		}
	}
	if c.logger != nil {
		c.logger.Info("SBOM uploaded to ServiceNow (status %d)", response.Status)
		c.logger.Trace("ServiceNow Response: %v", redact.Any(result))
	}
	return result, nil
}

func (c *Client) authMethod() string {
	if c.config.SnowAuthMethod == config.SnowAuthBasic {
		return config.SnowAuthBasic
	}
	return config.SnowAuthBearer
}

func (c *Client) authorizationHeader() string {
	if c.authMethod() == config.SnowAuthBasic {
		credentials := c.config.SnowUsername + ":" + c.config.SnowPassword
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	return "Bearer " + c.config.SnowAccessToken
}

func (c *Client) mapUploadError(err error) error {
	var appErr *apperr.Error
	if errors.As(err, &appErr) && (appErr.Status == http.StatusUnauthorized || appErr.Status == http.StatusForbidden) {
		nextStep := "Verify SNOW_ACCESS_TOKEN and that it has SBOM upload permission."
		if c.authMethod() == config.SnowAuthBasic {
			nextStep = "Verify SNOW_USERNAME, SNOW_PASSWORD, and that the account has SBOM upload permission."
		}
		return &apperr.Error{
			Kind:     apperr.KindAuth,
			Message:  "ServiceNow authentication failed.",
			Op:       appErr.Op,
			URL:      appErr.URL,
			Status:   appErr.Status,
			Detail:   appErr.Detail,
			NextStep: nextStep,
			Cause:    err,
		}
	}
	status, detail, targetURL := 0, err.Error(), ""
	if errors.As(err, &appErr) {
		status, detail, targetURL = appErr.Status, appErr.Detail, appErr.URL
	}
	return &apperr.Error{
		Kind:     apperr.KindUpload,
		Message:  "Failed to upload SBOM to ServiceNow.",
		Op:       "servicenow.upload_sbom",
		URL:      targetURL,
		Status:   status,
		Detail:   detail,
		NextStep: "Verify SNOW_INSTANCE_SUBDOMAIN and SNOW_BUSINESS_APPLICATION_ID.",
		Cause:    err,
	}
}
