// Package httpx provides timeout, TLS, logging, timing, and normalized errors.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/apperr"
	applog "github.com/snyk-ps/snyk-sbom-to-servicenow/internal/logging"
	"github.com/snyk-ps/snyk-sbom-to-servicenow/internal/redact"
)

const maxResponseBodyBytes int64 = 256 << 20 // 256 MiB safety limit

// Request describes a request sent by one of the domain clients.
type Request struct {
	Method    string
	URL       string
	Operation string
	Headers   map[string]string
	Query     url.Values
	Body      []byte
}

// Response is the normalized HTTP response consumed by domain clients.
type Response struct {
	Status    int
	Headers   http.Header
	Body      []byte
	URL       string
	ElapsedMS float64
}

// JSON decodes a response body and returns a normalized malformed-response error.
func (r *Response) JSON(destination any) error {
	if err := json.Unmarshal(r.Body, destination); err != nil {
		return &apperr.Error{
			Kind:     apperr.KindUnexpected,
			Message:  "Malformed response body (expected JSON).",
			URL:      r.URL,
			Status:   r.Status,
			Detail:   err.Error(),
			NextStep: "Verify the endpoint returns JSON and the API version is correct.",
			Cause:    err,
		}
	}
	return nil
}

// Client wraps net/http with the application's logging and error contract.
type Client struct {
	http   *http.Client
	logger *applog.Logger
}

// New constructs a client using the OS trust store by default.
func New(timeout time.Duration, verify bool, caBundle string, logger *applog.Logger) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if !verify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // explicitly requested by SSL_VERIFY=false
	}

	if caBundle != "" {
		pem, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, &apperr.Error{
				Kind:     apperr.KindConfig,
				Message:  "Unable to read CA_BUNDLE.",
				Op:       "httpx.new",
				URL:      caBundle,
				Detail:   err.Error(),
				NextStep: "Set CA_BUNDLE to a readable PEM certificate bundle.",
				Cause:    err,
			}
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return nil, &apperr.Error{
				Kind:     apperr.KindConfig,
				Message:  "CA_BUNDLE contains no valid PEM certificates.",
				Op:       "httpx.new",
				URL:      caBundle,
				NextStep: "Provide a PEM bundle containing at least one certificate.",
			}
		}
		tlsConfig.RootCAs = pool
	}

	transport.TLSClientConfig = tlsConfig
	return &Client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		logger: logger,
	}, nil
}

// NewWithHTTPClient is intended for tests and custom transports.
func NewWithHTTPClient(client *http.Client, logger *applog.Logger) *Client {
	return &Client{http: client, logger: logger}
}

// Do performs a request, returning errors for transport failures and non-2xx responses.
func (c *Client) Do(ctx context.Context, input Request) (*Response, error) {
	method := strings.ToUpper(input.Method)
	if method == "" {
		method = http.MethodGet
	}

	endpoint, err := url.Parse(input.URL)
	if err != nil {
		return nil, &apperr.Error{
			Kind:    apperr.KindUnexpected,
			Message: "Invalid request URL.",
			Op:      input.Operation,
			URL:     input.URL,
			Detail:  err.Error(),
			Cause:   err,
		}
	}
	if input.Query != nil {
		endpoint.RawQuery = input.Query.Encode()
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(input.Body))
	if err != nil {
		return nil, &apperr.Error{
			Kind:    apperr.KindUnexpected,
			Message: "Unable to construct HTTP request.",
			Op:      input.Operation,
			URL:     endpoint.String(),
			Detail:  err.Error(),
			Cause:   err,
		}
	}
	for key, value := range input.Headers {
		request.Header.Set(key, value)
	}

	if c.logger != nil {
		c.logger.Debug("HTTP %s %s", method, input.URL)
		c.logger.Debug("Request Headers: %s", redact.HeaderSummary(input.Headers))
		if len(input.Query) > 0 {
			c.logger.Debug("Query Params: %s", input.Query.Encode())
		}
		c.logger.Trace("Request body bytes: %d", len(input.Body))
	}

	start := time.Now()
	httpResponse, err := c.http.Do(request)
	if err != nil {
		return nil, &apperr.Error{
			Kind:     apperr.KindUnexpected,
			Message:  "HTTP transport error.",
			Op:       input.Operation,
			URL:      endpoint.String(),
			Detail:   err.Error(),
			NextStep: "Verify network connectivity, TLS trust, and the target URL.",
			Cause:    err,
		}
	}
	defer httpResponse.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, &apperr.Error{
			Kind:    apperr.KindUnexpected,
			Message: "Unable to read HTTP response body.",
			Op:      input.Operation,
			URL:     endpoint.String(),
			Status:  httpResponse.StatusCode,
			Detail:  err.Error(),
			Cause:   err,
		}
	}
	if int64(len(body)) > maxResponseBodyBytes {
		return nil, &apperr.Error{
			Kind:     apperr.KindUnexpected,
			Message:  "HTTP response body exceeds the 256 MiB safety limit.",
			Op:       input.Operation,
			URL:      endpoint.String(),
			Status:   httpResponse.StatusCode,
			NextStep: "Reduce the response size or adjust the client safety limit.",
		}
	}

	elapsed := time.Since(start)
	result := &Response{
		Status:    httpResponse.StatusCode,
		Headers:   httpResponse.Header.Clone(),
		Body:      body,
		URL:       endpoint.String(),
		ElapsedMS: float64(elapsed.Microseconds()) / 1000,
	}

	if c.logger != nil {
		c.logger.Debug("HTTP %s -> %d (%.1f ms)", method, result.Status, result.ElapsedMS)
		c.logger.Debug("Response Headers: %s", redact.HeaderSummary(flattenHeaders(result.Headers)))
		traceBody := redact.Body(body)
		if len(traceBody) > 2000 {
			traceBody = traceBody[:2000]
		}
		c.logger.Trace("Response body:\n%s", traceBody)
	}

	if result.Status < 200 || result.Status >= 300 {
		return nil, &apperr.Error{
			Kind:     apperr.KindUnexpected,
			Message:  fmt.Sprintf("HTTP request failed with status %d.", result.Status),
			Op:       input.Operation,
			URL:      result.URL,
			Status:   result.Status,
			Detail:   parseErrorMessage(body),
			NextStep: "Inspect the status and detail above; verify credentials and request shape.",
		}
	}

	return result, nil
}

func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func parseErrorMessage(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"error", "message", "detail", "title", "errors"} {
			if value, ok := payload[key]; ok && value != nil {
				return fmt.Sprint(redact.Any(value))
			}
		}
	}
	if len(body) == 0 {
		return ""
	}
	return fmt.Sprintf("<non-JSON error response omitted; %d bytes>", len(body))
}
