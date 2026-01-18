package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// API constants
const (
	defaultAPIURL   = "https://yaraify-api.abuse.ch/api/v1/"
	defaultTimeout  = 60 * time.Second
	maxResponseSize = 10 * 1024 * 1024 // prevents OOM from large responses (10MB)
)

// Client interacts with the YARAify API
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	interval   time.Duration
	lastReq    time.Time
}

// Option configures the Client
type Option func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithBaseURL sets the API base URL
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// NewClient creates a new YARAify API client
// Note: API key is required
func NewClient(apiKey string, options ...Option) *Client {
	c := &Client{
		apiKey:   apiKey,
		baseURL:  defaultAPIURL,
		interval: 100 * time.Millisecond, // 10 requests per second
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

// wait handles simple rate limiting
func (c *Client) wait() {
	elapsed := time.Since(c.lastReq)
	if elapsed < c.interval {
		time.Sleep(c.interval - elapsed)
	}
	c.lastReq = time.Now()
}

// MakeRequest makes an HTTP POST request to the API with JSON body
func (c *Client) MakeRequest(ctx context.Context, payload interface{}) (string, error) {
	c.wait()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "yrfy-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if len(body) == maxResponseSize {
		return "", fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return string(body), nil
}

// UploadFile uploads a file for scanning
func (c *Client) UploadFile(ctx context.Context, filePath string, options *ScanOptions) (string, error) {
	c.wait()

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("creating form file: %w", err)
	}

	if _, err := io.Copy(part, file); err != nil {
		return "", fmt.Errorf("copying file data: %w", err)
	}

	if options != nil {
		jsonData, err := json.Marshal(options)
		if err != nil {
			return "", fmt.Errorf("marshaling options: %w", err)
		}
		jsonPart, err := writer.CreateFormField("json_data")
		if err != nil {
			return "", fmt.Errorf("creating json field: %w", err)
		}
		if _, err := jsonPart.Write(jsonData); err != nil {
			return "", fmt.Errorf("writing json data: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("closing multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, body)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "yrfy-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	return string(respBody), nil
}

// MakeRequestRaw makes an HTTP POST request and returns the raw response body
func (c *Client) MakeRequestRaw(ctx context.Context, payload interface{}) (io.ReadCloser, error) {
	c.wait()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "yrfy-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	return resp.Body, nil
}
