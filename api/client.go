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
	"sync"
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
	mu         sync.Mutex // Protects lastReq for thread-safe rate limiting
	rulesURL   string
}

// Option configures the Client
type Option func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithRulesURL overrides where the full YARA rule archive is fetched from.
// Only tests should need this.
func WithRulesURL(url string) Option {
	return func(c *Client) {
		c.rulesURL = url
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
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := time.Since(c.lastReq)
	if elapsed < c.interval {
		time.Sleep(c.interval - elapsed)
	}
	c.lastReq = time.Now()
}

// MakeRequest makes an HTTP POST request and returns the response as a string.
// It is kept for callers that use the exported string API; internal code uses
// makeRequest to avoid converting the body to a string and back.
func (c *Client) MakeRequest(ctx context.Context, payload interface{}) (string, error) {
	body, err := c.makeRequest(ctx, payload)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) makeRequest(ctx context.Context, payload interface{}) ([]byte, error) {
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return body, nil
}

// UploadFile uploads a file for scanning and returns the response as a string.
// It is kept for callers that use the exported string API; internal code uses
// uploadFile to avoid converting the body to a string and back.
func (c *Client) UploadFile(ctx context.Context, filePath string, options *ScanOptions) (string, error) {
	body, err := c.uploadFile(ctx, filePath, options)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) uploadFile(ctx context.Context, filePath string, options *ScanOptions) ([]byte, error) {
	c.wait()

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, pr)
	if err != nil {
		_ = file.Close()
		_ = pw.CloseWithError(err)
		_ = pr.Close()
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "yrfy-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	go func() {
		defer func() { _ = file.Close() }()
		defer func() { _ = pw.Close() }()

		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			_ = pw.CloseWithError(fmt.Errorf("creating form file: %w", err))
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("copying file data: %w", err))
			return
		}

		if options != nil {
			jsonData, err := json.Marshal(options)
			if err != nil {
				_ = pw.CloseWithError(fmt.Errorf("marshaling options: %w", err))
				return
			}
			jsonPart, err := writer.CreateFormField("json_data")
			if err != nil {
				_ = pw.CloseWithError(fmt.Errorf("creating json field: %w", err))
				return
			}
			if _, err := jsonPart.Write(jsonData); err != nil {
				_ = pw.CloseWithError(fmt.Errorf("writing json data: %w", err))
				return
			}
		}

		if err := writer.Close(); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("closing multipart writer: %w", err))
		}
	}()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize+1)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(respBody) > maxResponseSize {
		return nil, fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return respBody, nil
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
		_ = resp.Body.Close()
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	return resp.Body, nil
}
