package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// ZipPassword is the password protecting every sample YARAify serves.
// The archives use AES128, which some unzip libraries cannot read; a tool
// reporting "compression type 99" lacks AES support.
const ZipPassword = "infected"

// zipMagic is the local file header of a ZIP archive (PK\x03\x04).
var zipMagic = []byte{'P', 'K', 3, 4}

// DownloadFile downloads a sample by its SHA256 hash and writes it to
// outPath. When outPath is empty the file is written to "<sha256>.zip" in the
// working directory. It returns the path written.
func (c *Client) DownloadFile(ctx context.Context, sha256, outPath string) (string, error) {
	return c.downloadSample(ctx, "get_file", sha256, outPath, "")
}

// DownloadUnpacked downloads the unpacked form of a sample, when YARAify was
// able to unpack it. outPath behaves as it does for DownloadFile, defaulting
// to "<sha256>_unpacked.zip".
func (c *Client) DownloadUnpacked(ctx context.Context, sha256, outPath string) (string, error) {
	return c.downloadSample(ctx, "get_unpacked", sha256, outPath, "_unpacked")
}

func (c *Client) downloadSample(ctx context.Context, query, sha256, outPath, suffix string) (string, error) {
	// Validate SHA256 format to prevent path traversal
	if err := ValidateSHA256(sha256); err != nil {
		return "", fmt.Errorf("invalid hash: %w", err)
	}

	if outPath == "" {
		outPath = fmt.Sprintf("%s%s.zip", sha256, suffix)
	}

	body, err := c.MakeRequestRaw(ctx, map[string]interface{}{
		"query":       query,
		"sha256_hash": sha256,
	})
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}
	defer func() { _ = body.Close() }()

	return writeZip(body, outPath, query)
}

// allRulesURL is where the full YARAhub archive actually lives. The curl
// example in the API documentation points at
// yaraify-api.abuse.ch/download/yaraify-rules.zip, which now redirects to the
// documentation page; the working location is the one the page itself links to.
const allRulesURL = "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"

// DownloadAllRules fetches the archive of every public rule on YARAhub.
// abuse.ch regenerates it every five minutes, so there is no point polling
// faster than that.
func (c *Client) DownloadAllRules(ctx context.Context, outPath string) (string, error) {
	if outPath == "" {
		outPath = "yaraify-rules.zip"
	}

	url := c.rulesURL
	if url == "" {
		url = allRulesURL
	}

	c.wait()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "yrfy-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	return writeZip(resp.Body, outPath, "download all rules")
}

// writeZip reads a response that should be a ZIP archive and saves it. A body
// that is not a ZIP is an error document, which is decoded for its reason.
func writeZip(body io.Reader, outPath, query string) (string, error) {
	// io.ReadFull is required here: a plain Read may return fewer bytes than
	// asked for even when more are available, which would make a valid
	// archive look like an error response.
	header := make([]byte, len(zipMagic))
	n, err := io.ReadFull(body, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", fmt.Errorf("error reading response header: %w", err)
	}

	if n < len(zipMagic) || string(header[:n]) != string(zipMagic) {
		return "", downloadError(header[:n], body, query)
	}

	if _, err := os.Stat(outPath); err == nil {
		return "", fmt.Errorf("file already exists: %s", outPath)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("error creating file: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := out.Write(header[:n]); err != nil {
		return "", fmt.Errorf("error writing file header: %w", err)
	}
	if _, err := io.Copy(out, body); err != nil {
		return "", fmt.Errorf("error saving file: %w", err)
	}

	return outPath, nil
}

// downloadError turns a non-ZIP response body into a useful error
func downloadError(read []byte, rest io.Reader, query string) error {
	const maxErrorSize = 1024 * 1024 // 1MB
	tail, err := io.ReadAll(io.LimitReader(rest, maxErrorSize))
	if err != nil {
		return fmt.Errorf("error reading error response: %w", err)
	}
	full := append(read, tail...)

	if serr := CheckStatus(full, query); serr != nil {
		return serr
	}

	var probe struct {
		QueryStatus string `json:"query_status"`
	}
	if err := json.Unmarshal(full, &probe); err == nil && probe.QueryStatus != "" {
		return fmt.Errorf("download failed: %s", probe.QueryStatus)
	}

	return fmt.Errorf("download failed: %s", strings.TrimSpace(string(full)))
}
