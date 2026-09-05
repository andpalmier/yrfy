package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dlSHA = "a638404ab71199981be143591853b713b8826a82904a1cf72675de6bb026c8f9"

func zipBody() []byte { return append([]byte{'P', 'K', 3, 4}, []byte("archive-contents")...) }

func TestDownloadFileWritesToOutPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBody())
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	dest := filepath.Join(t.TempDir(), "sample.zip")

	got, err := c.DownloadFile(context.Background(), dlSHA, dest)
	if err != nil {
		t.Fatalf("DownloadFile() error = %v", err)
	}
	if got != dest {
		t.Errorf("path = %q, want %q", got, dest)
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != string(zipBody()) {
		t.Errorf("written bytes = %q (err %v)", b, err)
	}
}

// A body arriving in pieces must still be recognised as a ZIP. A plain Read
// can return fewer bytes than asked for, which would look like an error.
func TestDownloadShortRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Skip("ResponseWriter is not a Flusher")
		}
		full := zipBody()
		_, _ = w.Write(full[:2])
		f.Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(full[2:])
		f.Flush()
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	dest := filepath.Join(t.TempDir(), "chunked.zip")
	if _, err := c.DownloadFile(context.Background(), dlSHA, dest); err != nil {
		t.Fatalf("a chunked ZIP was rejected: %v", err)
	}
}

func TestDownloadReportsAPIStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"query_status":"error","data":"file_not_found"}`))
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	_, err := c.DownloadFile(context.Background(), dlSHA, filepath.Join(t.TempDir(), "x.zip"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "unknown to YARAify") {
		t.Errorf("error should explain the reason, got: %v", err)
	}
}

func TestDownloadUnpackedDefaultName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBody())
	}))
	defer server.Close()

	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	got, err := c.DownloadUnpacked(context.Background(), dlSHA, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != dlSHA+"_unpacked.zip" {
		t.Errorf("default name = %q, want the _unpacked suffix", got)
	}
}

func TestDownloadRejectsBadHash(t *testing.T) {
	c := NewClient("test-key")
	if _, err := c.DownloadFile(context.Background(), "../../etc/passwd", ""); err == nil {
		t.Error("expected an error for a non-SHA256 hash")
	}
}

func TestDownloadAllRulesUsesRulesURL(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write(zipBody())
	}))
	defer server.Close()

	c := NewClient("test-key", WithRulesURL(server.URL+"/yarahub/yaraify-rules.zip"))
	dest := filepath.Join(t.TempDir(), "rules.zip")
	if _, err := c.DownloadAllRules(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	if path != "/yarahub/yaraify-rules.zip" {
		t.Errorf("requested %q, want the yarahub archive path", path)
	}
}
