package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestClient_ScanFile(t *testing.T) {
	// Create sample file
	tmpfile, err := os.CreateTemp("", "sample-*.exe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Logf("Warning: error removing temp file: %v", err)
		}
	}()
	if _, err := tmpfile.WriteString("test content"); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": {
				"task_id": "task-uuid"
			}
		}`); err != nil {
			return
		}
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	opts := ScanOptions{
		ClamAVScan: 1,
		ShareFile:  1,
	}

	resp, err := c.ScanFile(context.Background(), tmpfile.Name(), &opts)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	if resp.Data.TaskID != "task-uuid" {
		t.Errorf("Expected task ID task-uuid, got %s", resp.Data.TaskID)
	}
}

func TestScanOptionsIncludesExplicitZeroFlags(t *testing.T) {
	data, err := json.Marshal(ScanOptions{
		ClamAVScan:    0,
		ClamAVScanSet: true,
		ShareFile:     0,
		ShareFileSet:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"clamav_scan", "share_file"} {
		if value, ok := got[key]; !ok || value != float64(0) {
			t.Errorf("%s = %#v, want explicit 0 in %s", key, value, data)
		}
	}
}

func TestScanOptionsAcceptsIntegerLiterals(t *testing.T) {
	data, err := json.Marshal(ScanOptions{ClamAVScan: 1, ShareFile: 0})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["clamav_scan"] != float64(1) {
		t.Errorf("clamav_scan = %#v, want 1", got["clamav_scan"])
	}
	if _, ok := got["share_file"]; ok {
		t.Errorf("share_file = %#v, want omitted without ShareFileSet", got["share_file"])
	}
}

func TestClient_ScanFileReportsAPIError(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sample.exe"
	if err := os.WriteFile(path, []byte("test content"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"query_status":"no_file"}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	_, err := c.ScanFile(context.Background(), path, &ScanOptions{})
	if err == nil || err.Error() != "no file reached the API" {
		t.Fatalf("ScanFile() error = %v, want the no_file explanation", err)
	}
}
