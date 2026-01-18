package api

import (
	"context"
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
	defer os.Remove(tmpfile.Name())
	tmpfile.WriteString("test content")
	tmpfile.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": {
				"task_id": "task-uuid"
			}
		}`)
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
