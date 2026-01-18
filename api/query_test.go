package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_LookupHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": {
				"metadata": {
					"sha256_hash": "dummy_hash"
				}
			}
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	data, err := c.LookupHash(context.Background(), "d41d8cd98f00b204e9800998ecf8427e", "")
	if err != nil {
		t.Fatalf("LookupHash() error = %v", err)
	}
	if data.Data.Metadata.SHA256Hash != "dummy_hash" {
		t.Errorf("expected dummy_hash, got %s", data.Data.Metadata.SHA256Hash)
	}
}

func TestClient_GetYaraResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": [
				{
					"sha256_hash": "dummy_hash"
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	data, err := c.QueryYARA(context.Background(), "RuleName", 10)
	if err != nil {
		t.Fatalf("QueryYARA() error = %v", err)
	}
	if len(data.Data) != 1 {
		t.Errorf("Expected 1 result")
	}
}
