package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestQueryImphashRejectsLargeLimit(t *testing.T) {
	c := NewClient("test-key")
	if _, err := c.QueryImphash(context.Background(), "d41d8cd98f00b204e9800998ecf8427e", 1001); err == nil {
		t.Fatal("expected result_max validation error")
	}
}

func TestRescanFileRejectsBadHash(t *testing.T) {
	c := NewClient("test-key")
	if _, err := c.RescanFile(context.Background(), "not-a-hash"); err == nil {
		t.Fatal("expected hash validation error")
	}
}

func TestResultMaxRejectsNegativeBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[]}`)
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	ctx := context.Background()
	tlsHash := "T1" + strings.Repeat("A", 33)
	calls := []struct {
		name string
		call func() error
	}{
		{"yara", func() error { _, err := c.QueryYARA(ctx, "RuleName", -1); return err }},
		{"clamav", func() error { _, err := c.QueryClamAV(ctx, "Win.Trojan", -1); return err }},
		{"imphash", func() error { _, err := c.QueryImphash(ctx, "d41d8cd98f00b204e9800998ecf8427e", -1); return err }},
		{"tlsh", func() error { _, err := c.QueryTLSH(ctx, tlsHash, -1); return err }},
		{"telfhash", func() error { _, err := c.QueryTelfhash(ctx, "telfhash", -1); return err }},
		{"gimphash", func() error { _, err := c.QueryGimphash(ctx, "gimphash", -1); return err }},
		{"dhash", func() error { _, err := c.QueryDhashIcon(ctx, "dhash", -1); return err }},
	}
	for _, tc := range calls {
		if err := tc.call(); err == nil {
			t.Errorf("%s accepted result_max=-1", tc.name)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("API was contacted %d times for negative result_max values", got)
	}
}
