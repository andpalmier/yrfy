package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const methodsSHA256 = "a638404ab71199981be143591853b713b8826a82904a1cf72675de6bb026c8f9"
const methodsUUID = "1b95ce79-6034-4740-8e45-5f0840602d1a"

func yrfyTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewClient("test-key", WithBaseURL(server.URL+"/"))
}

func decodeJSON(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return payload
}

func TestQueryAndTaskMethodsForwardParameters(t *testing.T) {
	tlsHash := "T1" + strings.Repeat("A", 33)
	tests := []struct {
		name  string
		query string
		check func(*testing.T, map[string]any)
		call  func(context.Context, *Client) error
	}{
		{"task results", "get_results", func(t *testing.T, p map[string]any) {
			if p["task_id"] != methodsUUID || p["malpedia-token"] != "token" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.GetTaskResults(ctx, methodsUUID, "token")
			return err
		}},
		{"lookup hash", "lookup_hash", func(t *testing.T, p map[string]any) {
			if p["search_term"] != methodsSHA256 || p["malpedia-token"] != "token" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.LookupHash(ctx, methodsSHA256, "token")
			return err
		}},
		{"yara", "get_yara", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "Win_Test" || p["result_max"] != float64(10) {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryYARA(ctx, "Win_Test", 10)
			return err
		}},
		{"clamav", "get_clamav", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "Win.Trojan" || p["result_max"] != float64(10) {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryClamAV(ctx, "Win.Trojan", 10)
			return err
		}},
		{"imphash", "get_imphash", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "d41d8cd98f00b204e9800998ecf8427e" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryImphash(ctx, "d41d8cd98f00b204e9800998ecf8427e", 0)
			return err
		}},
		{"tlsh", "get_tlsh", func(t *testing.T, p map[string]any) {
			if p["search_term"] != tlsHash {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryTLSH(ctx, tlsHash, 0)
			return err
		}},
		{"telfhash", "get_telfhash", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "telfhash" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryTelfhash(ctx, "telfhash", 0)
			return err
		}},
		{"gimphash", "get_gimphash", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "gimphash" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryGimphash(ctx, "gimphash", 0)
			return err
		}},
		{"dhash", "get_dhash_icon", func(t *testing.T, p map[string]any) {
			if p["search_term"] != "dhash" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.QueryDhashIcon(ctx, "dhash", 0)
			return err
		}},
		{"identifier", "generate_identifier", func(t *testing.T, p map[string]any) {}, func(ctx context.Context, c *Client) error {
			_, err := c.GenerateIdentifier(ctx)
			return err
		}},
		{"list tasks", "list_tasks", func(t *testing.T, p map[string]any) {
			if p["identifier"] != "tracker" || p["task_status"] != "done" {
				t.Errorf("payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) error {
			_, err := c.ListTasks(ctx, "tracker", "done")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := yrfyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				payload := decodeJSON(t, r)
				if payload["query"] != tt.query {
					t.Errorf("query = %v, want %q", payload["query"], tt.query)
				}
				tt.check(t, payload)
				w.Header().Set("Content-Type", "application/json")
				switch tt.query {
				case "get_results":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"metadata":{"file_name":"sample.exe"}}}`)
				case "lookup_hash":
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","data":{"metadata":{"sha256_hash":%q},"tasks":[]}}`, methodsSHA256)
				case "generate_identifier":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","identifier":"tracker"}`)
				case "list_tasks":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[{"task_id":"task","task_status":"done"}]}`)
				default:
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","data":[{"sha256_hash":%q}]}`, methodsSHA256)
				}
			})
			if err := tt.call(context.Background(), c); err != nil {
				t.Fatalf("call failed: %v", err)
			}
		})
	}
}

func TestYARARuleMethods(t *testing.T) {
	tests := []struct {
		name  string
		query string
		call  func(context.Context, *Client) error
	}{
		{"recent rules", "recent_yararules", func(ctx context.Context, c *Client) error {
			_, err := c.RecentYARARules(ctx)
			return err
		}},
		{"deployed rules", "show_deployed_yara_rules", func(ctx context.Context, c *Client) error {
			_, err := c.ShowDeployedYARARules(ctx)
			return err
		}},
		{"get rule", "get_yara_rule", func(ctx context.Context, c *Client) error {
			rule, err := c.GetYARARule(ctx, methodsUUID)
			if err == nil && !strings.Contains(rule, "rule test") {
				return fmt.Errorf("rule body = %q", rule)
			}
			return err
		}},
		{"delete rule", "delete_yara_rule", func(ctx context.Context, c *Client) error {
			return c.DeleteYARARule(ctx, methodsUUID)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := yrfyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				payload := decodeJSON(t, r)
				if payload["query"] != tt.query {
					t.Errorf("query = %v, want %q", payload["query"], tt.query)
				}
				switch tt.query {
				case "recent_yararules", "show_deployed_yara_rules":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[{"yarahub_uuid":"`+methodsUUID+`","rule_name":"test"}]}`)
				case "get_yara_rule":
					_, _ = fmt.Fprint(w, "rule test { condition: true }")
				default:
					_, _ = fmt.Fprint(w, `{"query_status":"ok"}`)
				}
			})
			if err := tt.call(context.Background(), c); err != nil {
				t.Fatalf("call failed: %v", err)
			}
		})
	}
}

func TestRescanFileSuccess(t *testing.T) {
	c := yrfyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		payload := decodeJSON(t, r)
		if payload["query"] != "rescan_file" || payload["hash"] != methodsSHA256 {
			t.Errorf("payload = %#v", payload)
		}
		_, _ = fmt.Fprint(w, `{"query_status":"queued","data":{"task_id":"`+methodsUUID+`","file_size":"12","sightings":"2"}}`)
	})
	resp, err := c.RescanFile(context.Background(), methodsSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data.TaskID != methodsUUID || resp.Data.FileSize.String() != "12" || resp.Data.Sightings.String() != "2" {
		t.Errorf("rescan response = %+v", resp.Data)
	}
}

func TestGenerateIdentifierRejectsMissingValue(t *testing.T) {
	c := yrfyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"query_status":"ok"}`)
	})
	if _, err := c.GenerateIdentifier(context.Background()); err == nil {
		t.Fatal("expected an error when identifier is missing")
	}
}

func TestYRFYValidation(t *testing.T) {
	if err := ValidateTaskID("not-a-uuid"); err == nil {
		t.Error("invalid task ID accepted")
	}
	if err := ValidateTaskID(methodsUUID); err != nil {
		t.Errorf("valid task ID rejected: %v", err)
	}
	if err := ValidateTLSH("short"); err == nil {
		t.Error("short TLSH accepted")
	}
	if err := ValidateClamAVSignature(""); err == nil {
		t.Error("empty ClamAV signature accepted")
	}
	if err := ValidateIdentifier(strings.Repeat("x", 65)); err == nil {
		t.Error("long identifier accepted")
	}
}
