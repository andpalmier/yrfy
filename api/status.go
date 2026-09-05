package api

import (
	"encoding/json"
	"fmt"
)

// StatusError is returned when the API answers with a query_status that is
// not a success. YARAify reports failures two ways: a specific status such as
// illegal_uuid, or the generic status "error" with a machine readable code in
// the data field.
type StatusError struct {
	Status string
	Code   string
	Query  string
}

func (e *StatusError) Error() string {
	key := e.Code
	if key == "" {
		key = e.Status
	}
	if msg, ok := statusMessages[key]; ok {
		return msg
	}
	if e.Query != "" {
		return fmt.Sprintf("the API rejected the %s query with status %q", e.Query, key)
	}
	return fmt.Sprintf("the API returned status %q", key)
}

// CheckStatus inspects a raw API response and returns a *StatusError when the
// query did not succeed. "queued" is a success: a rescan reports it while the
// file waits to be processed.
func CheckStatus(raw []byte, query string) error {
	var probe struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil // let the caller's own decoding report the problem
	}
	switch probe.QueryStatus {
	case "", "ok", "queued":
		return nil
	}

	// A generic "error" carries the specific code in data.
	var code string
	if probe.QueryStatus == "error" && len(probe.Data) > 0 {
		_ = json.Unmarshal(probe.Data, &code)
	}

	return &StatusError{Status: probe.QueryStatus, Code: code, Query: query}
}

// statusMessages explains the statuses and error codes YARAify returns. The
// published documentation only lists ok and queued, so the rest were observed
// against the live API.
var statusMessages = map[string]string{
	"no_results":          "the query returned no results",
	"illegal_uuid":        "that is not a valid UUID",
	"unknown_query":       "the API does not recognise that query type",
	"missing_search_term": "no search term was sent to the API",
	"illegal_search_term": "the API rejected that search term",
	"illegal_hash":        "the API rejected that hash as malformed",
	"missing_hash":        "no hash was sent to the API",
	"illegal_task_id":     "that is not a valid task id",
	"unknown_task_id":     "that task id is unknown to YARAify",
	"file_not_found":      "that file is unknown to YARAify, or the reporter chose not to share it",
	"no_file":             "no file reached the API",
	"no_api_key":          "no API key was accepted: set ABUSECH_API_KEY (get one at https://auth.abuse.ch/)",
	"user_blacklisted":    "this API key is blacklisted: contact https://www.spamhaus.com/#contact-form",
	"http_post_expected":  "the API expected an HTTP POST request",
}
