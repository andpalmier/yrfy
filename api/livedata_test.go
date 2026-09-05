package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The files under testdata are real responses captured from the live YARAify
// API. Decoding them with DisallowUnknownFields means a field the API returns
// but the structs do not model fails the tests.
func TestLiveResponsesDecodeCompletely(t *testing.T) {
	tests := []struct {
		file string
		into func() any
	}{
		{"get_telfhash.json", func() any { return &YARAQueryResponse{} }},
		{"get_dhash_icon.json", func() any { return &YARAQueryResponse{} }},
		{"recent_yararules.json", func() any { return &YARARuleListResponse{} }},
		{"show_deployed.json", func() any { return &YARARuleListResponse{} }},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(tt.into()); err != nil {
				t.Errorf("live response does not fit the structs: %v", err)
			}
		})
	}
}

// A rescan reports query_status "queued", which is a success, not a failure.
func TestCheckStatusAcceptsQueued(t *testing.T) {
	if err := CheckStatus([]byte(`{"query_status":"queued","data":{}}`), "rescan_file"); err != nil {
		t.Errorf("queued should be a success, got %v", err)
	}
}

// YARAify reports some failures as the generic status "error" with the real
// code in data.
func TestCheckStatusUnwrapsGenericError(t *testing.T) {
	err := CheckStatus([]byte(`{"query_status":"error","data":"unknown_query"}`), "whatever")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "the API does not recognise that query type" {
		t.Errorf("got %q, want the explanation for unknown_query", err.Error())
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != "unknown_query" {
		t.Errorf("the specific code should stay available, got %+v", err)
	}
}

func TestCheckStatusSpecificStatus(t *testing.T) {
	err := CheckStatus([]byte(`{"query_status":"illegal_uuid"}`), "get_yara_rule")
	if err == nil || err.Error() != "that is not a valid UUID" {
		t.Errorf("got %v, want the illegal_uuid explanation", err)
	}
}

// The rescan response quotes file_size and sightings.
func TestRescanResponseQuotedNumbers(t *testing.T) {
	raw := []byte(`{"query_status":"queued","data":{
		"task_id":"a9138ab4-f214-11ef-b4a6-42010aa4000b",
		"file_size":"421888","sightings":"1"}}`)
	resp, err := ParseRescanResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data.FileSize.String() != "421888" {
		t.Errorf("FileSize = %q", resp.Data.FileSize.String())
	}
	if resp.Data.Sightings.String() != "1" {
		t.Errorf("Sightings = %q", resp.Data.Sightings.String())
	}
}

func TestValidateUUID(t *testing.T) {
	if err := ValidateUUID("1b95ce79-6034-4740-8e45-5f0840602d1a"); err != nil {
		t.Errorf("valid UUID rejected: %v", err)
	}
	for _, bad := range []string{"", "not-a-uuid", "1b95ce79603447408e455f0840602d1a"} {
		if err := ValidateUUID(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
