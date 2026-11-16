package api

import (
	"context"
	"fmt"
)

// ScanFile scans a file with YARAify
func (c *Client) ScanFile(ctx context.Context, filePath string, options *ScanOptions) (*ScanResponse, error) {
	if err := ValidateFilePath(filePath); err != nil {
		return nil, err
	}

	response, err := c.uploadFile(ctx, filePath, options)
	if err != nil {
		return nil, fmt.Errorf("error uploading file: %w", err)
	}

	resp, err := parseResponse(response, "scan", ParseScanResponse, func(r *ScanResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetTaskResults retrieves results for a task ID
func (c *Client) GetTaskResults(ctx context.Context, taskID string, malpediaToken string) (*TaskResultResponse, error) {
	if err := ValidateTaskID(taskID); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":   "get_results",
		"task_id": taskID,
	}

	if malpediaToken != "" {
		payload["malpedia-token"] = malpediaToken
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving task results: %w", err)
	}

	resp, err := parseResponse(response, "get_results", ParseTaskResultResponse, func(r *TaskResultResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// LookupHash queries YARAify for a file hash
func (c *Client) LookupHash(ctx context.Context, hash string, malpediaToken string) (*HashLookupResponse, error) {
	if err := ValidateHash(hash); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":       "lookup_hash",
		"search_term": hash,
	}

	if malpediaToken != "" {
		payload["malpedia-token"] = malpediaToken
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error looking up hash: %w", err)
	}

	resp, err := parseResponse(response, "lookup_hash", ParseHashLookupResponse, func(r *HashLookupResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// QueryYARA retrieves files matching a YARA rule
func (c *Client) QueryYARA(ctx context.Context, ruleName string, resultMax int) (*YARAQueryResponse, error) {
	if err := ValidateYARARuleName(ruleName); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":       "get_yara",
		"search_term": ruleName,
	}

	if resultMax != 0 {
		if err := ValidateResultMax(resultMax); err != nil {
			return nil, err
		}
		payload["result_max"] = resultMax
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error querying YARA rule: %w", err)
	}

	resp, err := parseResponse(response, "get_yara", ParseYARAQueryResponse, func(r *YARAQueryResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// QueryClamAV retrieves files matching a ClamAV signature
func (c *Client) QueryClamAV(ctx context.Context, signature string, resultMax int) (*YARAQueryResponse, error) {
	if err := ValidateClamAVSignature(signature); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":       "get_clamav",
		"search_term": signature,
	}

	if resultMax != 0 {
		if err := ValidateResultMax(resultMax); err != nil {
			return nil, err
		}
		payload["result_max"] = resultMax
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error querying ClamAV signature: %w", err)
	}

	resp, err := parseResponse(response, "get_clamav", ParseYARAQueryResponse, func(r *YARAQueryResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// QueryImphash retrieves files with a specific imphash
func (c *Client) QueryImphash(ctx context.Context, imphash string, resultMax int) (*YARAQueryResponse, error) {
	if err := ValidateImphash(imphash); err != nil {
		return nil, err
	}
	return c.queryByHashKind(ctx, "get_imphash", imphash, "imphash", resultMax)
}

// QueryTLSH retrieves files with a specific TLSH
func (c *Client) QueryTLSH(ctx context.Context, tlsh string, resultMax int) (*YARAQueryResponse, error) {
	if err := ValidateTLSH(tlsh); err != nil {
		return nil, err
	}
	return c.queryByHashKind(ctx, "get_tlsh", tlsh, "TLSH", resultMax)
}

// GenerateIdentifier generates a new identifier for tracking submissions
func (c *Client) GenerateIdentifier(ctx context.Context) (string, error) {
	payload := map[string]interface{}{
		"query": "generate_identifier",
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("error generating identifier: %w", err)
	}

	resp, err := parseResponse(response, "generate_identifier", ParseIdentifierResponse, func(r *IdentifierResponse) string { return r.QueryStatus })
	if err != nil {
		return "", err
	}
	if resp.Identifier == "" {
		return "", fmt.Errorf("identifier missing from response")
	}

	return resp.Identifier, nil
}

// ListTasks lists tasks for an identifier
func (c *Client) ListTasks(ctx context.Context, identifier string, taskStatus string) (*TaskListResponse, error) {
	if err := ValidateIdentifier(identifier); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":      "list_tasks",
		"identifier": identifier,
	}

	if taskStatus != "" {
		payload["task_status"] = taskStatus
	}

	response, err := c.makeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error listing tasks: %w", err)
	}

	resp, err := parseResponse(response, "list_tasks", ParseTaskListResponse, func(r *TaskListResponse) string { return r.QueryStatus })
	if err != nil {
		return nil, err
	}

	return resp, nil
}
