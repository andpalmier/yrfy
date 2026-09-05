package api

import (
	"context"
	"fmt"
)

// queryByHashKind is the shared body of the search_term style hash lookups.
// get_telfhash, get_gimphash and get_dhash_icon all take the same shape as
// get_imphash and get_tlsh.
func (c *Client) queryByHashKind(ctx context.Context, query, searchTerm, label string, resultMax int) (*YARAQueryResponse, error) {
	if searchTerm == "" {
		return nil, fmt.Errorf("%s cannot be empty", label)
	}

	payload := map[string]interface{}{
		"query":       query,
		"search_term": searchTerm,
	}

	if resultMax > 0 {
		if err := ValidateResultMax(resultMax); err != nil {
			return nil, err
		}
		payload["result_max"] = resultMax
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error querying %s: %w", label, err)
	}

	if err := CheckStatus([]byte(response), query); err != nil {
		return nil, err
	}

	resp, err := ParseYARAQueryResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return resp, nil
}

// QueryTelfhash retrieves files with a specific telfhash
func (c *Client) QueryTelfhash(ctx context.Context, telfhash string, resultMax int) (*YARAQueryResponse, error) {
	return c.queryByHashKind(ctx, "get_telfhash", telfhash, "telfhash", resultMax)
}

// QueryGimphash retrieves files with a specific gimphash
func (c *Client) QueryGimphash(ctx context.Context, gimphash string, resultMax int) (*YARAQueryResponse, error) {
	return c.queryByHashKind(ctx, "get_gimphash", gimphash, "gimphash", resultMax)
}

// QueryDhashIcon retrieves files whose icon has a specific dhash
func (c *Client) QueryDhashIcon(ctx context.Context, dhash string, resultMax int) (*YARAQueryResponse, error) {
	return c.queryByHashKind(ctx, "get_dhash_icon", dhash, "icon dhash", resultMax)
}

// RescanFile asks YARAify to scan a file it already holds against the current
// rule set. The hash may be MD5, SHA1, SHA256 or SHA3-384. A successful call
// reports query_status "queued" and returns the new task.
func (c *Client) RescanFile(ctx context.Context, hash string) (*RescanResponse, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash cannot be empty")
	}

	payload := map[string]interface{}{
		"query": "rescan_file",
		"hash":  hash,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error requesting rescan: %w", err)
	}

	if err := CheckStatus([]byte(response), "rescan_file"); err != nil {
		return nil, err
	}

	return ParseRescanResponse([]byte(response))
}
