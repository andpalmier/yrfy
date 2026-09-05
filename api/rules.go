package api

import (
	"context"
	"fmt"
	"regexp"
)

// uuidRegex matches a UUID in the form YARAhub uses
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateUUID checks that a string is a UUID
func ValidateUUID(id string) error {
	if id == "" {
		return fmt.Errorf("UUID cannot be empty")
	}
	if !uuidRegex.MatchString(id) {
		return fmt.Errorf("invalid UUID: expected the form 1b95ce79-6034-4740-8e45-5f0840602d1a")
	}
	return nil
}

// RecentYARARules lists the most recently deployed public rules on YARAhub.
// Only rules whose author set yarahub_rule_matching_tlp to TLP:WHITE appear.
func (c *Client) RecentYARARules(ctx context.Context) ([]YARARule, error) {
	return c.yaraRuleList(ctx, "recent_yararules")
}

// ShowDeployedYARARules lists the rules deployed under your own account.
func (c *Client) ShowDeployedYARARules(ctx context.Context) ([]YARARule, error) {
	return c.yaraRuleList(ctx, "show_deployed_yara_rules")
}

func (c *Client) yaraRuleList(ctx context.Context, query string) ([]YARARule, error) {
	response, err := c.MakeRequest(ctx, map[string]interface{}{"query": query})
	if err != nil {
		return nil, fmt.Errorf("error running %s: %w", query, err)
	}

	if err := CheckStatus([]byte(response), query); err != nil {
		return nil, err
	}

	resp, err := ParseYARARuleListResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return resp.Data, nil
}

// GetYARARule downloads the text of a single rule from YARAhub. Only rules
// whose author set yarahub_rule_sharing_tlp to TLP:WHITE can be fetched.
//
// The API answers with the rule source rather than JSON, so the body is
// returned as-is once it is clear it is not an error document.
func (c *Client) GetYARARule(ctx context.Context, uuid string) (string, error) {
	if err := ValidateUUID(uuid); err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"query": "get_yara_rule",
		"uuid":  uuid,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("error downloading YARA rule: %w", err)
	}

	if err := CheckStatus([]byte(response), "get_yara_rule"); err != nil {
		return "", err
	}

	return response, nil
}

// DeleteYARARule removes one of your own rules from YARAhub. This cannot be
// undone.
func (c *Client) DeleteYARARule(ctx context.Context, uuid string) error {
	if err := ValidateUUID(uuid); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"query":        "delete_yara_rule",
		"yarahub_uuid": uuid,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return fmt.Errorf("error deleting YARA rule: %w", err)
	}

	if err := CheckStatus([]byte(response), "delete_yara_rule"); err != nil {
		return err
	}

	// CheckStatus already turned any failure into an error.
	return nil
}
