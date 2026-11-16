package cmd

import "testing"

func TestCommandValidationRejectsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]string) error
		args []string
	}{
		{"scan missing file", executeScan, nil},
		{"task missing id", executeTask, nil},
		{"query no selector", executeQuery, []string{"-limit", "10"}},
		{"query multiple selectors", executeQuery, []string{"-hash", "d41d8cd98f00b204e9800998ecf8427e", "-yara", "Rule"}},
		{"rescan missing hash", executeRescan, nil},
		{"rules no action", executeRules, nil},
		{"rules multiple actions", executeRules, []string{"-recent", "-all"}},
		{"download missing hash", executeDownload, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(tt.args); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}
