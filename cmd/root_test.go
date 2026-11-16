package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestExecuteLeavesSubcommandFlagValueAlone(t *testing.T) {
	t.Setenv("ABUSECH_API_KEY", "")
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"yrfy", "scan", "-file", "sample.exe", "-identifier", "-t"}

	err := Execute()
	if err == nil || !strings.Contains(err.Error(), "ABUSECH_API_KEY environment variable is required") {
		t.Fatalf("Execute() error = %v, want missing API key", err)
	}
}
