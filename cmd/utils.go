package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andpalmier/yrfy/api"
)

// verbose controls verbose output mode
var verbose bool

// printRootHelp displays the help message for the root command
func printRootHelp() {
	fmt.Println("yrfy - YARAify CLI Client")
	fmt.Println("  A command-line tool for interacting with the YARAify API")
	fmt.Println("  Built by @andpalmier")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  yrfy [command] [flags]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  scan               Scan a file with YARAify")
	fmt.Println("  task               Query task results by task ID")
	fmt.Println("  query              Query by hash, YARA rule, ClamAV signature, etc.")
	fmt.Println("  version            Show version information")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  -v, --verbose      Enable verbose output")
	fmt.Println("  -V, --version      Show version information")
	fmt.Println("  -h, --help         Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Scan a file")
	fmt.Println("  yrfy scan -file malware.exe")
	fmt.Println()
	fmt.Println("  # Scan with unpacking enabled")
	fmt.Println("  yrfy scan -file malware.exe -unpack")
	fmt.Println()
	fmt.Println("  # Get task results")
	fmt.Println("  yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b")
	fmt.Println()
	fmt.Println("  # Query by hash")
	fmt.Println("  yrfy query -hash b0bb095dd0ad8b8de1c83b13c38e68dd")
	fmt.Println()
	fmt.Println("  # Query by YARA rule")
	fmt.Println("  yrfy query -yara MALWARE_Win_Emotet -limit 50")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  ABUSECH_API_KEY    Your abuse.ch API key (required)")
	fmt.Println("                     Get one at https://auth.abuse.ch/")
	fmt.Println()
	fmt.Println("For more information about a command:")
	fmt.Println("  yrfy [command] --help")
}

// getAPIClient creates and returns an API client with the API key from environment
// Returns an error if the API key is not set
func getAPIClient() (*api.Client, error) {
	apiKey := os.Getenv("ABUSECH_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ABUSECH_API_KEY environment variable is required. Get one at https://auth.abuse.ch/")
	}

	if verbose {
		printVerbose("Creating API client")
	}

	return api.NewClient(apiKey), nil
}

func getContext() (context.Context, context.CancelFunc) {
	timeout := 120 * time.Second // Longer timeout for file scans

	if verbose {
		printVerbose(fmt.Sprintf("Setting request timeout to %v", timeout))
	}

	return context.WithTimeout(context.Background(), timeout)
}

func printUsageHeader(command, description string) {
	fmt.Printf("Usage:\n  yrfy %s [flags]\n", command)
	fmt.Println(description)
}

func printError(message string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", message)
}

func printDetailedError(err error, context string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	if context != "" {
		fmt.Fprintf(os.Stderr, "Context: %s\n", context)
	}

	errStr := err.Error()
	suggestions := map[string]string{
		"Unauthorized":       "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here",
		"API key":            "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here",
		"timeout":            "The request timed out. Try again or check your network connection",
		"deadline exceeded":  "The request timed out. Try again or check your network connection",
		"connection refused": "Cannot reach API. Check your internet connection",
	}

	for keyword, solution := range suggestions {
		if contains(errStr, keyword) {
			fmt.Fprintf(os.Stderr, "Solution: %s\n", solution)
			break
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Full error: %+v\n", err)
	}
}

func printVerbose(message string) {
	fmt.Printf("[VERBOSE] %s\n", message)
}

func printSuccess(message string) {
	fmt.Println(message)
}

func printJSON(data interface{}) {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Printf("%+v\n", data)
		return
	}
	fmt.Println(string(b))
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func SetVerbose(v bool) {
	verbose = v
	InitLogger(v)
}

func IsVerbose() bool {
	return verbose
}
