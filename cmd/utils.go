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
var (
	verbose bool
	// requestTimeout bounds a single API request. YARAify scans files, which
	// takes longer than a plain lookup, so the default is generous.
	requestTimeout = 120 * time.Second
)

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
	fmt.Println("  rescan             Rescan a file YARAify already holds")
	fmt.Println("  download           Download a file or its unpacked form")
	fmt.Println("  rules              List, download or delete YARA rules on YARAhub")
	fmt.Println("  query              Query by hash, YARA rule, ClamAV signature, etc.")
	fmt.Println("  version            Show version information")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  -v, --verbose      Enable verbose output")
	fmt.Println("  -t, --timeout      Per-request timeout (default 30s, e.g. 2m)")
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

	return api.NewClient(apiKey, api.WithTimeout(requestTimeout)), nil
}

func getContext() (context.Context, context.CancelFunc) {
	if verbose {
		printVerbose(fmt.Sprintf("Setting request timeout to %v", requestTimeout))
	}

	return context.WithTimeout(context.Background(), requestTimeout)
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
	for _, s := range errorSuggestions {
		if strings.Contains(errStr, s.keyword) {
			fmt.Fprintf(os.Stderr, "Solution: %s\n", s.solution)
			break
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Full error: %+v\n", err)
	}
}

// errorSuggestions maps a substring of an error to a suggested fix.
// Ordered, so the hint shown is the same on every run when several keywords
// match the same error.
var errorSuggestions = []struct {
	keyword  string
	solution string
}{
	{"Unauthorized", "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here"},
	{"API key", "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here"},
	{"timeout", "The request timed out. Try again or check your network connection"},
	{"deadline exceeded", "The request timed out. Try again or check your network connection"},
	{"connection refused", "Cannot reach API. Check your internet connection"},
}

func printVerbose(message string) {
	fmt.Printf("[VERBOSE] %s\n", message)
}

func printJSON(data interface{}) {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Printf("%+v\n", data)
		return
	}
	fmt.Println(string(b))
}

func SetVerbose(v bool) {
	verbose = v
	// InitLogger(v)
}

func IsVerbose() bool {
	return verbose
}

// SetTimeout sets the per-request timeout
func SetTimeout(d time.Duration) {
	requestTimeout = d
}

// Timeout returns the per-request timeout
func Timeout() time.Duration {
	return requestTimeout
}
