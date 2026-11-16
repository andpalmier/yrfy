package cmd

import (
	"fmt"
	"os"
	"time"
)

// Execute runs the root command and handles subcommands
func Execute() error {
	// Parse global flags only before the subcommand. Otherwise a flag value
	// such as "-comment -t" would be mistaken for the global timeout flag.
	args := os.Args[1:]
globals:
	for len(args) > 0 {
		switch args[0] {
		case "-v", "--verbose":
			SetVerbose(true)
			args = args[1:]
		case "-V", "--version":
			return executeVersion([]string{})
		case "-t", "--timeout":
			if len(args) < 2 {
				printError("missing value for " + args[0])
				return fmt.Errorf("missing timeout value")
			}
			d, err := time.ParseDuration(args[1])
			if err != nil || d <= 0 {
				printError(fmt.Sprintf("invalid timeout %q: use a duration such as 45s or 2m", args[1]))
				return fmt.Errorf("invalid timeout")
			}
			SetTimeout(d)
			args = args[2:]
		default:
			break globals
		}
	}

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printRootHelp()
		fmt.Println()
		return nil
	}

	switch args[0] {
	case "version":
		return executeVersion(args[1:])
	case "scan":
		return executeScan(args[1:])
	case "task":
		return executeTask(args[1:])
	case "query":
		return executeQuery(args[1:])
	case "rescan":
		return executeRescan(args[1:])
	case "download":
		return executeDownload(args[1:])
	case "rules":
		return executeRules(args[1:])
	default:
		printError(fmt.Sprintf("unknown subcommand '%s'", args[0]))
		printRootHelp()
		fmt.Println()
		os.Exit(1)
	}
	return nil
}
