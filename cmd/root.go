package cmd

import (
	"fmt"
	"os"
)

// Execute runs the root command and handles subcommands
func Execute() error {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-v", "--verbose":
			SetVerbose(true)
			args = append(args[:i], args[i+1:]...)
			i--
		case "-V", "--version":
			return executeVersion([]string{})
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
	default:
		printError(fmt.Sprintf("unknown subcommand '%s'", args[0]))
		printRootHelp()
		fmt.Println()
		os.Exit(1)
	}
	return nil
}
