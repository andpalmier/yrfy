package cmd

import (
	"fmt"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func executeVersion(args []string) error {
	fmt.Printf("yrfy version %s\n", Version)
	fmt.Printf("  commit: %s\n", Commit)
	fmt.Printf("  built: %s\n", BuildDate)
	return nil
}
