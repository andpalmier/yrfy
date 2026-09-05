package cmd

import (
	"flag"
	"fmt"
)

// executeRescan handles the 'rescan' subcommand
func executeRescan(args []string) error {
	rescanCmd := flag.NewFlagSet("rescan", flag.ExitOnError)
	hash := rescanCmd.String("hash", "", "MD5, SHA1, SHA256 or SHA3-384 hash of the file to rescan")

	rescanCmd.Usage = func() {
		printUsageHeader("rescan", "Asks YARAify to scan a file it already holds against the current rules.")
		fmt.Println("\nFlags:")
		fmt.Println("  -hash <hash>    MD5, SHA1, SHA256 or SHA3-384 hash of the file")
		fmt.Println("\nExample:")
		fmt.Println("  yrfy rescan -hash 3cf9260ab6feb907cca7138f8959cbfa")
		fmt.Println("\nThe scan is queued. Use the returned task id with 'yrfy task -id <id>'.")
	}

	if err := rescanCmd.Parse(args); err != nil {
		return err
	}

	if *hash == "" {
		printError("you must specify a hash using -hash")
		rescanCmd.Usage()
		return fmt.Errorf("missing hash")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	result, err := client.RescanFile(ctx, *hash)
	if err != nil {
		printDetailedError(err, fmt.Sprintf("Failed to request a rescan of %s", *hash))
		return err
	}

	printJSON(result)
	return nil
}
