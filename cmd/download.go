package cmd

import (
	"flag"
	"fmt"

	"github.com/andpalmier/yrfy/api"
)

// executeDownload handles the 'download' subcommand
func executeDownload(args []string) error {
	downloadCmd := flag.NewFlagSet("download", flag.ExitOnError)
	sha256 := downloadCmd.String("sha256", "", "SHA256 hash of the file to download")
	unpacked := downloadCmd.Bool("unpacked", false, "Download the unpacked form of the file")
	out := downloadCmd.String("out", "", "Path to write the file to")

	downloadCmd.Usage = func() {
		printUsageHeader("download", "Downloads a file from YARAify by its SHA256 hash.")
		fmt.Println("\nFlags:")
		fmt.Println("  -sha256 <hash>    SHA256 hash of the file to download")
		fmt.Println("  -unpacked         Download the unpacked form instead of the original")
		fmt.Println("  -out <path>       Where to write the file (default: <sha256>.zip)")
		fmt.Println("\nExamples:")
		fmt.Println("  yrfy download -sha256 <hash>")
		fmt.Println("  yrfy download -sha256 <hash> -unpacked -out /tmp/unpacked.zip")
		fmt.Printf("\nFiles are zipped with AES128 and the password %q. A tool reporting\n", api.ZipPassword)
		fmt.Println("\"compression type 99\" cannot read AES archives; use 7-Zip or pyzipper.")
		fmt.Println("Files whose reporter chose not to share them cannot be downloaded.")
	}

	if err := downloadCmd.Parse(args); err != nil {
		return err
	}

	if *sha256 == "" {
		printError("you must specify a SHA256 hash using -sha256")
		downloadCmd.Usage()
		return fmt.Errorf("missing SHA256 hash")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	var path string
	if *unpacked {
		path, err = client.DownloadUnpacked(ctx, *sha256, *out)
	} else {
		path, err = client.DownloadFile(ctx, *sha256, *out)
	}
	if err != nil {
		printDetailedError(err, fmt.Sprintf("Failed to download %s", *sha256))
		return err
	}

	fmt.Printf("File downloaded successfully: %s\n", path)
	fmt.Printf("The archive is password protected: %s\n", api.ZipPassword)
	return nil
}
