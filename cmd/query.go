package cmd

import (
	"flag"
	"fmt"

	"github.com/andpalmier/yrfy/api"
)

func executeScan(args []string) error {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	file := scanCmd.String("file", "", "File to scan")
	unpack := scanCmd.Bool("unpack", false, "Enable malware unpacking")
	noClamAV := scanCmd.Bool("no-clamav", false, "Disable ClamAV scanning")
	noShare := scanCmd.Bool("no-share", false, "Do not share the file publicly")
	skipKnown := scanCmd.Bool("skip-known", false, "Skip if file is already known")
	skipNoisy := scanCmd.Bool("skip-noisy", false, "Skip if file was scanned 10+ times in 24h")
	identifier := scanCmd.String("identifier", "", "Identifier to track submission")

	scanCmd.Usage = func() {
		printUsageHeader("scan", "Scan a file with YARAify YARA and ClamAV engines.")
		fmt.Println("\nFlags:")
		fmt.Println("  -file <path>       File to scan (required)")
		fmt.Println("  -unpack            Enable malware unpacking (PE only)")
		fmt.Println("  -no-clamav         Disable ClamAV scanning")
		fmt.Println("  -no-share          Do not share the file publicly")
		fmt.Println("  -skip-known        Skip if file is already known")
		fmt.Println("  -skip-noisy        Skip if file was scanned 10+ times in 24h")
		fmt.Println("  -identifier <id>   Identifier to track submission")
		fmt.Println("\nExamples:")
		fmt.Println("  yrfy scan -file malware.exe")
		fmt.Println("  yrfy scan -file sample.dll -unpack")
		fmt.Println("  yrfy scan -file private.exe -no-share")
	}

	if len(args) < 1 {
		printError("expected -file flag")
		scanCmd.Usage()
		return fmt.Errorf("expected -file flag")
	}

	if err := scanCmd.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		printError("you must specify a file using -file")
		scanCmd.Usage()
		fmt.Println()
		return fmt.Errorf("missing -file flag")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	options := &api.ScanOptions{
		ClamAVScan: 1,
		ShareFile:  1,
	}

	if *noClamAV {
		options.ClamAVScan = 0
	}
	if *unpack {
		options.Unpack = 1
	}
	if *noShare {
		options.ShareFile = 0
	}
	if *skipKnown {
		options.SkipKnown = 1
	}
	if *skipNoisy {
		options.SkipNoisy = 1
	}
	if *identifier != "" {
		options.Identifier = *identifier
	}

	result, err := client.ScanFile(ctx, *file, options)
	if err != nil {
		printDetailedError(err, "Failed to scan file")
		return err
	}

	printJSON(result)
	return nil
}

func executeTask(args []string) error {
	taskCmd := flag.NewFlagSet("task", flag.ExitOnError)
	taskID := taskCmd.String("id", "", "Task ID to query")
	malpediaToken := taskCmd.String("malpedia-token", "", "Malpedia token for non-public rules")

	taskCmd.Usage = func() {
		printUsageHeader("task", "Query task results by task ID.")
		fmt.Println("\nFlags:")
		fmt.Println("  -id <task_id>          Task ID to query (required)")
		fmt.Println("  -malpedia-token <tok>  Malpedia token for TLP:GREEN/AMBER/RED rules")
		fmt.Println("\nExamples:")
		fmt.Println("  yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b")
	}

	if len(args) < 1 {
		printError("expected -id flag")
		taskCmd.Usage()
		return fmt.Errorf("expected -id flag")
	}

	if err := taskCmd.Parse(args); err != nil {
		return err
	}

	if *taskID == "" {
		printError("you must specify a task ID using -id")
		taskCmd.Usage()
		fmt.Println()
		return fmt.Errorf("missing -id flag")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	result, err := client.GetTaskResults(ctx, *taskID, *malpediaToken)
	if err != nil {
		printDetailedError(err, fmt.Sprintf("Failed to get task results: %s", *taskID))
		return err
	}

	printJSON(result)
	return nil
}

func executeQuery(args []string) error {
	queryCmd := flag.NewFlagSet("query", flag.ExitOnError)
	hash := queryCmd.String("hash", "", "Query by file hash (MD5/SHA1/SHA256/SHA3-384)")
	yara := queryCmd.String("yara", "", "Query by YARA rule name")
	clamav := queryCmd.String("clamav", "", "Query by ClamAV signature")
	imphash := queryCmd.String("imphash", "", "Query by imphash")
	tlsh := queryCmd.String("tlsh", "", "Query by TLSH")
	limit := queryCmd.Int("limit", 25, "Limit the number of results (max 1000)")
	malpediaToken := queryCmd.String("malpedia-token", "", "Malpedia token for non-public rules")

	queryCmd.Usage = func() {
		printUsageHeader("query", "Query YARAify by hash, YARA rule, ClamAV signature, or fuzzy hash.")
		fmt.Println("\nFlags:")
		fmt.Println("  -hash <hash>           Query by file hash (MD5/SHA1/SHA256/SHA3-384)")
		fmt.Println("  -yara <rule>           Query by YARA rule name")
		fmt.Println("  -clamav <signature>    Query by ClamAV signature")
		fmt.Println("  -imphash <hash>        Query by imphash")
		fmt.Println("  -tlsh <hash>           Query by TLSH")
		fmt.Println("  -limit <number>        Limit results (default: 25, max: 1000)")
		fmt.Println("  -malpedia-token <tok>  Malpedia token for TLP:GREEN/AMBER/RED rules")
		fmt.Println("\nExamples:")
		fmt.Println("  yrfy query -hash b0bb095dd0ad8b8de1c83b13c38e68dd")
		fmt.Println("  yrfy query -yara MALWARE_Win_Emotet -limit 50")
		fmt.Println("  yrfy query -clamav Win.Malware.Emotet")
		fmt.Println("  yrfy query -imphash 43fd39eb6df6bf3a9a3edd1f646cd16e")
	}

	if len(args) < 1 {
		printError("expected query arguments")
		queryCmd.Usage()
		return fmt.Errorf("expected query arguments")
	}

	if err := queryCmd.Parse(args); err != nil {
		return err
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	if *hash != "" {
		result, err := client.LookupHash(ctx, *hash, *malpediaToken)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to lookup hash: %s", *hash))
			return err
		}
		printJSON(result)
		return nil
	}

	if *yara != "" {
		result, err := client.QueryYARA(ctx, *yara, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query YARA rule: %s", *yara))
			return err
		}
		printJSON(result)
		return nil
	}

	if *clamav != "" {
		result, err := client.QueryClamAV(ctx, *clamav, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query ClamAV: %s", *clamav))
			return err
		}
		printJSON(result)
		return nil
	}

	if *imphash != "" {
		result, err := client.QueryImphash(ctx, *imphash, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query imphash: %s", *imphash))
			return err
		}
		printJSON(result)
		return nil
	}

	if *tlsh != "" {
		result, err := client.QueryTLSH(ctx, *tlsh, *limit)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to query TLSH: %s", *tlsh))
			return err
		}
		printJSON(result)
		return nil
	}

	printError("please provide a query parameter (e.g., -hash, -yara, -clamav)")
	queryCmd.Usage()
	fmt.Println()
	return fmt.Errorf("please provide a query parameter")
}
