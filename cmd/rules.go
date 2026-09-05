package cmd

import (
	"flag"
	"fmt"
)

// executeRules handles the 'rules' subcommand
func executeRules(args []string) error {
	rulesCmd := flag.NewFlagSet("rules", flag.ExitOnError)
	recent := rulesCmd.Bool("recent", false, "List recently deployed public YARA rules")
	mine := rulesCmd.Bool("mine", false, "List the YARA rules deployed under your account")
	get := rulesCmd.String("get", "", "Download one YARA rule by its YARAhub UUID")
	del := rulesCmd.String("delete", "", "Delete one of your own YARA rules by UUID")
	all := rulesCmd.Bool("all", false, "Download the archive of every public YARA rule")
	out := rulesCmd.String("out", "", "Where to write the archive (default: yaraify-rules.zip)")

	rulesCmd.Usage = func() {
		printUsageHeader("rules", "Lists, downloads and deletes YARA rules on YARAhub.")
		fmt.Println("\nFlags:")
		fmt.Println("  -recent          List recently deployed public rules")
		fmt.Println("  -mine            List rules deployed under your account")
		fmt.Println("  -get <uuid>      Print one rule by its YARAhub UUID")
		fmt.Println("  -delete <uuid>   Delete one of your own rules. This cannot be undone")
		fmt.Println("  -all             Download the archive of every public rule")
		fmt.Println("  -out <path>      Where to write the archive (default: yaraify-rules.zip)")
		fmt.Println("\nExamples:")
		fmt.Println("  yrfy rules -recent")
		fmt.Println("  yrfy rules -get 1b95ce79-6034-4740-8e45-5f0840602d1a")
		fmt.Println("  yrfy rules -all -out /tmp/yaraify-rules.zip")
		fmt.Println("\nOnly rules whose author set yarahub_rule_sharing_tlp to TLP:WHITE")
		fmt.Println("can be downloaded. abuse.ch rebuilds the full archive every five")
		fmt.Println("minutes, so there is no point fetching it more often than that.")
	}

	if err := rulesCmd.Parse(args); err != nil {
		return err
	}

	selected := 0
	for _, on := range []bool{*recent, *mine, *get != "", *del != "", *all} {
		if on {
			selected++
		}
	}
	if selected == 0 {
		printError("choose one of -recent, -mine, -get, -delete or -all")
		rulesCmd.Usage()
		return fmt.Errorf("no action selected")
	}
	if selected > 1 {
		printError("choose only one of -recent, -mine, -get, -delete or -all")
		rulesCmd.Usage()
		return fmt.Errorf("more than one action selected")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	switch {
	case *recent:
		result, err := client.RecentYARARules(ctx)
		if err != nil {
			printDetailedError(err, "Failed to list recent YARA rules")
			return err
		}
		printJSON(result)

	case *mine:
		result, err := client.ShowDeployedYARARules(ctx)
		if err != nil {
			printDetailedError(err, "Failed to list your YARA rules")
			return err
		}
		if len(result) == 0 {
			fmt.Println("You have no YARA rules deployed on YARAhub.")
			return nil
		}
		printJSON(result)

	case *get != "":
		rule, err := client.GetYARARule(ctx, *get)
		if err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to download rule %s", *get))
			return err
		}
		fmt.Println(rule)

	case *del != "":
		if err := client.DeleteYARARule(ctx, *del); err != nil {
			printDetailedError(err, fmt.Sprintf("Failed to delete rule %s", *del))
			return err
		}
		fmt.Printf("Deleted YARA rule %s\n", *del)

	case *all:
		path, err := client.DownloadAllRules(ctx, *out)
		if err != nil {
			printDetailedError(err, "Failed to download the YARA rule archive")
			return err
		}
		fmt.Printf("Rules downloaded successfully: %s\n", path)
	}

	return nil
}
