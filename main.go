package main

import (
	"os"

	"github.com/andpalmier/yrfy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
