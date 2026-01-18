package cmd

import (
	"log"
	"os"
)

var logger *log.Logger

func InitLogger(verbose bool) {
	if verbose {
		logger = log.New(os.Stderr, "[DEBUG] ", log.Ltime|log.Lshortfile)
	} else {
		logger = log.New(os.Stderr, "", 0)
	}
}

func init() {
	InitLogger(false)
}
