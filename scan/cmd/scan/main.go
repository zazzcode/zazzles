// Command scan is the canonical entry point for the Zazzles scanner CLI.
package main

import (
	"os"

	"github.com/zazzcode/zazzles/scan/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
