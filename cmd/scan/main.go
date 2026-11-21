// Command scan is the root compatibility entry point for the Zazzles scanner CLI.
// The canonical entry point is ./scan/cmd/scan.
package main

import (
	"os"

	"github.com/zazzcode/zazzles/scan/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
