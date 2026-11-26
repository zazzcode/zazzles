/*
Command mdlint checks added and replaced lines in committed Markdown and agent
rule files. It flags invisible characters, hidden comments, common prompt
injection patterns, and basic text defects before a change reaches integration.
Prompt checks normalize common obfuscations and use paragraph context.

Agents may read raw source, including content that a Markdown preview hides.
The diff keeps unrelated legacy content out of the gate. Findings identify
locations and rules without repeating suspect text into logs.
*/
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(".", os.Args[1:], os.Stderr))
}

func run(dir string, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdlint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	base := flags.String("base", "", "base commit (required)")
	head := flags.String("head", "HEAD", "commit containing the proposed changes")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: go run ./tools/mdlint -base <commit> [-head <commit>]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *base == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}

	found, err := lintDiff(dir, *base, *head, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mdlint: %v\n", err)
		return 2
	}
	if found {
		return 1
	}
	return 0
}
