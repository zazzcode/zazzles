package main

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type fileChange struct {
	name, oldMode, newMode, oldBlob, newBlob string
}

type lineSpan struct {
	first, end int // 1-based, with an exclusive end
}

var hunkHeader = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if failure, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git %s failed: %w (%+q)", args[0], err, bytes.TrimSpace(failure.Stderr))
		}
		return nil, fmt.Errorf("git %s failed: %w", args[0], err)
	}
	return out, nil
}

func lintDiff(dir, baseRef, headRef string, out io.Writer) (bool, error) {
	base, err := git(dir, "rev-parse", "--verify", "--end-of-options", baseRef+"^{commit}")
	if err != nil {
		return false, fmt.Errorf("resolve base commit: %w", err)
	}
	head, err := git(dir, "rev-parse", "--verify", "--end-of-options", headRef+"^{commit}")
	if err != nil {
		return false, fmt.Errorf("resolve head commit: %w", err)
	}
	changes, err := markdownChanges(dir, string(bytes.TrimSpace(base)), string(bytes.TrimSpace(head)))
	if err != nil {
		return false, err
	}

	found := false
	for _, change := range changes {
		report := func(line int, message string) {
			fmt.Fprintf(out, "%+q:%d: %s\n", change.name, line, message)
			found = true
		}
		if !regularFile(change.newMode) {
			report(1, "expected a regular Markdown or agent rules file")
			continue
		}
		if err := lintChange(dir, change, report); err != nil {
			return found, fmt.Errorf("lint %+q: %w", change.name, err)
		}
	}
	return found, nil
}

func markdownChanges(dir, base, head string) ([]fileChange, error) {
	// Treat renames as additions so a file entering a Markdown path is checked.
	raw, err := git(dir, "diff", "--raw", "-z", "--no-abbrev", "--no-relative",
		"--no-renames", "--diff-filter=AMT", base, head, "--")
	if err != nil {
		return nil, err
	}
	fields := bytes.Split(raw, []byte{0})
	if len(fields)%2 != 1 || len(fields[len(fields)-1]) != 0 {
		return nil, fmt.Errorf("unexpected git raw diff format")
	}
	var changes []fileChange
	for i := 0; i+1 < len(fields); i += 2 {
		name := string(fields[i+1])
		if !isMarkdown(name) {
			continue
		}
		meta := strings.Fields(string(fields[i]))
		if len(meta) != 5 || !strings.HasPrefix(meta[0], ":") {
			return nil, fmt.Errorf("unexpected git raw diff entry for %+q", name)
		}
		changes = append(changes, fileChange{
			name: name, oldMode: meta[0][1:], newMode: meta[1], oldBlob: meta[2], newBlob: meta[3],
		})
	}
	return changes, nil
}

func isMarkdown(name string) bool {
	name = strings.ToLower(path.Base(name))
	if name == ".cursorrules" {
		return true
	}
	switch path.Ext(name) {
	case ".md", ".markdown", ".mdx", ".mdc":
		return true
	default:
		return false
	}
}

func regularFile(mode string) bool {
	return mode == "100644" || mode == "100755"
}

func lintChange(dir string, change fileChange, report func(int, string)) error {
	var spans []lineSpan
	if regularFile(change.oldMode) {
		var err error
		spans, err = addedLines(dir, change.oldBlob, change.newBlob)
		if err != nil || len(spans) == 0 {
			return err
		}
	}
	blob, err := git(dir, "cat-file", "blob", change.newBlob)
	if err != nil {
		return err
	}
	lintLines(blob, spans, report)
	return nil
}

func addedLines(dir, oldBlob, newBlob string) ([]lineSpan, error) {
	if oldBlob == newBlob {
		return nil, nil
	}
	// Compare blobs directly so path attributes cannot select another diff driver.
	patch, err := git(dir, "diff", "--text", "--no-ext-diff", "--no-textconv", "--no-color",
		"--unified=0", "--inter-hunk-context=0", "--diff-algorithm=myers",
		"--no-indent-heuristic", oldBlob, newBlob, "--")
	if err != nil {
		return nil, err
	}
	var spans []lineSpan
	for line := range bytes.Lines(patch) {
		if !bytes.HasPrefix(line, []byte("@@ ")) {
			continue
		}
		match := hunkHeader.FindSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("unexpected git hunk header")
		}
		first, err := strconv.Atoi(string(match[1]))
		if err != nil {
			return nil, fmt.Errorf("parse git hunk start: %w", err)
		}
		count := 1
		if len(match[2]) > 0 {
			count, err = strconv.Atoi(string(match[2]))
			if err != nil {
				return nil, fmt.Errorf("parse git hunk length: %w", err)
			}
		}
		if count > 0 {
			spans = append(spans, lineSpan{first: first, end: first + count})
		}
	}
	return spans, nil
}
