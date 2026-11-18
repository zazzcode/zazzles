package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// WriteBundle creates a fresh private run folder under base, never replacing an earlier run.
// The directory name is operational metadata; artifact contents remain deterministic.
func WriteBundle(base string, r *analysis.AnalysisReport) (string, error) {
	base, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	name := strings.Map(func(ch rune) rune {
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '-' || ch == '_' {
			return ch
		}
		return '-'
	}, filepath.Base(filepath.Clean(r.Root)))
	if strings.Trim(name, "-") == "" {
		name = "target"
	}
	repoDir := filepath.Join(base, name)
	if err := os.MkdirAll(repoDir, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(repoDir, "run-")
	if err != nil {
		return "", err
	}
	Enrich(r)
	outputs := []struct {
		name  string
		write func(io.Writer) error
	}{
		{"findings.json", func(w io.Writer) error { enc := json.NewEncoder(w); enc.SetIndent("", "  "); return enc.Encode(r) }},
		{"findings.html", func(w io.Writer) error { return HTML(w, r) }},
		{"findings.sarif", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(SARIF(r))
		}},
	}
	for _, output := range outputs {
		path := filepath.Join(dir, output.name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return dir, err
		}
		// Renderers emit many small writes; buffer them so each is not a syscall.
		w := bufio.NewWriterSize(f, 1<<20)
		err = output.write(w)
		if err == nil {
			err = w.Flush()
		}
		closeErr := f.Close()
		if err != nil {
			return dir, fmt.Errorf("write %s: %w", path, err)
		}
		if closeErr != nil {
			return dir, closeErr
		}
	}
	return dir, nil
}
