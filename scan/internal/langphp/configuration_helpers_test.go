package langphp

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// removed marks an overlay path that is deleted from the fixture copy.
const removed = "\x00removed"

// overlayFixture copies a fixture project and applies the overlay to the
// copy: each path is written, or deleted when its text is removed.
func overlayFixture(t *testing.T, dir string, overlay map[string]string) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(root, rel), 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, rel), raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range overlay {
		p := filepath.Join(root, filepath.FromSlash(name))
		if text == removed {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func at(s analysis.Span) string { return s.File + ":" + strconv.Itoa(s.StartLine) }

// configurationRecords returns each configuration candidate keyed by
// "check file:line".
func configurationRecords(r *analysis.AnalysisReport) map[string]analysis.CandidateUse {
	out := map[string]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == analysis.ConfigurationKind {
			out[u.Configuration.Check+" "+at(u.Sink.Span)] = u
		}
	}
	return out
}

// joinedFacts lists a candidate's joined facts as "kind file:line text".
func joinedFacts(u analysis.CandidateUse) []string {
	var out []string
	for _, e := range u.Configuration.Joined {
		out = append(out, e.Kind+" "+at(e.Span)+" "+e.Text)
	}
	return out
}

func gapKinds(gaps []analysis.Gap) []string {
	var out []string
	for _, g := range gaps {
		out = append(out, g.Kind)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V, keep func(string) bool) []string {
	var out []string
	for k := range m {
		if keep(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p+" ") {
			return true
		}
	}
	return false
}
