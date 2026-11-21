package langphp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func classFixture(t *testing.T) *analysis.AnalysisReport {
	t.Helper()
	return phpAnalyze(t, filepath.Join("testdata", "classes"), "")
}

// classCommands returns the command candidates whose sink is in file, keyed
// by the entry file of their invocation.
func classCommands(r *analysis.AnalysisReport, file string) map[string]analysis.CandidateUse {
	entries := map[string]string{}
	for _, e := range r.Entries {
		entries[e.ID] = e.Location.Span.File
	}
	out := map[string]analysis.CandidateUse{}
	for _, u := range phpUsesOfKind(r, "command_execution_candidate") {
		if u.Sink.Span.File == file {
			out[entries[u.EntryID]] = u
		}
	}
	return out
}

func hasSource(u analysis.CandidateUse, file, text string) bool {
	for _, d := range u.Dependencies {
		if d.Source.Kind == "input_source" && d.Source.Span.File == file && strings.Contains(d.Source.Text, text) {
			return true
		}
	}
	return false
}

// TestPHPClassBinding (close-findings-gaps AC3, D-8 to D-11).
func TestPHPClassBinding(t *testing.T) {
	r := classFixture(t)
	t.Run("new C across modules reaches a private method's exec", func(t *testing.T) {
		got := classCommands(r, "basic/src/C.php")
		u, ok := got["basic/index.php"]
		if !ok || len(got) != 1 {
			t.Fatalf("want one command candidate under basic/index.php, got %v", keys(got))
		}
		if !hasSource(u, "basic/src/C.php", "php://input") {
			t.Fatalf("body source missing: %+v", u.Dependencies)
		}
		if u.Completeness == nil || len(u.Completeness.Blockers) > 0 || u.Command.Paths[0].Protection != "raw" {
			t.Fatalf("want a raw witnessed path: blockers %+v paths %+v", u.Completeness, u.Command.Paths)
		}
	})
	t.Run("two declarations of one name stay unresolved", func(t *testing.T) {
		if got := classCommands(r, "duplicate/src/RunnerA.php"); len(got) > 0 {
			t.Fatalf("an ambiguous class yields no candidate, got %v", keys(got))
		}
		if got := classCommands(r, "duplicate/src/RunnerB.php"); len(got) > 0 {
			t.Fatalf("an ambiguous class yields no candidate, got %v", keys(got))
		}
		if !reportHasGap(r, "php_class_unresolved", "declared more than once") {
			t.Fatal("want php_class_unresolved naming the duplicate declaration")
		}
	})
	t.Run("a switch on a constant property reaches only its case", func(t *testing.T) {
		got := classCommands(r, "switch/src/Health.php")
		if _, ok := got["switch/index.php"]; ok {
			t.Fatal("the constant command never selects the exec case")
		}
		u, ok := got["switch/request.php"]
		if !ok || !hasSource(u, "switch/src/Health.php", "php://input") {
			t.Fatalf("a request-selected command reaches the exec case: %v", keys(got))
		}
	})
	t.Run("escapeshellarg on a promoted property records the control", func(t *testing.T) {
		got := classCommands(r, "quoted/src/Pinger.php")
		u, ok := got["quoted/index.php"]
		if !ok || !hasSource(u, "quoted/index.php", "host") {
			t.Fatalf("want the promoted request property at the shell: %v", keys(got))
		}
		if p := u.Command.Paths; len(p) != 1 || p[0].Protection != "guarded" || len(p[0].Controls) == 0 {
			t.Fatalf("want a guarded path with its control: %+v", p)
		}
	})
	t.Run("a trait method of an in-repository parent resolves", func(t *testing.T) {
		got := classCommands(r, "hierarchy/src/Base.php")
		u, ok := got["hierarchy/index.php"]
		if !ok || !hasSource(u, "hierarchy/index.php", "target") || u.Command.Paths[0].Protection != "raw" {
			t.Fatalf("want the trait's system call with the request target: %v", keys(got))
		}
		if !reportHasGap(r, "php_class_unresolved", "Vendor\\Missing\\Runner") {
			t.Fatal("a method behind a parent outside the repository leaves a gap")
		}
	})
}

func keys(m map[string]analysis.CandidateUse) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func reportHasGap(r *analysis.AnalysisReport, kind, detail string) bool {
	all := append([]analysis.Gap{}, r.Gaps...)
	for _, u := range r.Uses {
		all = append(all, u.Gaps...)
	}
	for _, g := range all {
		if g.Kind == kind && strings.Contains(g.Detail, detail) {
			return true
		}
	}
	return false
}

// TestPHPMethodBoundKeepsUnresolvedResult: a method call the expansion bound
// stops (here a recursive method) keeps the unresolved-method result instead
// of attaching work_limit blockers to every record its output reaches.
func TestPHPMethodBoundKeepsUnresolvedResult(t *testing.T) {
	root := phpFixture(t, map[string]string{"index.php": `<?php
class Markdown {
	public function text($s) { return $this->lines($s); }
	private function lines($s) { return $this->block($s) . $this->lines($s); }
	private function block($s) { return "<p>" . $s . "</p>"; }
}
$md = new Markdown();
$page = $md->text(file_get_contents('README.md'));
echo "<div>" . $_COOKIE['theme'] . "</div>" . $page;
`})
	r := phpAnalyze(t, root, "")
	found := false
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		if !hasSource(u, "index.php", "theme") {
			continue
		}
		found = true
		for _, g := range u.Completeness.Blockers {
			if g.Kind == "work_limit" {
				t.Fatalf("the bound added a blocker: %+v", g)
			}
		}
	}
	if !found {
		t.Fatal("no rendering claim for the cookie value")
	}
}
