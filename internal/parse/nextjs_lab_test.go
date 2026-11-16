package parse

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// labFamilies maps the CWE of a vuln-nextjs ground-truth row to the record
// kind zazzles produces for it. CWEs without an analyzer family (for example
// CWE-95 eval, CWE-601 open redirect, CWE-502 via SCA) are reported as
// unsupported and skipped, so new lab rows never fail this test silently.
var labFamilies = map[string]string{
	"CWE-22":  "path_traversal_candidate",
	"CWE-78":  "command_execution_candidate",
	"CWE-89":  "sql_query_candidate",
	"CWE-918": "ssrf_candidate",
	"CWE-79":  "xss_candidate",
	"CWE-95":  "code_execution_candidate",
	"CWE-601": "open_redirect_candidate",
}

// TestNextJSVulnLab is the offline integration test against the owner-maintained
// vuln-nextjs lab. The lab grows over time, so the test is driven by the lab's
// own tests/expected-scanner-findings.json at whatever commit is checked out:
// every SAST row with expectedFinding=true in a supported family must produce
// a record of that family in its source file with no completeness blockers
// (complete evidence for the judge); a safe-control row may produce a record
// (the judge decides protection) but never an incomplete one that hides a
// verdict. Judged outcomes are verified by paid runs and exact replay.
func TestNextJSVulnLab(t *testing.T) {
	root := os.Getenv("ZAZZLES_VULN_NEXTJS")
	if root == "" {
		t.Skip("set ZAZZLES_VULN_NEXTJS to a clean vuln-nextjs checkout")
	}
	if out, err := exec.Command("git", "-C", root, "status", "--porcelain").Output(); err != nil || len(strings.TrimSpace(string(out))) > 0 {
		t.Skipf("lab checkout has local changes: %s %v", out, err)
	}
	head, _ := exec.Command("git", "-C", root, "rev-parse", "--short", "HEAD").Output()
	t.Logf("vuln-nextjs at %s", strings.TrimSpace(string(head)))
	raw, err := os.ReadFile(filepath.Join(root, "tests", "expected-scanner-findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var truth struct {
		Sources []struct {
			ID, Source, CWE, Scanner, ControlFor string
			ExpectedFinding                      bool
		} `json:"sources"`
	}
	if err := json.Unmarshal(raw, &truth); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind == "xss_data_candidate" {
			continue // data-transfer facts for cross-tier linking; never judged
		}
		if _, err := analysispacks.Select(u); err != nil {
			t.Errorf("%s %s:%d: judge selection rejects the record: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
		}
	}
	for _, g := range r.Gaps {
		if g.Kind == "parse_error" {
			t.Errorf("parse error %s", g.At.File)
		}
	}
	checked, unsupported := 0, []string{}
	for _, row := range truth.Sources {
		if row.Scanner != "SAST" || row.CWE == "" {
			continue
		}
		kind, ok := labFamilies[row.CWE]
		if !ok {
			unsupported = append(unsupported, row.ID+" "+row.CWE)
			continue
		}
		checked++
		uses := usesOf(r, kind, row.Source)
		if row.ExpectedFinding && len(uses) == 0 {
			t.Errorf("%s: no %s in %s (false negative)", row.ID, kind, row.Source)
		}
		for _, u := range uses {
			if b := blockers(u); len(b) > 0 {
				t.Errorf("%s: %s %s:%d has blockers %+v", row.ID, kind, row.Source, u.Sink.Span.StartLine, b)
			}
			if row.ExpectedFinding && kind == "xss_candidate" && u.XSS != nil && (u.XSS.Protection == "encoded" || u.XSS.Protection == "sanitized") {
				t.Errorf("%s: vulnerable sink classified %s at %s:%d", row.ID, u.XSS.Protection, row.Source, u.Sink.Span.StartLine)
			}
			if !row.ExpectedFinding && kind == "xss_candidate" && u.XSS != nil && u.XSS.Protection == "raw" {
				t.Errorf("%s: safe control classified raw at %s:%d", row.ID, row.Source, u.Sink.Span.StartLine)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no supported ground-truth rows")
	}
	t.Logf("checked %d supported rows; unsupported families: %v", checked, unsupported)
	inv, err := Routes(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range inv.Routes {
		if !strings.HasPrefix(route.Framework, "nextjs") {
			t.Errorf("non-Next route %s %s %s", route.Method, route.PathPattern, route.Registration.File)
		}
	}
}
