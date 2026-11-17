package parse

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// dvwaPin is the acceptance revision of the DVWA checkout this gate was
// reviewed against (.zazz/evaluation/dvwa-detection-guide.md). A different
// revision fails here so changed modules get re-reviewed, never silently
// judged with stale expectations.
const dvwaPin = "a1978a2fed195acd093010af6395f86a281537ca"

// TestDVWASourceKey is the offline structural gate against a clean DVWA
// checkout: every required module of the detection guide produces its
// candidate kind with source-attributed dependencies, every record survives
// judge selection, and the guestbook stored-XSS link resolves to its writing
// entry. Expectations live only in this test and never enter model inputs;
// protection verdicts (impossible-level controls) belong to paid assessment.
func TestDVWASourceKey(t *testing.T) {
	root := os.Getenv("ZAZZLES_DVWA")
	if root == "" {
		t.Skip("set ZAZZLES_DVWA to a clean DVWA checkout")
	}
	if out, err := exec.Command("git", "-C", root, "status", "--porcelain").Output(); err != nil || len(strings.TrimSpace(string(out))) > 0 {
		t.Skipf("DVWA checkout has local changes: %s %v", out, err)
	}
	head, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if rev := strings.TrimSpace(string(head)); rev != dvwaPin {
		t.Fatalf("DVWA at %s, guide pin is %s: re-review changed modules and re-pin the guide", rev, dvwaPin)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range r.Gaps {
		if g.Kind == "parse_error" {
			t.Errorf("parse error %s", g.At.File)
		}
	}
	for i := range r.Uses {
		u := &r.Uses[i]
		if u.Kind == "xss_data_candidate" {
			continue // data-transfer facts for cross-tier linking; never judged
		}
		if _, err := analysispacks.Select(*u); err != nil {
			t.Errorf("%s %s:%d: judge selection rejects the record: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
		}
	}
	require := []struct{ prefix, kind, label string }{
		{"vulnerabilities/sqli/", "sql_query_candidate", "SQLI-001"},
		{"vulnerabilities/sqli_blind/", "sql_query_candidate", "SQLI-002"},
		{"vulnerabilities/brute/", "sql_query_candidate", "AUTH-001"},
		{"vulnerabilities/captcha/", "sql_query_candidate", "AUTH-002"},
		{"vulnerabilities/csrf/", "sql_query_candidate", "CSRF-001"},
		{"vulnerabilities/exec/", "command_execution_candidate", "CMD-001"},
		{"vulnerabilities/xss_r/", "xss_candidate", "XSSR-001"},
		{"vulnerabilities/xss_s/", "sql_query_candidate", "XSSS-001 write"},
		{"vulnerabilities/upload/", "path_traversal_candidate", "UPLD-001"},
		{"vulnerabilities/fi/", "path_traversal_candidate", "FI-001"},
		{"vulnerabilities/open_redirect/", "open_redirect_candidate", "REDIR-001"},
		{"vulnerabilities/view_help.php", "code_execution_candidate", "CODE-001"},
	}
	for _, req := range require {
		if !dvwaHasCandidate(r.Uses, req.prefix, req.kind) {
			t.Errorf("%s: no %s with a sink or input dependency in %s", req.label, req.kind, req.prefix)
		}
	}
	dvwaStoredLink(t, r.Uses)
}

// dvwaHasCandidate reports a use of the kind whose sink or any dependency's
// source evidence sits under prefix (module attribution rides input spans for
// the shared dvwaPage.inc.php render sink).
func dvwaHasCandidate(uses []analysis.CandidateUse, prefix, kind string) bool {
	for i := range uses {
		u := &uses[i]
		if u.Kind != kind {
			continue
		}
		if strings.HasPrefix(u.Sink.Span.File, prefix) {
			return true
		}
		for _, d := range u.Dependencies {
			if strings.HasPrefix(d.Source.Span.File, prefix) {
				return true
			}
		}
	}
	return false
}

// dvwaStoredLink asserts the guestbook stored-XSS chain resolves to its
// writing entry (XSSS-001).
func dvwaStoredLink(t *testing.T, uses []analysis.CandidateUse) {
	t.Helper()
	for i := range uses {
		u := &uses[i]
		if u.Kind != "xss_candidate" || u.XSS == nil || u.XSS.Type != "stored" {
			continue
		}
		if u.XSS.StorageKey != "php-sql:guestbook.comment" && u.XSS.StorageKey != "php-sql:guestbook.name" {
			continue
		}
		if !u.XSS.OriginResolved {
			t.Errorf("guestbook stored origin unresolved: %s", u.XSS.ProtectionReason)
		}
		if len(u.XSS.RelatedEntries) == 0 {
			t.Errorf("guestbook stored link missing writing entry: %s", fmt.Sprintf("%s:%d", u.Sink.Span.File, u.Sink.Span.StartLine))
		}
		return
	}
	t.Error("no stored guestbook claim (XSSS-001)")
}
