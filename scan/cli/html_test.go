package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportHTMLFromSavedReport(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "report.json")
	saved := json.RawMessage(`{"schema_version":1,"root":"target-no-longer-present","entries":[{"route":{"id":"r","method":"POST","path_pattern":"/login"}}],"uses":[{"id":"u","route_id":"r","kind":"sql_query_candidate","sink":{"text":"db.query(sql)"},"assessment":{"status":"not_run"}}]}`)
	data, _ := json.Marshal(saved)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--export-html", file}, &out, &errout); code != 0 || !strings.Contains(out.String(), "POST /login") || !strings.Contains(out.String(), "Not assessed") {
		t.Fatalf("code=%d stderr=%s", code, errout.String())
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(data, after) {
		t.Fatal("export changed canonical JSON")
	}
	for _, args := range [][]string{{"--export-html", file, "--export-sarif", file}, {"--export-html", file, "--json"}, {"--export-html", file, "--analyze", "target"}, {"--export-html", file, "--judge", "openai"}} {
		out.Reset()
		errout.Reset()
		if code := run(args, &out, &errout); code != 2 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
	for _, bad := range []string{`{`, `{"schema_version":99,"uses":[]}`, `{"schema_version":1,"routes":[]}`} {
		if err := os.WriteFile(file, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errout.Reset()
		if code := run([]string{"--export-html", file}, &out, &errout); code != 1 || out.Len() != 0 {
			t.Fatalf("bad=%s code=%d", bad, code)
		}
	}
}

func TestOutputDirectoryPrecedenceAndStdout(t *testing.T) {
	target, err := filepath.Abs("../internal/langjs/testdata/string-flow")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	environmentDir := filepath.Join(base, "env")
	override := filepath.Join(base, "flag")
	t.Setenv("SCAN_FINDINGS_DIR", environmentDir)
	for _, args := range [][]string{
		{"--analyze", "--entry", "server.ts", target},
		{"--analyze", "--json", "--output-dir", override, "--entry", "server.ts", target},
		{"--analyze", "--json", "--output-dir", "", "--entry", "server.ts", target},
	} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 0 {
			t.Fatalf("code=%d err=%s", code, stderr.String())
		}
		if strings.Contains(strings.Join(args, " "), "--json") {
			var report analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Findings) == 0 {
				t.Fatalf("stdout not evidence JSON: %s", out.String())
			}
		}
	}
	for _, dir := range []string{environmentDir, override} {
		repoDir := filepath.Join(dir, filepath.Base(target))
		runs, err := os.ReadDir(repoDir)
		if err != nil || len(runs) != 1 {
			t.Fatalf("output %s runs=%v err=%v", dir, runs, err)
		}
		for _, name := range []string{"findings.json", "findings.html", "findings.sarif"} {
			if _, err := os.Stat(filepath.Join(repoDir, runs[0].Name(), name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"--list", "--output-dir", override, target}, &out, &stderr); code != 2 {
		t.Fatalf("list output-dir code=%d", code)
	}
	if code := run([]string{"--analyze", "--output-dir", target + "/server.ts", "--entry", "server.ts", target}, &out, &stderr); code != 1 {
		t.Fatalf("file output-dir code=%d", code)
	}
}

// The stub prevents real provider traffic while exercising failed-assessment delivery.
type failingReportTransport struct{}

func (failingReportTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline assessment failure")
}

func TestFailedJudgeRetainsOutputBundle(t *testing.T) {
	// A fixture whose first record is sent: the string-flow record is now
	// settled by the resolution gate without a request.
	target, err := filepath.Abs("../internal/langjs/testdata/javascript/path-traversal")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	t.Setenv("SCAN_FINDINGS_DIR", base)
	t.Setenv("OPENAI_API_KEY", "offline-test-key")
	previous := http.DefaultTransport
	http.DefaultTransport = failingReportTransport{}
	t.Cleanup(func() { http.DefaultTransport = previous })
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--entry", "server.js", "--judge", "openai", "--judge-limit", "1", target}, &out, &stderr); code != exitOK || !strings.Contains(stderr.String(), "scan: warning: some assessments are incomplete") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	files, err := filepath.Glob(filepath.Join(base, "path-traversal", "run-*", "findings.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var report analysis.AnalysisReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, u := range report.Uses {
		failed = failed || u.Assessment.Status == "failed"
	}
	if !failed {
		t.Fatal("failure lost")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(files[0]), "findings.html")); err != nil {
		t.Fatal(err)
	}
}
