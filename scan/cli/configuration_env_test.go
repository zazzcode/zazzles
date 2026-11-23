package cli

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/judge"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	reportpkg "github.com/zazzcode/zazzles/scan/internal/report"
)

// TestEnvValuesNeverReported scans a project whose environment files hold
// marker values under keys other than APP_ENV and APP_DEBUG, in the forms
// that could carry one into a kept key. No marker may reach the JSON, HTML
// or SARIF report or any judge request.
func TestEnvValuesNeverReported(t *testing.T) {
	const marker = "zz-env-marker"
	root := t.TempDir()
	fixture := filepath.Join(scanModuleRoot, "internal/langphp/testdata/symfony/configuration")
	err := filepath.WalkDir(fixture, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixture, p)
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
	for name, text := range map[string]string{
		// The project file: a continuation line, a value with a second
		// assignment, and a third key.
		".env": "APP_ENV=prod\\\nAPP_SECRET=" + marker + "-1\nAPP_DEBUG=0 MAILER_DSN=" + marker + "-2\nDATABASE_URL=mysql://" + marker + "-3\n",
		// The deployed file: a kept key beside third keys.
		"deploy/env.stage": "APP_SECRET=" + marker + "-4\nAPP_ENV=dev\nAPP_DEBUG=\"1 " + marker + "-5\"\nexport API_TOKEN=" + marker + "-6\n",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := pipeline.AnalyzeWithOptions(root, "", nil, pipeline.Options{})
	if err != nil {
		t.Fatal(err)
	}
	report.SelectedScope = &analysis.EntrySelection{}
	report.RecordCheckMatches(nil)
	client, err := judge.New("openai", "fixture-model", "never-persist-test-key")
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string][]byte{}
	kept := false
	for _, u := range report.Uses {
		trace, err := client.Preview(u)
		if err != nil {
			t.Fatalf("%s: %v", u.ID, err)
		}
		outputs["request "+u.ID] = trace.Request
		if u.Configuration != nil && u.Sink.Span.File == "deploy/env.stage" && u.Sink.Text == "APP_ENV=dev" {
			kept = true
		}
	}
	if !kept {
		t.Fatal("the deployed environment file gave no debug_enabled candidate, so the scan read no environment value")
	}
	reportpkg.Enrich(report)
	if outputs["json"], err = json.Marshal(report); err != nil {
		t.Fatal(err)
	}
	if outputs["sarif"], err = json.Marshal(reportpkg.SARIF(report)); err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := reportpkg.HTML(&page, report); err != nil {
		t.Fatal(err)
	}
	outputs["html"] = page.Bytes()
	for name, raw := range outputs {
		for _, leaked := range []string{marker, "APP_SECRET", "MAILER_DSN", "DATABASE_URL", "API_TOKEN"} {
			if strings.Contains(string(raw), leaked) {
				t.Errorf("%s contains %q", name, leaked)
			}
		}
	}
}
