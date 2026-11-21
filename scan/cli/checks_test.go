package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestEntrySelectors(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := "../internal/langjs/testdata/string-flow"
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--json", root}, &out, &stderr); code != exitOK {
		t.Fatal(stderr.String())
	}
	var inventory analysis.AnalysisReport
	if err := json.Unmarshal(out.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	first := inventory.Entries[0]
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"kind", []string{"--analyze", "--json", "--entry-kind", "http", root}, exitOK},
		{"id", []string{"--analyze", "--json", "--entry-id", first.ID, root}, exitOK},
		{"intersect", []string{"--analyze", "--json", "--entry", "server.ts", "--route", first.HTTP.Path, "--entry-kind", "http", "--entry-id", first.ID, root}, exitOK},
		{"empty intersection", []string{"--analyze", "--route", first.HTTP.Path, "--entry-kind", "browser", root}, exitError},
		{"unknown id", []string{"--analyze", "--entry-id", "missing", root}, exitError},
		{"invalid kind", []string{"--analyze", "--entry-kind", "HTTP", root}, exitUsage},
		{"list conflict", []string{"--list", "--entry-kind", "http", root}, exitUsage},
		{"export conflict", []string{"--export-html", "saved.json", "--entry-kind", "http"}, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			stderr.Reset()
			if code := run(tc.args, &out, &stderr); code != tc.code {
				t.Fatalf("code %d want %d: %s", code, tc.code, stderr.String())
			}
			if tc.code == exitOK {
				var r analysis.AnalysisReport
				if err := json.Unmarshal(out.Bytes(), &r); err != nil {
					t.Fatal(err)
				}
				if r.SelectedScope == nil {
					t.Fatal("missing selected scope")
				}
				if err := r.ValidateUses(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, tc := range []struct {
		name, selector, legacy string
		valid                  bool
	}{
		{"legacy", "", `"method":"POST","path":"/login",`, true},
		{"http", `{"kind":"http","method":"POST","path":"/login"}`, "", true},
		{"graphql", `{"kind":"graphql","type":"Query","field":"search"}`, "", true},
		{"grpc", `{"kind":"grpc","service":"accounts.AccountService","method":"Create"}`, "", true},
		{"browser", `{"kind":"browser","category":"component","name":"Signup","event":"submit"}`, "", true},
		{"conflict", `{"kind":"http","method":"POST","path":"/login"}`, `"method":"POST","path":"/login",`, false},
		{"mixed fields", `{"kind":"graphql","type":"Query","field":"search","path":"/graphql"}`, "", false},
		{"unknown field", `{"kind":"http","method":"POST","path":"/login","typo":true}`, "", false},
		{"unknown kind", `{"kind":"future"}`, "", false},
		{"missing identity", `{"kind":"browser","category":"component"}`, "", false},
		{"file escape", `{"kind":"http","method":"POST","path":"/login","registration_file":"../other.ts"}`, "", false},
	} {
		t.Run("decode/"+tc.name, func(t *testing.T) {
			prefix := tc.legacy
			if tc.selector != "" {
				prefix += `"selector":` + tc.selector + `,`
			}
			data := `[{` + prefix + `"id":"check","kind":"sql_query","fields":["email"],"validation":"explicit policy","protection":"data only"}]`
			file := filepath.Join(t.TempDir(), "checks.json")
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			checks, err := loadChecks(file)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && (checks[0].Selector == nil || checks[0].Method != "" || checks[0].Path != "") {
				t.Fatal("legacy selector not normalized")
			}
		})
	}
	for _, data := range []string{"[]", strings.Repeat(" ", 65537), `[{"id":"x","unknown":true}]`, "[] []"} {
		file := filepath.Join(t.TempDir(), "checks.json")
		os.WriteFile(file, []byte(data), 0600)
		if _, err := loadChecks(file); err == nil {
			t.Fatal("invalid/oversized checks accepted")
		}
	}
}
