package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/pipeline"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

// The architecture baseline pins what a structural refactor must not change for
// every parse fixture repository: candidate IDs in report order, the offline
// judge request and equivalence-signature digests of each candidate, normalized
// report and SARIF hashes, and the record counts. It has its own update flag so a
// broad -update run cannot rebaseline it by accident.
var updateArchitectureBaseline = flag.Bool("update-architecture-baseline", false, "rewrite the architecture compatibility golden")

const (
	architectureBaselineGolden = "testdata/architecture-baseline.json"
	repositoryRoot             = "../.."
)

type baselineUse struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	RequestSHA256   string `json:"request_sha256,omitempty"`
	PreviewError    string `json:"preview_error,omitempty"`
	SignatureSHA256 string `json:"signature_sha256,omitempty"`
	SignatureError  string `json:"signature_error,omitempty"`
}

type baselineFixture struct {
	Uses          []baselineUse `json:"uses"`
	ReportSHA256  string        `json:"report_sha256"`
	SARIFSHA256   string        `json:"sarif_sha256"`
	Entries       int           `json:"entries"`
	Registrations int           `json:"registrations"`
	Dispatch      int           `json:"dispatch_bindings"`
	Callables     int           `json:"callables"`
	Invocations   int           `json:"invocation_contexts"`
	UsesCount     int           `json:"uses_count"`
	Gaps          int           `json:"gaps"`
}

func TestArchitectureBaseline(t *testing.T) {
	fixtures := architectureFixtures(t)
	got := map[string]baselineFixture{}
	for _, rel := range fixtures {
		root := filepath.Join(repositoryRoot, filepath.FromSlash(rel))
		first := architectureSnapshot(t, root)
		second := architectureSnapshot(t, root)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("%s: analysis is not deterministic across two runs: %s", rel, firstBaselineDifference(first, second))
		}
		got[rel] = first
	}
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updateArchitectureBaseline {
		if err := os.WriteFile(architectureBaselineGolden, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(architectureBaselineGolden)
	if err != nil {
		t.Fatalf("architecture golden missing (%v); run go test ./cmd/scan -run TestArchitectureBaseline -update-architecture-baseline", err)
	}
	if bytes.Equal(raw, encoded) {
		return
	}
	var want map[string]baselineFixture
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("architecture golden is not valid JSON: %v", err)
	}
	for _, rel := range fixtures {
		w, ok := want[rel]
		if !ok {
			t.Errorf("%s: fixture is not in the architecture golden", rel)
			continue
		}
		if !reflect.DeepEqual(w, got[rel]) {
			t.Errorf("%s: architecture baseline changed: %s", rel, firstBaselineDifference(w, got[rel]))
		}
	}
	for rel := range want {
		if _, ok := got[rel]; !ok {
			t.Errorf("%s: golden fixture no longer exists", rel)
		}
	}
	if !t.Failed() {
		t.Fatal("architecture golden bytes differ from the generated baseline (formatting only)")
	}
}

// architectureFixtures lists every fixture repository: each directory directly
// under the language and mixed testdata trees (PHP's in internal/langphp), plus the two top-level JS/TS
// repositories. The list is computed and sorted so a new fixture is pinned on its
// next update instead of going stale in a hand-kept list.
func architectureFixtures(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, tree := range []string{"internal/parse/testdata/javascript", "internal/parse/testdata/typescript", "internal/parse/testdata/python", "internal/langphp/testdata", "internal/parse/testdata/mixed"} {
		entries, err := os.ReadDir(filepath.Join(repositoryRoot, tree))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, tree+"/"+e.Name())
			}
		}
	}
	out = append(out, "internal/parse/testdata/express-login", "internal/parse/testdata/string-flow")
	sort.Strings(out)
	return out
}

// architectureSnapshot follows the CLI order in runAnalysisConfigured: analyze,
// select, record checks, build each judge request, then Enrich before hashing the
// report users receive. The client is offline: Preview builds the same request
// bytes AssessTrace would send, and the key never leaves the process.
func architectureSnapshot(t *testing.T, root string) baselineFixture {
	t.Helper()
	report, err := pipeline.AnalyzeWithOptions(root, "", nil, pipeline.Options{})
	if err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	report.SelectedScope = &analysis.EntrySelection{}
	report.RecordCheckMatches(nil)
	client, err := judge.New("openai", "fixture-model", "never-persist-test-key")
	if err != nil {
		t.Fatal(err)
	}
	out := baselineFixture{
		Uses:          []baselineUse{},
		Entries:       len(report.Entries),
		Registrations: len(report.Registrations),
		Dispatch:      len(report.DispatchBindings),
		Callables:     len(report.Callables),
		Invocations:   len(report.InvocationContexts),
		UsesCount:     len(report.Uses),
		Gaps:          len(report.Gaps),
	}
	for _, u := range report.Uses {
		row := baselineUse{ID: u.ID, Kind: u.Kind}
		if trace, err := client.Preview(u); err != nil {
			row.PreviewError = err.Error()
		} else {
			row.RequestSHA256 = sha256Hex(trace.Request)
		}
		if signature, err := client.EquivalenceSignature(u); err != nil {
			row.SignatureError = err.Error()
		} else {
			row.SignatureSHA256 = sha256Hex([]byte(signature))
		}
		out.Uses = append(out.Uses, row)
	}
	reportpkg.Enrich(report)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	out.ReportSHA256 = sha256Hex(encoded)
	sarif, err := json.Marshal(reportpkg.SARIF(report))
	if err != nil {
		t.Fatal(err)
	}
	out.SARIFSHA256 = sha256Hex(sarif)
	return out
}

// firstBaselineDifference names the first differing use ID so a mismatch can be
// localized without storing full reports in the golden.
func firstBaselineDifference(want, got baselineFixture) string {
	for i := 0; i < len(want.Uses) || i < len(got.Uses); i++ {
		switch {
		case i >= len(want.Uses):
			return "first differing use " + got.Uses[i].ID + " (added)"
		case i >= len(got.Uses):
			return "first differing use " + want.Uses[i].ID + " (removed)"
		case want.Uses[i] != got.Uses[i]:
			if want.Uses[i].ID != got.Uses[i].ID {
				return "first differing use " + want.Uses[i].ID + " (now " + got.Uses[i].ID + ")"
			}
			return "first differing use " + got.Uses[i].ID + " (request or signature digest)"
		}
	}
	w, g := want, got
	w.Uses, g.Uses = nil, nil
	return "uses unchanged; report, SARIF or counts differ: want " + baselineSummary(w) + ", got " + baselineSummary(g)
}

func baselineSummary(f baselineFixture) string {
	raw, _ := json.Marshal(f)
	return string(raw)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
