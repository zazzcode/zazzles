package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

type pathMatrixSink struct {
	File string `json:"file"`
	Line int    `json:"line"`
}
type pathMatrixRow struct {
	ID                 string          `json:"id"`
	Target             string          `json:"target"`
	Sink               *pathMatrixSink `json:"sink"`
	Sinks              []any           `json:"sinks"`
	Role               string          `json:"operation_role"`
	ContextCount       int             `json:"context_count"`
	Status             string          `json:"status"`
	AllowUnresolved    bool            `json:"allow_unresolved"`
	RegistrationFile   string          `json:"registration_file"`
	ExceptRegistration string          `json:"except_registration_file"`
}
type pathMatrix struct {
	Targets   map[string]struct{ Revision string } `json:"targets"`
	Positives []pathMatrixRow                      `json:"expected_positives"`
	Protected []pathMatrixRow                      `json:"expected_protected"`
	Unknown   []pathMatrixRow                      `json:"expected_unknown"`
	None      []pathMatrixRow                      `json:"expected_no_candidate"`
}

// TestPathSourceCases checks the independent source-reviewed matrix against the
// actual structural candidates of every pinned target present in the workspace
// (DEV_ROOT, default ~/Dev). Nothing is executed in a target and labels never
// enter scanner input. Targets absent or not at their pin are skipped. Model
// outcomes are asserted by the live evaluation records, not here.
func TestPathSourceCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".zazz", "evaluation", "path-traversal", "matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m pathMatrix
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	devRoot := os.Getenv("DEV_ROOT")
	if devRoot == "" {
		home, _ := os.UserHomeDir()
		devRoot = filepath.Join(home, "Dev")
	}
	reports := map[string]*analysis.AnalysisReport{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for target, info := range m.Targets {
		root := filepath.Join(devRoot, target)
		head, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(head)) != info.Revision {
			t.Logf("skipping %s: not available at pin %s", target, info.Revision)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := Analyze(root, "")
			if err != nil {
				t.Errorf("%s: %v", target, err)
				return
			}
			mu.Lock()
			reports[target] = r
			mu.Unlock()
		}()
	}
	wg.Wait()

	type candidate struct {
		use          analysis.CandidateUse
		registration string
	}
	candidates := func(target string, sink *pathMatrixSink) []candidate {
		r := reports[target]
		registrations := map[string]string{}
		for _, e := range r.Entries {
			registrations[e.ID] = e.Location.Span.File
		}
		var out []candidate
		for _, u := range r.Uses {
			if u.Kind != "path_traversal_candidate" {
				continue
			}
			if sink == nil || (u.Sink.Span.File == sink.File && u.Sink.Span.StartLine == sink.Line) {
				out = append(out, candidate{u, registrations[u.EntryID]})
			}
		}
		return out
	}
	hasUnsafeWitness := func(u analysis.CandidateUse) bool {
		for _, f := range u.Path.Paths {
			if f.Protection == "raw" {
				return true
			}
			if f.Protection == "guarded" && len(f.Controls) > 0 && !f.NormalizedBeforeGuard {
				nonEnforcing := true
				for _, ci := range f.Controls {
					if !analysis.KnownNonEnforcingPathGuard(u.Path.Guards[ci].Kind) {
						nonEnforcing = false
					}
				}
				if nonEnforcing {
					return true
				}
			}
		}
		return false
	}

	// rowSinks lists every sink a row names: the single sink, or the sinks array
	// (objects with file and line, or bare line numbers in the row's file).
	rowSinks := func(row pathMatrixRow) []*pathMatrixSink {
		var out []*pathMatrixSink
		for _, raw := range row.Sinks {
			switch v := raw.(type) {
			case map[string]any:
				out = append(out, &pathMatrixSink{File: v["file"].(string), Line: int(v["line"].(float64))})
			case float64:
				if row.Sink != nil {
					out = append(out, &pathMatrixSink{File: row.Sink.File, Line: int(v)})
				}
			}
		}
		if len(out) == 0 && row.Sink != nil {
			out = append(out, row.Sink)
		}
		return out
	}
	hasFlow := func(u analysis.CandidateUse, protection string) bool {
		for _, f := range u.Path.Paths {
			if f.Protection == protection {
				return true
			}
		}
		return false
	}
	for _, row := range m.Positives {
		if reports[row.Target] == nil {
			continue
		}
		for _, sink := range rowSinks(row) {
			t.Run(fmt.Sprintf("positive/%s/%s:%d", row.ID, sink.File, sink.Line), func(t *testing.T) {
				found := candidates(row.Target, sink)
				if len(found) == 0 || (row.ContextCount > 0 && len(found) != row.ContextCount) {
					t.Fatalf("candidates %d, want %d (contexts)", len(found), max(row.ContextCount, 1))
				}
				for _, c := range found {
					if !hasUnsafeWitness(c.use) || c.use.Path.Role != row.Role {
						t.Fatalf("context %s: want an unsafe %s witness flow, got role %s flows %+v guards %+v", c.registration, row.Role, c.use.Path.Role, c.use.Path.Paths, c.use.Path.Guards)
					}
					if err := c.use.Path.Validate(len(c.use.Dependencies), len(c.use.Context)); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
	for _, row := range m.Protected {
		if reports[row.Target] == nil {
			continue
		}
		for _, sink := range rowSinks(row) {
			t.Run(fmt.Sprintf("protected/%s/%s:%d", row.ID, sink.File, sink.Line), func(t *testing.T) {
				found := candidates(row.Target, sink)
				if len(found) == 0 {
					t.Fatal("a protected control must stay visible as a record")
				}
				for _, c := range found {
					for _, flow := range c.use.Path.Paths {
						enforcing := false
						for _, i := range flow.Controls {
							enforcing = enforcing || analysis.EnforcingPathGuard(c.use.Path.Guards[i].Kind)
						}
						if flow.Protection != "guarded" || !enforcing {
							t.Fatalf("flow lacks an enforcing control: %+v guards %+v", flow, c.use.Path.Guards)
						}
					}
				}
			})
		}
	}
	for _, row := range m.Unknown {
		if reports[row.Target] == nil {
			continue
		}
		t.Run("unknown/"+row.ID, func(t *testing.T) {
			var found []candidate
			for _, sink := range rowSinks(row) {
				found = append(found, candidates(row.Target, sink)...)
			}
			if row.Status == "blocked_unsupported_extraction" {
				// The documented shared-acquisition limit: when it is lifted this row must
				// become an ordinary unresolved record and this assertion must be updated.
				if len(found) != 0 {
					t.Fatalf("blocked row %s now has %d candidates; update the matrix status", row.ID, len(found))
				}
				return
			}
			if len(found) == 0 {
				t.Fatalf("no candidate: an intentionally unknown case must stay visible as a Review record")
			}
			for _, c := range found {
				if row.RegistrationFile != "" && c.registration != row.RegistrationFile {
					t.Fatalf("candidate registered in %s, want only %s", c.registration, row.RegistrationFile)
				}
				if hasFlow(c.use, "raw") {
					t.Fatalf("%s %s: an unknown control must not present a raw witness: %+v", row.ID, c.registration, c.use.Path.Paths)
				}
			}
		})
	}
	for _, row := range m.None {
		if reports[row.Target] == nil {
			continue
		}
		t.Run("none/"+row.ID, func(t *testing.T) {
			for _, c := range candidates(row.Target, row.Sink) {
				switch {
				case row.ExceptRegistration != "" && c.registration == row.ExceptRegistration:
				case row.AllowUnresolved && !hasFlow(c.use, "raw"):
				default:
					t.Fatalf("%s: unexpected candidate (registered in %s) flows %+v", row.ID, c.registration, c.use.Path.Paths)
				}
			}
		})
	}
}
