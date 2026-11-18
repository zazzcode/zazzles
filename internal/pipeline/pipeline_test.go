package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

const (
	jsTestdata    = "../langjs/testdata"
	mixedTestdata = "testdata/mixed"
	pyTestdata    = "../langpy/testdata"
	phpTestdata   = "../langphp/testdata"
)

// fixtures lists the architecture-baseline repositories: every directory under
// the language and mixed testdata trees plus the two top-level JS/TS repositories.
func fixtures(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, tree := range []string{filepath.Join(jsTestdata, "javascript"), filepath.Join(jsTestdata, "typescript"), pyTestdata, phpTestdata, mixedTestdata} {
		entries, err := os.ReadDir(tree)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(tree, e.Name()))
			}
		}
	}
	out = append(out, filepath.Join(jsTestdata, "express-login"), filepath.Join(jsTestdata, "string-flow"))
	sort.Strings(out)
	return out
}

func reportJSON(t *testing.T, root string, opts Options) []byte {
	t.Helper()
	r, err := AnalyzeWithOptions(root, "", nil, opts)
	if err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// AC3: sequential and concurrent runners produce identical reports.
func TestWorkersEquivalence(t *testing.T) {
	for _, root := range fixtures(t) {
		t.Run(strings.TrimPrefix(root, "../"), func(t *testing.T) {
			want := reportJSON(t, root, Options{Workers: 1})
			for i := 0; i < 5; i++ {
				if got := reportJSON(t, root, Options{Workers: 1}); !bytes.Equal(got, want) {
					t.Fatalf("run %d: sequential report changed between runs", i)
				}
				if got := reportJSON(t, root, Options{}); !bytes.Equal(got, want) {
					t.Fatalf("run %d: default-concurrency report differs from Workers: 1", i)
				}
			}
		})
	}
}

// recordingStages wraps production stages, counting walks and recording which
// runners ran.
type recordingStages struct {
	mu    sync.Mutex
	walks int
	ran   map[int]bool
}

func (r *recordingStages) stages() stages {
	st := productionStages()
	walkFn := st.walk
	st.walk = func(root string) (parse.Inventory, error) {
		r.mu.Lock()
		r.walks++
		r.mu.Unlock()
		return walkFn(root)
	}
	for i, run := range st.runners {
		i, run := i, run
		st.runners[i] = func(inv parse.Inventory, entry string, checks []analysis.Check, opts parse.Options) (*analysis.AnalysisReport, error) {
			r.mu.Lock()
			r.ran[i] = true
			r.mu.Unlock()
			return run(inv, entry, checks, opts)
		}
	}
	return st
}

// AC1: a full mixed-language scan walks the target exactly once and runs every
// language, with output identical to the production entry point.
func TestFullScanWalksOnce(t *testing.T) {
	root := filepath.Join(mixedTestdata, "three-language")
	rec := &recordingStages{ran: map[int]bool{}}
	got, err := rec.stages().analyze(root, "", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.walks != 1 {
		t.Fatalf("walks = %d, want 1", rec.walks)
	}
	if !rec.ran[javascriptRunner] || !rec.ran[pythonRunner] || !rec.ran[phpRunner] {
		t.Fatalf("runners = %v, want all three", rec.ran)
	}
	b, _ := json.Marshal(got)
	if want := reportJSON(t, root, Options{}); !bytes.Equal(b, want) {
		t.Fatal("recorded scan differs from AnalyzeWithOptions")
	}
}

// AC2: a Python-only repository never invokes the PHP runner; the JS runner
// only builds the base report (parse tests show it opens no grammar).
func TestPythonOnlyScanSkipsPHP(t *testing.T) {
	root := filepath.Join(pyTestdata, "routes")
	rec := &recordingStages{ran: map[int]bool{}}
	got, err := rec.stages().analyze(root, "", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ran[phpRunner] || !rec.ran[pythonRunner] || !rec.ran[javascriptRunner] {
		t.Fatalf("runners = %v, want javascript (base report) and python only", rec.ran)
	}
	if len(got.Entries) == 0 {
		t.Fatal("expected Python entries")
	}
}

func TestEntryModesSelectOneLanguage(t *testing.T) {
	root := filepath.Join(mixedTestdata, "three-language")
	for entry, want := range map[string]int{"app.py": pythonRunner, "index.php": phpRunner, "server.js": javascriptRunner} {
		rec := &recordingStages{ran: map[int]bool{}}
		if _, err := rec.stages().analyze(root, entry, nil, Options{}); err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		if len(rec.ran) != 1 || !rec.ran[want] {
			t.Fatalf("%s: runners = %v, want only %d", entry, rec.ran, want)
		}
	}
}

// AC4: when Python and PHP both fail and PHP finishes first, Python's error is returned.
func TestEarliestRunnerErrorWins(t *testing.T) {
	pyErr, phpErr := errors.New("python failed"), errors.New("php failed")
	phpDone := make(chan struct{})
	st := productionStages()
	st.walk = func(root string) (parse.Inventory, error) {
		return parse.Inventory{Root: root, Files: nil}, nil
	}
	st.runners[javascriptRunner] = func(parse.Inventory, string, []analysis.Check, parse.Options) (*analysis.AnalysisReport, error) {
		return &analysis.AnalysisReport{}, nil
	}
	st.runners[pythonRunner] = func(parse.Inventory, string, []analysis.Check, parse.Options) (*analysis.AnalysisReport, error) {
		<-phpDone
		return nil, pyErr
	}
	st.runners[phpRunner] = func(parse.Inventory, string, []analysis.Check, parse.Options) (*analysis.AnalysisReport, error) {
		defer close(phpDone)
		return nil, phpErr
	}
	all := [runnerCount]bool{true, true, true}
	for _, workers := range []int{0, 2, 3} {
		if _, err := st.run(parse.Inventory{}, "", nil, Options{Workers: workers}, all); !errors.Is(err, pyErr) {
			t.Fatalf("workers %d: err = %v, want %v", workers, err, pyErr)
		}
		phpDone = make(chan struct{})
	}
}

func BenchmarkPipelineMixed(b *testing.B) {
	root := filepath.Join(mixedTestdata, "three-language")
	for _, bc := range []struct {
		name string
		opts Options
	}{{"sequential", Options{Workers: 1}}, {"default", Options{}}} {
		b.Run(bc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := AnalyzeWithOptions(root, "", nil, bc.opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
