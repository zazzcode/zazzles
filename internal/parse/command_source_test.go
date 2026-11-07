package parse

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

type matrixContext struct {
	Framework        string   `json:"framework"`
	RegistrationFile string   `json:"registration_file"`
	Methods          []string `json:"methods"`
	Registrations    int      `json:"registrations"`
}
type matrixCase struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Sink   struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"sink"`
	Contexts []matrixContext `json:"contexts"`
}
type matrixControl struct {
	ID     string   `json:"id"`
	Target string   `json:"target"`
	Files  []string `json:"files"`
	Sink   *struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"sink"`
}
type matrixFile struct {
	Targets map[string]struct {
		Revision string `json:"revision"`
	} `json:"targets"`
	Cases    []matrixCase    `json:"cases"`
	Controls []matrixControl `json:"negative_controls"`
}

// TestCommandSourceCases checks the independent expected matrix against actual
// source-derived candidates on every pinned target present in the workspace
// (DEV_ROOT, default ~/Dev). No target code is executed and labels never enter
// scanner input. Targets that are absent or not at their pin are skipped.
func TestCommandSourceCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".zazz", "evaluation", "command-injection", "matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m matrixFile
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
	if len(reports) == 0 {
		t.Skip("no pinned acceptance target available")
	}
	claimed := map[string]map[string]bool{}
	for _, c := range m.Cases {
		r := reports[c.Target]
		if r == nil {
			continue
		}
		if claimed[c.Target] == nil {
			claimed[c.Target] = map[string]bool{}
		}
		methods := map[string]string{}
		registration := map[string]string{}
		for _, e := range r.Entries {
			methods[e.ID] = e.HTTPRoute().Method
			registration[e.ID] = e.Location.Span.File
		}
		for _, ctx := range c.Contexts {
			want := ctx.Registrations * len(ctx.Methods)
			found := 0
			for _, u := range commandUses(r) {
				if u.Sink.Span.File != c.Sink.File || u.Sink.Span.StartLine != c.Sink.Line || registration[u.EntryID] != ctx.RegistrationFile {
					continue
				}
				ok := false
				for _, method := range ctx.Methods {
					ok = ok || methods[u.EntryID] == method
				}
				if !ok {
					continue
				}
				found++
				claimed[c.Target][u.ID] = true
				resolved := false
				for _, p := range u.Command.Paths {
					resolved = resolved || p.Protection == "raw" || p.Protection == "guarded"
				}
				if !resolved || u.Components == nil || u.Components.Failure != "" {
					t.Errorf("%s/%s: candidate lacks a resolved path or selection: %+v", c.ID, ctx.Framework, u.Components)
				}
				validCommandFacts(t, u)
			}
			if found != want {
				t.Errorf("%s/%s: %d command contexts, want %d", c.ID, ctx.Framework, found, want)
			}
		}
	}
	for target, r := range reports {
		for _, u := range commandUses(r) {
			if !claimed[target][u.ID] {
				t.Errorf("%s: unexpected command candidate at %s:%d", target, u.Sink.Span.File, u.Sink.Span.StartLine)
			}
		}
	}
	for _, ctrl := range m.Controls {
		r := reports[ctrl.Target]
		if r == nil {
			continue
		}
		for _, u := range commandUses(r) {
			for _, f := range ctrl.Files {
				if u.Sink.Span.File == f {
					t.Errorf("control %s: command candidate in %s", ctrl.ID, f)
				}
			}
			if ctrl.Sink != nil && u.Sink.Span.File == ctrl.Sink.File && u.Sink.Span.StartLine == ctrl.Sink.Line {
				t.Errorf("control %s: constant command became a candidate", ctrl.ID)
			}
		}
	}
}
