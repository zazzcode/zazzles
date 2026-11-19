package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestClientResultsHaveSeparateHeadingsAndIdentity(t *testing.T) {
	r := &analysis.AnalysisReport{SchemaVersion: 1,
		Entries: []analysis.EntryPoint{{ID: "client:view", Kind: "browser", Name: "SearchComponent", Browser: &analysis.BrowserEntryMetadata{Category: "component", Framework: "angular"}, Location: analysis.Evidence{Span: analysis.Span{File: "search.component.ts", StartLine: 10}}}},
		Uses:    []analysis.CandidateUse{{ID: "x", EntryID: "client:view", EntryKind: "browser", Kind: "xss_candidate", XSS: &analysis.XSSFacts{Type: "dom", EntryKind: "client", Protection: "raw", OutputContext: "html_text", OriginResolved: true}, Sink: analysis.Evidence{Text: `[innerHTML]="value"`, Span: analysis.Span{File: "search.component.html", StartLine: 5}}, Assessment: analysis.Assessment{Status: "not_run"}}}}
	var html bytes.Buffer
	if err := HTML(&html, r); err != nil {
		t.Fatal(err)
	}
	text := html.String()
	for _, heading := range []string{"Server / API entries", "Browser / client-side", "Component / source", "Source location", "SearchComponent", "search.component.html:5"} {
		if !strings.Contains(text, heading) {
			t.Fatalf("missing %s", heading)
		}
	}
	if !strings.Contains(text, `id="hide-protected"`) || !strings.Contains(text, `data-record-type="finding"`) || !strings.Contains(text, "Showing open Findings and Review items") {
		t.Fatal("remediation filter or record identity missing")
	}
	start := strings.Index(text, `<section id="client-source-rows"`)
	end := strings.Index(text[start:], "</section>") + start
	client := text[start:end]
	for _, routeLabel := range []string{"Route signature", "Route location", "HTTP route", "Route association unavailable"} {
		if strings.Contains(client, routeLabel) {
			t.Fatalf("client results contain API label: %s", routeLabel)
		}
	}
	if r.Findings[0].EntryID != "client:view" {
		t.Fatal("finding manufactured a route identity")
	}
	sarif := SARIF(r)
	run := sarif["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	props := result["properties"].(map[string]any)
	if props["scan.entryId"] != "client:view" || props["scan.route"] != nil {
		t.Fatal("SARIF manufactured a route")
	}
}

func TestBrowserEventPipeline(t *testing.T) {
	for _, lang := range []string{"javascript", "typescript"} {
		t.Run(lang, func(t *testing.T) {
			r, err := pipeline.Analyze(fixtureRoot(lang+"/browser-events"), "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 6 || len(r.Uses) != 4 {
				t.Fatalf("lost parsed controls: %d/%d", len(r.Entries), len(r.Uses))
			}
			dir, err := WriteBundle(t.TempDir(), r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
			if err != nil {
				t.Fatal(err)
			}
			var saved analysis.AnalysisReport
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if err := saved.ValidateUses(); err != nil {
				t.Fatal(err)
			}
			html, err := os.ReadFile(filepath.Join(dir, "findings.html"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(html), "Jinja autoescape") || !strings.Contains(string(html), "textContent") {
				t.Fatal("event report lacks DOM-specific repair guidance")
			}
			statuses := map[string]int{}
			for _, f := range saved.Findings {
				statuses[f.Status]++
				if !strings.Contains(string(html), `data-record-type="`+f.RecordType+`"`) {
					t.Fatalf("HTML lost status %s", f.Status)
				}
			}
			if len(statuses) != 3 {
				t.Fatalf("raw/encoded/unknown status controls lost: %v", statuses)
			}
			run := SARIF(&saved)["runs"].([]any)[0].(map[string]any)
			results := run["results"].([]any)
			if sarifRecords(results) != 4 {
				t.Fatal("zero-use entry became a finding or use was lost")
			}
			shown := []int{}
			for i, f := range saved.Findings {
				if f.GroupedInto == "" {
					shown = append(shown, i)
				}
			}
			for k, item := range results {
				i := shown[k]
				result := item.(map[string]any)
				props := result["properties"].(map[string]any)
				f := props["scan.finding"].(analysis.Finding)
				if f.Status != saved.Findings[i].Status || props["scan.entryId"] != saved.Uses[i].EntryID || props["scan.invocationContextId"] != saved.Uses[i].InvocationContextID || props["scan.route"] != nil {
					t.Fatal("SARIF status/context parity failed")
				}
				if len(result["relatedLocations"].([]any)) < 2 {
					t.Fatal("registration/callback/source witnesses lost")
				}
			}
			for _, e := range saved.Entries {
				if e.HTTP != nil || e.Browser.Category != "event" || !strings.Contains(string(html), e.ID) {
					t.Fatal("event identity/details missing")
				}
			}
			if !strings.Contains(string(html), "browser_event_callback_unresolved") {
				t.Fatal("zero-use gap hidden")
			}
			inv := run["invocations"].([]any)[0].(map[string]any)
			if inv["properties"] == nil || len(inv["toolExecutionNotifications"].([]any)) == 0 {
				t.Fatal("SARIF zero-use coverage missing")
			}
		})
	}
}
