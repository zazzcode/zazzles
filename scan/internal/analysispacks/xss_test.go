package analysispacks

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func TestXSSComponentSelection(t *testing.T) {
	u := analysis.CandidateUse{Kind: "xss_candidate", EntryKind: "browser", Sink: analysis.Evidence{Span: analysis.Span{File: "page.js"}}, XSS: &analysis.XSSFacts{Type: "dom", EntryKind: "client", OutputContext: "html_text"}, APIModel: XSSContract("browser-output-v1", "")}
	Attach(&u)
	if u.Components == nil || u.Components.Failure != "" {
		t.Fatalf("browser-only selection: %+v", u.Components)
	}
	m, err := ForUse(u)
	if err != nil || len(m.Questions) != 5 {
		t.Fatalf("XSS material: %+v %v", m, err)
	}
}

func TestXSSMaterialBoundsAndConflicts(t *testing.T) {
	items, err := descriptors()
	if err != nil {
		t.Fatal(err)
	}
	u := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "client.js"}}, XSS: &analysis.XSSFacts{Type: "dom"}, APIModel: XSSContract("browser-output-v1", "")}
	c, err := newCatalog(items)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.closure([]string{"render.html-output-v1", "render.browser-output-v1"}); err == nil {
		t.Fatal("competing primary contracts accepted")
	}
	for i, v := range items {
		if v.ID == "context.xss" {
			items[i].Material = strings.Repeat("x", MaxMaterialBytes+1)
		}
	}
	oversized, err := newCatalog(items)
	if err != nil {
		t.Fatal(err)
	}
	s, err := oversized.selectUse(u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = oversized.material(FamFamily(u.Kind), s); err == nil {
		t.Fatal("oversize selected interpretation accepted")
	}
	valid, err := c.selectUse(u)
	if err != nil {
		t.Fatal(err)
	}
	if valid.Digest == s.Digest {
		t.Fatal("changed bytes without version bump retained digest")
	}
	for len(valid.Components) <= MaxComponents {
		valid.Components = append(valid.Components, valid.Components[0])
	}
	if _, err = c.material(FamFamily(u.Kind), valid); err == nil {
		t.Fatal("component count bound lost")
	}
	for _, missing := range []string{"render.browser-output-v1", "protection.xss", "flow.xss"} {
		var filtered []Component
		for _, v := range items {
			if v.ID != missing {
				filtered = append(filtered, v)
			}
		}
		if _, err := newCatalog(filtered); err == nil {
			t.Fatalf("missing %s did not fail configuration", missing)
		}
	}
}

func BenchmarkXSSComponentSelection(b *testing.B) {
	u := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "client.js"}}, XSS: &analysis.XSSFacts{Type: "dom"}, APIModel: XSSContract("browser-output-v1", "")}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Select(u); err != nil {
			b.Fatal(err)
		}
	}
}

func TestXSSMaterialMeasurements(t *testing.T) {
	for _, v := range []struct{ file, id, kind string }{{"app.js", "html-output-v1", "reflected"}, {"view.html", "python-html-output-v1", "stored"}, {"client.ts", "browser-output-v1", "cross_tier"}} {
		u := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: v.file}}, XSS: &analysis.XSSFacts{Type: v.kind}, APIModel: XSSContract(v.id, "")}
		s, err := Select(u)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		for _, ref := range s.Components {
			size += len(embedded.components[ref.ID].Material)
		}
		if size > MaxMaterialBytes {
			t.Fatal("material exceeds bound")
		}
		t.Logf("%s components=%d selected_material_bytes=%d", v.kind, len(s.Components), size)
	}
}

// TestXSSFetchResponseContract keeps the Express html-output-v1 contract and its
// descriptor material unchanged while a web Response binding selects the same
// rendering component with its own library and reference.
func TestXSSFetchResponseContract(t *testing.T) {
	express, fetch := XSSContract("html-output-v1", "express"), XSSContract("html-output-v1", FetchResponseLibrary)
	if express.Library != "express" || XSSContract("html-output-v1", "").Library != "express" {
		t.Fatalf("express contract changed: %+v", express)
	}
	if fetch.ID != "html-output-v1" || fetch.Library != FetchResponseLibrary || !strings.Contains(fetch.Reference, "Response") {
		t.Fatalf("fetch response contract: %+v", fetch)
	}
	u := analysis.CandidateUse{Kind: "xss_candidate", EntryKind: "http", Sink: analysis.Evidence{Kind: "html_response", Span: analysis.Span{File: "app/api/x/route.ts"}}, XSS: &analysis.XSSFacts{Type: "reflected", EntryKind: "server", OutputContext: "html_text"}, APIModel: fetch}
	Attach(&u)
	if u.Components == nil || u.Components.Failure != "" {
		t.Fatalf("fetch response selection: %+v", u.Components)
	}
}

// TestXSSChoiceLabels (judge-request-size-reduction D-5): every XSS choice
// carries a short non-empty label instead of the boilerplate sentence; the
// values are unchanged and the protocol is xss-components-v4.
func TestXSSChoiceLabels(t *testing.T) {
	values := map[string][]string{
		"output_context":          {"html_text", "html_attribute", "url", "script", "style", "unquoted_attribute", "active_attribute", "html_tag", "template_code", "unknown"},
		"encoding_adequacy":       {"adequate", "inadequate", "not_present", "unknown"},
		"sanitizer_effectiveness": {"effective", "ineffective", "absent", "unknown"},
		"xss_all_paths_protected": {"yes", "no", "unknown"},
		"xss_exposure":            {"vulnerable", "protected", "unknown", "not_applicable"},
	}
	for _, q := range XSSQuestions() {
		choices := XSSChoices(q.Name)
		if len(choices) != len(values[q.Name]) {
			t.Fatalf("%s: %d choices", q.Name, len(choices))
		}
		for i, c := range choices {
			if c["value"] != values[q.Name][i] {
				t.Errorf("%s: choice %d value %q, want %q", q.Name, i, c["value"], values[q.Name][i])
			}
			if d := c["description"]; d == "" || strings.Contains(d, "Apply the definition of") {
				t.Errorf("%s/%s: description %q", q.Name, c["value"], d)
			}
			if c["description"] != strings.ReplaceAll(c["value"], "_", " ") {
				t.Errorf("%s/%s: label %q", q.Name, c["value"], c["description"])
			}
		}
	}
	if XSSProtocol != "xss-components-v4" {
		t.Errorf("XSSProtocol = %s", XSSProtocol)
	}
}
