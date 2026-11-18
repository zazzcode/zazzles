package langjs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestBrowserEventDispatch(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "events.js", `const input=document.querySelector('input');
 function render(event){document.body.innerHTML=event.target.value;}
 input.addEventListener('input',render);
 input.addEventListener('change',render);`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 2 || len(r.DispatchBindings) != 2 || len(r.InvocationContexts) != 2 {
		t.Fatalf("want two event contexts: entries=%+v bindings=%+v", r.Entries, r.DispatchBindings)
	}
	a, b := r.DispatchBindings[0], r.DispatchBindings[1]
	if a.CallableID == "" || a.CallableID != b.CallableID {
		t.Fatalf("shared callback identity missing: %+v", r.DispatchBindings)
	}
	if len(r.Uses) != 2 || r.Uses[0].InvocationContextID == r.Uses[1].InvocationContextID {
		t.Fatalf("want separate contextual uses: %+v", r.Uses)
	}

	for _, e := range r.Entries {
		if e.HTTP != nil || e.Browser == nil || e.Browser.Category != "event" || e.Browser.Target != "input" {
			t.Fatalf("wrong event: %+v", e)
		}
	}
	for _, c := range r.InvocationContexts {
		if len(c.Inputs) == 0 {
			t.Fatalf("missing event input: %+v", c)
		}
	}
	checkedReport, err := AnalyzeWithChecks(root, "", []analysis.Check{{ID: "input-only", Kind: "xss", Fields: []string{"event.target.value"}, Selector: &analysis.EntrySelector{Kind: "browser", Category: "event", Name: "input on input", Event: "input"}}})
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, u := range checkedReport.Uses {
		if u.Check != nil {
			checked++
			if len(u.Completeness.Evidence["input_source"]) != 1 {
				t.Fatal("checked input binding missing")
			}
			if u.EntryFacts.Browser.Event != "input" {
				t.Fatal("check crossed contexts")
			}
		}
	}
	if checked != 1 {
		t.Fatalf("want one checked context, got %d", checked)
	}
}

func TestBrowserEventProvenance(t *testing.T) {
	for _, tt := range []struct{ name, source, protection, sourceKind, role string }{
		{"input raw", `document.querySelector('input').addEventListener('input',(e)=>{document.body.innerHTML=e.target.value})`, "raw", "browser_event_source", "browser.event.target.value"},
		{"change text", `document.addEventListener('change',(e)=>{document.body.textContent=e.target.value})`, "encoded", "browser_event_source", "browser.event.target.value"},
		{"submit sanitizer", `import DOMPurify from 'dompurify';document.addEventListener('submit',(e)=>{document.body.innerHTML=DOMPurify.sanitize(e.target.value)})`, "sanitized", "browser_event_source", "browser.event.target.value"},
		{"message raw", `window.addEventListener('message',e=>{document.body.innerHTML=e.data})`, "raw", "browser_event_source", "browser.message.data"},
		{"message unknown transform", `window.addEventListener('message',(e)=>{document.body.innerHTML=wrap(e.data)})`, "unknown", "browser_event_source", "browser.message.data"},
		{"message origin check", `window.addEventListener('message',(e)=>{if(e.origin==='https://trusted.test'){document.body.innerHTML=e.data}})`, "raw", "browser_event_source", "browser.message.data"},
		{"click reads location", `document.addEventListener('click',(e)=>{document.body.innerHTML=location.hash})`, "raw", "browser_source", "browser.event.target.value"},
		{"DOM read in event", `const input=document.querySelector('input');document.addEventListener('click',()=>{document.body.innerHTML=input.value})`, "raw", "browser_source", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "events.js", tt.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want %s, got %+v", tt.protection, uses)
			}
			u := uses[0]
			if u.Dependencies[0].Source.Kind != tt.sourceKind {
				t.Fatalf("wrong origin: %+v", u.Dependencies)
			}
			if u.EntryFacts.Browser.Category != "event" || u.DispatchFacts.Resolution != "resolved" {
				t.Fatal("event association missing")
			}
			if tt.role != "" && (len(u.InvocationFacts.Inputs) != 1 || u.InvocationFacts.Inputs[0].Role != tt.role) {
				t.Fatalf("wrong input role: %+v", u.InvocationFacts.Inputs)
			}
			if u.Completeness == nil || len(u.Completeness.Evidence["entry_registration"]) == 0 || len(u.Completeness.Evidence["dispatch_binding"]) == 0 {
				t.Fatal("missing contextual completeness")
			}
			if tt.name == "message origin check" && len(u.InvocationFacts.Controls) == 0 {
				t.Fatal("origin condition was lost")
			}
		})
	}
}

func TestBrowserEventUnknownAndLimits(t *testing.T) {
	for _, tt := range []struct {
		name, source, gap string
		entries           int
	}{
		{"dynamic name", `window.addEventListener(eventName,()=>{})`, "browser_event_name_unresolved", 1},
		{"unsupported name", `window.addEventListener('custom',()=>{})`, "browser_event_name_unresolved", 1},
		{"dynamic target", `getTarget().addEventListener('input',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"fake bus", `const bus={addEventListener(){}};bus.addEventListener('click',()=>{document.body.innerHTML=location.hash})`, "browser_event_receiver_unresolved", 0},
		{"shadowed arrow global", `const setup=window=>window.addEventListener('message',()=>{});`, "browser_event_receiver_unresolved", 0},
		{"fake window", `const window={addEventListener(){}};window.addEventListener('message',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"mutated receiver", `let el=document.body;el={};el.addEventListener('click',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"mutated alias", `const el=document.body;el.addEventListener=custom;const alias=el;alias.addEventListener('click',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"mutated method", `const el=document.body;el.addEventListener=custom;el.addEventListener('click',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"mutated factory", `document.querySelector=custom;document.querySelector('input').addEventListener('input',()=>{})`, "browser_event_receiver_unresolved", 0},
		{"mutated callback", `let fn=(e)=>{};fn=other;window.addEventListener('message',fn)`, "browser_event_callback_unresolved", 1},
		{"uninitialized callback", `let fn;window.addEventListener('message',fn)`, "browser_event_callback_unresolved", 1},
		{"missing callback", `window.addEventListener('message',unknown)`, "browser_event_callback_unresolved", 1},
		{"parameter callback", `function setup(callback){window.addEventListener('message',callback)}`, "browser_event_callback_unresolved", 1},
		{"destructured parameter", `window.addEventListener('message',({data})=>{document.body.innerHTML=data})`, "browser_event_parameter_unresolved", 1},
		{"unsupported projection", `window.addEventListener('message',(e)=>{document.body.innerHTML=e.unknown})`, "browser_event_projection_unresolved", 1},
		{"mutated input", `window.addEventListener('message',(e)=>{e.data='fixed';document.body.innerHTML=e.data})`, "browser_event_input_mutation", 1},
		{"zero use", `window.addEventListener('click',()=>{})`, "", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "events.js", tt.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			events := 0
			gaps := append([]analysis.Gap{}, r.Gaps...)
			for _, e := range r.Entries {
				if e.Browser != nil && e.Browser.Category == "event" {
					events++
				}
			}
			for _, c := range r.InvocationContexts {
				gaps = append(gaps, c.Gaps...)
			}
			if events != tt.entries || tt.gap != "" && !gapKind(gaps, tt.gap) {
				t.Fatalf("entries=%d gaps=%+v", events, gaps)
			}
			for _, b := range r.DispatchBindings {
				if b.Mechanism == "addEventListener" && tt.gap != "" && tt.gap != "browser_event_input_mutation" && tt.gap != "browser_event_projection_unresolved" && b.CallableID != "" {
					t.Fatalf("fabricated callback: %+v", b)
				}
			}
			if tt.name == "zero use" && (len(r.Uses) != 0 || len(r.InvocationContexts) != 1 || r.DispatchBindings[0].Resolution != "resolved") {
				t.Fatal("lost zero-use registration")
			}
		})
	}
	t.Run("mutable closure", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "events.js", `import DOMPurify from 'dompurify';let value=DOMPurify.sanitize(location.hash);window.addEventListener('click',()=>{document.body.innerHTML=value});value=location.hash`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Uses) != 1 || r.Uses[0].XSS.Protection != "unknown" || !gapKind(r.Uses[0].Gaps, "browser_event_closure_mutation") {
			t.Fatalf("stale protection borrowed: %+v", r.Uses)
		}
	})
	t.Run("depth limit", func(t *testing.T) {
		source := ""
		for i := 0; i < 6; i++ {
			source += "window.addEventListener('click',()=>{"
		}
		for i := 0; i < 6; i++ {
			source += "});"
		}
		root := t.TempDir()
		writeSource(t, root, "events.js", source)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range r.InvocationContexts {
			found = found || gapKind(c.Gaps, "browser_event_limit")
		}
		if !found || !gapKind(r.Gaps, "browser_event_unvisited") {
			t.Fatal("depth/unvisited gaps lost")
		}
	})

	t.Run("expansion limit", func(t *testing.T) {
		root := t.TempDir()
		var src strings.Builder
		for i := 0; i < 130; i++ {
			fmt.Fprintf(&src, "window.addEventListener('click',()=>{});\n")
		}
		writeSource(t, root, "events.js", src.String())
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range r.InvocationContexts {
			found = found || gapKind(c.Gaps, "browser_event_limit")
		}
		if !found || len(r.Entries) != 130 {
			t.Fatalf("limit/zero-use entries lost: %d", len(r.Entries))
		}
	})
}

func TestBrowserEventPipeline(t *testing.T) {
	for _, lang := range []string{"javascript", "typescript"} {
		t.Run(lang, func(t *testing.T) {
			root := "testdata/" + lang + "/browser-events"
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 6 || len(r.Uses) != 4 || len(r.Callables) != 4 {
				t.Fatalf("wrong event inventory: entries=%d uses=%d callables=%d", len(r.Entries), len(r.Uses), len(r.Callables))
			}
			protections := map[string]int{}
			contexts := map[string]bool{}
			for _, u := range r.Uses {
				protections[u.XSS.Protection]++
				contexts[u.InvocationContextID] = true
				if u.Completeness == nil || u.EntryFacts.Browser.Category != "event" {
					t.Fatal("missing real event claim")
				}
			}
			if protections["raw"] != 2 || protections["encoded"] != 1 || protections["unknown"] != 1 || len(contexts) != 4 {
				t.Fatalf("protection/context mismatch: %v %v", protections, contexts)
			}
			if err := r.ValidateUses(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("imported helper inventory", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "app.js", `import {setup} from './events.js';document.body.innerHTML=location.hash;setup()`)
		writeSource(t, root, "events.js", `export function setup(){window.addEventListener('message',(e)=>{document.body.innerHTML=e.data})}`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		events, uses := 0, 0
		for _, e := range r.Entries {
			if e.Browser != nil && e.Browser.Category == "event" {
				events++
			}
		}
		for _, u := range r.Uses {
			if u.EntryFacts.Browser != nil && u.EntryFacts.Browser.Category == "event" {
				uses++
			}
		}
		if events != 1 || uses != 1 || !gapKind(r.Gaps, "browser_event_import_context_unresolved") {
			t.Fatalf("duplicate/cross-module binding: %d/%d gaps=%v", events, uses, r.Gaps)
		}
	})

}
