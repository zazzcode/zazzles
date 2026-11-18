package langphp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func phpFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// phpUsesFor analyzes one fixture directory and returns the report.
func phpAnalyze(t *testing.T, root, entry string) *analysis.AnalysisReport {
	t.Helper()
	r, err := Analyze(root, entry)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func phpUsesOfKind(r *analysis.AnalysisReport, kind string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind {
			out = append(out, u)
		}
	}
	return out
}

func TestPHPEntries(t *testing.T) {
	r := phpAnalyze(t, "testdata/routes", "")
	if len(r.Entries) != 2 {
		t.Fatalf("entries: %#v", r.Entries)
	}
	for _, e := range r.Entries {
		if e.Kind != "http" || e.HTTP == nil || e.HTTP.Framework != "php" || e.HTTP.SourcePath == "" {
			t.Fatalf("unexpected entry %#v", e)
		}
	}
	if len(r.InvocationContexts) != 2 || len(r.Registrations) != 2 || len(r.DispatchBindings) != 2 {
		t.Fatalf("entry records incomplete: inv=%d reg=%d dispatch=%d", len(r.InvocationContexts), len(r.Registrations), len(r.DispatchBindings))
	}
}

func TestPHPIncludeDispatch(t *testing.T) {
	r := phpAnalyze(t, "testdata/includes", "index.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) < 2 {
		t.Fatalf("expected dispatch alternatives to reach the render sink, got %#v", r.Uses)
	}
	raw, encoded := false, false
	conditions := 0
	for _, u := range uses {
		switch u.XSS.Protection {
		case "raw":
			raw = true
		case "encoded":
			encoded = true
		}
		for _, e := range u.Context {
			if e.Kind == "dispatch_condition" {
				conditions++
			}
		}
		if u.Sink.Span.File != "index.php" {
			t.Fatalf("sink recorded at wrong file: %s", u.Sink.Span.File)
		}
	}
	if !raw || !encoded {
		t.Fatalf("low must stay raw and impossible must stay encoded: %#v", uses)
	}
	if conditions == 0 {
		t.Fatal("dispatch alternatives carry no selecting condition evidence")
	}
	// The impossible-alternative control never protects the low alternative:
	// verify no use claims whole-entry protection from a sibling condition.
	for _, u := range uses {
		if u.XSS.Protection == "encoded" && strings.Contains(u.XSS.ProtectionReason, "sibling") {
			t.Fatal("borrowed sibling protection")
		}
	}

	dynamic := phpAnalyze(t, "testdata/includes", "dynamic.php")
	gapFound := false
	for _, g := range dynamic.Gaps {
		gapFound = gapFound || g.Kind == "php_dynamic_include"
	}
	for _, e := range dynamic.Entries {
		for _, g := range e.Gaps {
			gapFound = gapFound || g.Kind == "php_dynamic_include"
		}
	}
	if !gapFound {
		t.Fatalf("unresolvable include must record php_dynamic_include: %#v", dynamic.Gaps)
	}
	if len(phpUsesOfKind(dynamic, "sql_query_candidate")) != 0 {
		t.Fatal("dynamic include invented edges")
	}
	pathUses := phpUsesOfKind(dynamic, "path_traversal_candidate")
	if len(pathUses) != 1 || pathUses[0].APIModel.ID != "php-include-v1" {
		t.Fatalf("dynamic include operand must stay a path candidate: %#v", pathUses)
	}
}

func TestSQLPHPContracts(t *testing.T) {
	r := phpAnalyze(t, "testdata/sql", "sqli.php")
	uses := phpUsesOfKind(r, "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("sqli uses: %#v", r.Uses)
	}
	u := uses[0]
	if u.APIModel == nil || u.APIModel.ID != "php-mysqli-v1" {
		t.Fatalf("contract: %#v", u.APIModel)
	}
	binding := false
	for _, e := range u.Context {
		binding = binding || (e.Kind == "sink_binding" && strings.Contains(e.Text, "mysqli_connect"))
	}
	if !binding {
		t.Fatal("connection provenance missing")
	}
	if u.InputFacts == nil || u.InputFacts.Framework != "php" {
		t.Fatalf("input facts: %#v", u.InputFacts)
	}
	if err := u.InputFacts.Validate(u.Dependencies); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range u.InputFacts.Values {
		found = found || v.Origin == "http.query_or_form"
	}
	if !found {
		t.Fatalf("$_REQUEST origin: %#v", u.InputFacts.Values)
	}
	if u.Components == nil || u.Components.Failure != "" || !phpHasComponent(u.Components, "source.php-input-v1") {
		t.Fatalf("selection: %#v", u.Components)
	}

	shadowed := phpAnalyze(t, "testdata/sql", "shadowed.php")
	if len(phpUsesOfKind(shadowed, "sql_query_candidate")) != 0 {
		t.Fatal("shadowed mysqli_query became a sink")
	}

	protected := phpAnalyze(t, "testdata/sql", "protected.php")
	pu := phpUsesOfKind(protected, "sql_query_candidate")
	if len(pu) != 1 || pu[0].APIModel.ID != "php-pdo-v1" {
		t.Fatalf("pdo uses: %#v", protected.Uses)
	}
	bound := false
	for _, e := range pu[0].Context {
		bound = bound || e.Kind == "parameter_binding"
	}
	if !bound {
		t.Fatal("prepare+bindParam binding control missing")
	}

	sqlite := phpAnalyze(t, "testdata/sql", "sqlite.php")
	su := phpUsesOfKind(sqlite, "sql_query_candidate")
	if len(su) != 1 || su[0].APIModel.ID != "php-sqlite3-v1" {
		t.Fatalf("sqlite uses: %#v", sqlite.Uses)
	}
}

func TestCommandPHPOperands(t *testing.T) {
	r := phpAnalyze(t, "testdata/command", "ping.php")
	uses := phpUsesOfKind(r, "command_execution_candidate")
	if len(uses) != 1 {
		t.Fatalf("command uses: %#v", r.Uses)
	}
	u := uses[0]
	if u.Command == nil || u.Command.ContractID != "php-program-execution-v1" || u.Command.EffectiveShellMode != "enabled" {
		t.Fatalf("facts: %#v", u.Command)
	}
	if u.Command.Operands[0].Slot != "shell_command" || !u.Command.Operands[0].Dynamic {
		t.Fatalf("operands: %#v", u.Command.Operands)
	}
	quoted := false
	for _, p := range u.Command.Paths {
		quoted = quoted || p.Protection == "guarded"
	}
	if quoted {
		t.Fatal("ping.php operand must stay raw")
	}

	esc := phpAnalyze(t, "testdata/command", "escaped.php")
	eu := phpUsesOfKind(esc, "command_execution_candidate")
	if len(eu) != 1 {
		t.Fatalf("escaped uses: %#v", esc.Uses)
	}
	if eu[0].Command.Paths[0].Protection != "guarded" {
		t.Fatalf("escapeshellarg control: %#v", eu[0].Command.Paths)
	}
}

func TestPHPXSSReflected(t *testing.T) {
	r := phpAnalyze(t, "testdata/xss", "reflected.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) != 1 || uses[0].XSS.Protection != "raw" || uses[0].XSS.Type != "reflected" {
		t.Fatalf("reflected: %#v", uses)
	}
	if uses[0].XSS.OutputContext != "html_text" || uses[0].XSS.ContentType != "text/html" {
		t.Fatalf("context: %#v", uses[0].XSS)
	}
	if uses[0].APIModel.ID != "php-html-output-v1" {
		t.Fatalf("render contract: %#v", uses[0].APIModel)
	}
	esc := phpAnalyze(t, "testdata/xss", "escaped.php")
	euses := phpUsesOfKind(esc, "xss_candidate")
	if len(euses) != 1 || euses[0].XSS.Protection != "encoded" {
		t.Fatalf("escaped output must not be raw: %#v", euses)
	}
}

func TestPHPXSSStored(t *testing.T) {
	r := phpAnalyze(t, "testdata/xss", "stored.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) == 0 {
		t.Fatal("stored rendering missing")
	}
	stored := false
	for _, u := range uses {
		if u.XSS.Type == "stored" {
			stored = true
			if !strings.HasPrefix(u.XSS.StorageKey, "php-sql:guestbook.") {
				t.Fatalf("storage key: %q", u.XSS.StorageKey)
			}
			if len(u.XSS.RelatedEntries) == 0 {
				t.Fatal("stored write entry not linked")
			}
		}
	}
	if !stored {
		t.Fatalf("no stored claim: %#v", uses)
	}
}

// TestPHPXSSStoredNumericRow covers mysqli_fetch_row access by numeric
// position: the SELECT header resolves the column so the storage key matches
// its INSERT-recorded write.
func TestPHPXSSStoredNumericRow(t *testing.T) {
	r := phpAnalyze(t, "testdata/xss", "stored_row.php")
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		if u.XSS.Type != "stored" {
			continue
		}
		key := u.XSS.StorageKey
		if key != "php-sql:guestbook.name" && key != "php-sql:guestbook.comment" {
			t.Fatalf("storage key: %q", key)
		}
		if !u.XSS.OriginResolved || len(u.XSS.RelatedEntries) == 0 {
			t.Fatalf("stored link unresolved: %#v", u.XSS)
		}
		return
	}
	t.Fatal("no stored claim from numeric row access")
}

func TestPathPHPOperands(t *testing.T) {
	fi := phpAnalyze(t, "testdata/path", "fi.php")
	fiu := phpUsesOfKind(fi, "path_traversal_candidate")
	if len(fiu) != 1 || fiu[0].APIModel.ID != "php-include-v1" {
		t.Fatalf("include candidate: %#v", fiu)
	}
	inclusion := false
	for _, g := range append(append([]analysis.Gap{}, fiu[0].Gaps...), fiu[0].Completeness.Coverage...) {
		inclusion = inclusion || g.Kind == "file_inclusion"
	}
	if !inclusion {
		t.Fatal("file_inclusion fact missing")
	}

	// A terminating !in_array membership rejection guards the fall-through
	// include; an unguarded sibling stays raw.
	aw := phpAnalyze(t, "testdata/path", "allowlist.php")
	awu := phpUsesOfKind(aw, "path_traversal_candidate")
	if len(awu) != 2 {
		t.Fatalf("allowlist candidates: %#v", awu)
	}
	guardCount, rawCount := 0, 0
	for _, u := range awu {
		for _, p := range u.Path.Paths {
			switch p.Protection {
			case "guarded":
				guardCount++
			case "raw":
				rawCount++
			}
		}
	}
	if guardCount != 1 || rawCount != 1 {
		t.Fatalf("allowlist guard: guarded=%d raw=%d %#v", guardCount, rawCount, awu)
	}
	// Include is a file READ with a separate file_inclusion execution-context
	// fact; the shared path facts validate only read/write/delete roles.
	if fiu[0].Path.Role != "read" {
		t.Fatalf("role: %#v", fiu[0].Path)
	}

	fs := phpAnalyze(t, "testdata/path", "fs.php")
	fsu := phpUsesOfKind(fs, "path_traversal_candidate")
	if len(fsu) != 1 || fsu[0].APIModel.ID != "php-filesystem-v1" || fsu[0].Path.Role != "read" {
		t.Fatalf("filesystem candidate: %#v", fsu)
	}

	up := phpAnalyze(t, "testdata/path", "upload.php")
	upu := phpUsesOfKind(up, "path_traversal_candidate")
	if len(upu) != 1 || upu[0].APIModel.ID != "php-upload-move-v1" {
		t.Fatalf("upload candidate: %#v", up.Uses)
	}
	dest := -1
	for i, o := range upu[0].Path.Operands {
		if o.Slot == "destination" {
			dest = i
		}
	}
	if dest < 0 {
		t.Fatalf("destination operand: %#v", upu[0].Path.Operands)
	}
	guarded := false
	for _, flow := range upu[0].Path.Paths {
		if flow.Operand == "destination" && flow.Protection == "guarded" {
			guarded = true
		}
	}
	if !guarded {
		t.Fatalf("basename control must guard the destination: %#v", upu[0].Path.Paths)
	}
}

func TestCodePHPEval(t *testing.T) {
	r := phpAnalyze(t, "testdata/code", "eval.php")
	uses := phpUsesOfKind(r, "code_execution_candidate")
	if len(uses) != 1 {
		t.Fatalf("code uses: %#v", r.Uses)
	}
	u := uses[0]
	if u.Code == nil || u.Code.ContractID != "php-eval-v1" || u.Code.ExecutionContext != "server" || u.Code.Shape != "whole_program" {
		t.Fatalf("code facts: %#v", u.Code)
	}
	if u.APIModel.ID != "php-eval-v1" {
		t.Fatalf("contract: %#v", u.APIModel)
	}
}

// TestCodePHPFileEval covers the DVWA view_help.php shape: eval over a
// file_get_contents return whose path is request-derived — path control is
// content control, so the operand stays tainted through the read.
func TestCodePHPFileEval(t *testing.T) {
	r := phpAnalyze(t, "testdata/code", "file_eval.php")
	uses := phpUsesOfKind(r, "code_execution_candidate")
	if len(uses) != 2 {
		t.Fatalf("code uses: %#v", r.Uses)
	}
	for _, u := range uses {
		if len(u.Dependencies) != 1 {
			t.Fatalf("operand deps: %#v", u.Dependencies)
		}
	}
	// The read stays a path claim alongside the code claim.
	if paths := phpUsesOfKind(r, "path_traversal_candidate"); len(paths) != 2 {
		t.Fatalf("path uses: %#v", paths)
	}
}

func TestCodeRedirectPHP(t *testing.T) {
	r := phpAnalyze(t, "testdata/code", "redirect.php")
	uses := phpUsesOfKind(r, "open_redirect_candidate")
	if len(uses) != 1 {
		t.Fatalf("redirect uses: %#v", r.Uses)
	}
	u := uses[0]
	if u.Redirect == nil || u.Redirect.ContractID != "php-header-redirect-v1" || u.Redirect.Operation != "header" {
		t.Fatalf("redirect facts: %#v", u.Redirect)
	}
	for _, d := range u.Dependencies {
		if d.SinkSlot != "destination" {
			t.Fatalf("slot: %#v", d)
		}
	}
	fixed := phpFixture(t, map[string]string{"fixed.php": "<?php header('Location: /home');"})
	fr := phpAnalyze(t, fixed, "")
	if len(phpUsesOfKind(fr, "open_redirect_candidate")) != 0 {
		t.Fatal("fixed literal redirect produced a claim")
	}
}

func TestPHPInputFacts(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"page.php": "<?php\n$id = $_POST['id'];\n$cmd = shell_exec('echo ' . $id);\n",
	})
	r := phpAnalyze(t, root, "")
	uses := phpUsesOfKind(r, "command_execution_candidate")
	if len(uses) != 1 {
		t.Fatalf("uses: %#v", r.Uses)
	}
	u := uses[0]
	if u.InputFacts == nil {
		t.Fatal("input facts missing")
	}
	if err := u.InputFacts.Validate(u.Dependencies); err != nil {
		t.Fatal(err)
	}
	if u.InputFacts.Acquisition != "http" || u.InputFacts.Framework != "php" || u.InputFacts.Binding.Span.File != "page.php" {
		t.Fatalf("facts: %#v", u.InputFacts)
	}
	if len(u.InputFacts.Values) != 1 || u.InputFacts.Values[0].Origin != "http.form" {
		t.Fatalf("origin: %#v", u.InputFacts.Values)
	}
	body := phpFixture(t, map[string]string{"body.php": "<?php $data = file_get_contents('php://input'); echo $data;"})
	br := phpAnalyze(t, body, "")
	bu := phpUsesOfKind(br, "xss_candidate")
	if len(bu) != 1 || bu[0].InputFacts.Values[0].Origin != "http.body" {
		t.Fatalf("php://input origin: %#v", bu)
	}
}

func phpHasComponent(sel *analysis.ComponentSelection, id string) bool {
	if sel == nil {
		return false
	}
	raw, _ := json.Marshal(sel)
	return strings.Contains(string(raw), "\""+id+"\"")
}

func TestPHPSelectionClosures(t *testing.T) {
	r := phpAnalyze(t, "testdata/sql", "sqli.php")
	for _, u := range r.Uses {
		if u.Components == nil || u.Components.Failure != "" {
			t.Fatalf("PHP candidate selection failed: %s %#v", u.Kind, u.Components)
		}
	}
	nosql := analysis.CandidateUse{Kind: "nosql_query_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: "page.php"}}}
	if _, err := analysispacks.Select(nosql); err == nil {
		t.Fatal("NoSQL selected for PHP")
	}
	ssrf := analysis.CandidateUse{Kind: "ssrf_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: "page.php"}}}
	if _, err := analysispacks.Select(ssrf); err == nil {
		t.Fatal("SSRF selected for PHP")
	}
}
