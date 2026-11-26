package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func identityID(kind, digit string) string {
	return kind + ":v1:" + strings.Repeat(digit, 64)
}

// identityUse is a small XSS record whose entry identifier recurs (the
// invocation and its transport) and whose related entries are partly named
// again by a path.
func identityUse() analysis.CandidateUse {
	ev := func(kind, text string, line int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: text, SHA256: strings.Repeat("c", 64), Span: analysis.Span{File: "app.js", StartLine: line, EndLine: line, StartByte: line * 10, EndByte: line*10 + len(text)}}
	}
	entry, writer, other := identityID("entry", "a"), identityID("entry", "b"), identityID("entry", "d")
	sink := ev("render", "res.send(html)", 3)
	u := analysis.CandidateUse{
		ID: identityID("candidate", "e"), Kind: "xss_candidate", EntryID: entry, InvocationContextID: identityID("invocation", "f"), EntryKind: "http",
		Sink:         sink,
		Context:      []analysis.Evidence{ev("handler", "const token = '"+strings.Repeat("9", 64)+"'", 2)},
		EntryFacts:   &analysis.EntryPoint{InstanceID: "express:app.js:server", Location: ev("route_registration", "app.get('/x', h)", 1), Transports: []analysis.TransportAssociation{{Kind: "http", EntryID: entry}}},
		Dependencies: []analysis.Dependency{{Source: ev("input_source", "req.query.q", 2), Transfers: []analysis.Evidence{ev("assignment", "html = q", 2)}}},
		XSS:          &analysis.XSSFacts{Type: "reflected", RelatedEntries: []string{writer, other, entry}, Paths: []analysis.XSSPath{{Dependency: 0, Entry: writer, Protection: "unknown"}}},
		APIModel:     analysispacks.XSSContract("html-output-v1", "express"),
	}
	u.Components, _ = analysispacks.Select(u)
	return u
}

func sentUse(t *testing.T, u analysis.CandidateUse) map[string]any {
	t.Helper()
	c, _ := New("openai", "fixture-model", "offline")
	payload, err := c.payloadForm(u, true)
	if err != nil {
		t.Fatal(err)
	}
	use, err := requestUse(payload)
	if err != nil {
		t.Fatal(err)
	}
	return use
}

func TestWireIdentitySingleOccurrenceIsAbsent(t *testing.T) {
	u := identityUse()
	use := sentUse(t, u)
	raw, _ := json.Marshal(use)
	for _, id := range []string{u.ID, u.InvocationContextID, identityID("entry", "d"), "express:app.js:server"} {
		if strings.Contains(string(raw), id) {
			t.Fatalf("single-occurrence identifier %s was sent", id)
		}
	}
	if _, ok := use["candidate_id"]; ok {
		t.Fatal("candidate_id key kept without its value")
	}
	invocation := use["invocation"].(map[string]any)
	for _, key := range []string{"invocation_context_id", "instance_id"} {
		if _, ok := invocation[key]; ok {
			t.Fatalf("invocation.%s kept", key)
		}
	}
}

func TestWireIdentityRecurringAliases(t *testing.T) {
	use := sentUse(t, identityUse())
	invocation := use["invocation"].(map[string]any)
	entry, _ := invocation["entry_id"].(string)
	transport := invocation["transports"].([]any)[0].(map[string]any)
	xss := use["xss"].(map[string]any)
	path := xss["paths"].([]any)[0].(map[string]any)
	writer, _ := path["entry"].(string)
	alias := regexp.MustCompile(`^i[0-9]+$`)
	if !alias.MatchString(entry) || !alias.MatchString(writer) {
		t.Fatalf("recurring identifiers not aliased: entry %q writer %q", entry, writer)
	}
	if transport["entry_id"] != entry {
		t.Fatalf("one identifier, two aliases: %v vs %q", transport["entry_id"], entry)
	}
	if entry == writer {
		t.Fatal("distinct identifiers share an alias")
	}
	related := xss["related_entries"].([]any)
	if xss["related_entry_count"] != float64(3) || !reflect.DeepEqual(related, []any{writer, entry}) {
		t.Fatalf("related entries: count %v list %v (writer %s entry %s)", xss["related_entry_count"], related, writer, entry)
	}
}

func TestWireIdentityAliasOrderIsFirstOccurrence(t *testing.T) {
	in := map[string]any{"b": []any{identityID("x", "2"), identityID("x", "1")}, "a": map[string]any{"z": identityID("x", "1"), "y": identityID("x", "2")}}
	out := localIdentity(in)
	raw, _ := json.Marshal(out)
	if string(raw) != `{"a":{"y":"i0","z":"i1"},"b":["i0","i1"],"b_count":2}` {
		t.Fatalf("alias order: %s", raw)
	}
	for i := 0; i < 20; i++ {
		again, _ := json.Marshal(localIdentity(map[string]any{"b": []any{identityID("x", "2"), identityID("x", "1")}, "a": map[string]any{"z": identityID("x", "1"), "y": identityID("x", "2")}}))
		if string(again) != string(raw) {
			t.Fatal("alias numbering is not deterministic")
		}
	}
}

func TestWireIdentityKeepsCanonicalUse(t *testing.T) {
	u := identityUse()
	snapshot := func() string {
		raw, _ := json.Marshal([]any{u, u.EntryFacts, u.XSS})
		return string(raw)
	}
	before := snapshot()
	_ = sentUse(t, u)
	c, _ := New("openai", "fixture-model", "offline")
	if _, err := c.EquivalenceSignature(u); err != nil {
		t.Fatal(err)
	}
	if before != snapshot() {
		t.Fatal("projection mutated the CandidateUse")
	}
}

func TestWireIdentityKeepsSourceHashLiteral(t *testing.T) {
	use := sentUse(t, identityUse())
	literal := "const token = '" + strings.Repeat("9", 64) + "'"
	raw, _ := json.Marshal(use["source_excerpts"])
	evidence, _ := json.Marshal(use["evidence"])
	if !strings.Contains(string(raw)+string(evidence), literal) {
		t.Fatalf("source hash literal changed: %s %s", raw, evidence)
	}
}

// TestWireIdentityRelatedEntryClasses: records that differ only in which
// entries are related, with the same count, share one equivalence class.
func TestWireIdentityRelatedEntryClasses(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	a, b := identityUse(), identityUse()
	b.XSS = &analysis.XSSFacts{Type: a.XSS.Type, RelatedEntries: []string{identityID("entry", "b"), identityID("entry", "7"), identityID("entry", "a")}, Paths: a.XSS.Paths}
	sa, err := c.EquivalenceSignature(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := c.EquivalenceSignature(b)
	if sa != sb {
		t.Fatal("related entries of one count split the class")
	}
	b.XSS.RelatedEntries = b.XSS.RelatedEntries[:2]
	if sc, _ := c.EquivalenceSignature(b); sc == sa {
		t.Fatal("a different related-entry count merged the class")
	}
}

// An XSS path may refer to the current entry or to another transport entry.
// A scheduler member may reuse the leader only if those links agree.
func TestWireIdentitySignsPathEntryRelationships(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	signature := func(entry, other, path string) string {
		u := identityUse()
		u.EntryID = entry
		u.EntryFacts.Transports = []analysis.TransportAssociation{
			{Kind: "http", EntryID: entry},
			{Kind: "graphql", EntryID: other},
		}
		u.XSS.RelatedEntries = nil
		u.XSS.Paths[0].Entry = path
		sig, err := c.EquivalenceSignature(u)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	a, b := identityID("entry", "a"), identityID("entry", "b")
	if signature(a, b, a) == signature(a, b, b) {
		t.Fatal("different path-to-transport relationships share a signature")
	}
	if signature(a, b, a) != signature(b, a, b) {
		t.Fatal("renaming the entries split the equivalence class")
	}
}

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

// TestWireIdentityNoHashesInFixtureRequests sweeps every judge fixture use:
// outside source excerpt and evidence text no request carries a 64-hex run.
func TestWireIdentityNoHashesInFixtureRequests(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	n := 0
	for _, fu := range judgeFixtureUses(t) {
		if !AssessableUse(fu.use) {
			continue
		}
		trace, err := c.Preview(fu.use)
		if err != nil {
			continue
		}
		requests := [][]byte{trace.Request}
		for _, g := range trace.Groups {
			requests = append(requests, g.Request)
		}
		for _, req := range requests {
			n++
			if hit := hashOutsideSource(t, req); hit != "" {
				t.Errorf("%s %s:%d: request carries %q", fu.fixture, fu.use.Kind, fu.use.Sink.Span.StartLine, hit)
			}
		}
	}
	if n == 0 {
		t.Fatal("no fixture request built")
	}
	t.Logf("%d fixture requests checked", n)
}

func hashOutsideSource(t *testing.T, payload []byte) string {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal([]byte(envelope["input"].(string)), &input); err != nil {
		t.Fatal(err)
	}
	if use, ok := input["use"].(map[string]any); ok {
		delete(use, "source_excerpts")
		delete(use, "evidence")
	} else {
		// A query-language request (document operation, SQL text) holds the call
		// and source as text and no use bundle.
		for _, k := range []string{"source", "call", "receiver_path"} {
			delete(input, k)
		}
	}
	envelope["input"] = input
	raw, _ := json.Marshal(envelope)
	if m := hex64.FindIndex(raw); m != nil {
		lo := max(m[0]-60, 0)
		return string(raw[lo:m[1]])
	}
	return ""
}

type fixtureUse struct {
	fixture string
	use     analysis.CandidateUse
}

var (
	fixtureUsesOnce sync.Once
	fixtureUses     []fixtureUse
	fixtureUsesErr  error
)

// judgeFixtureUses analyzes every fixture repository the judge tests draw on
// once per test binary: the JS/TS, Python, PHP and mixed testdata trees.
func judgeFixtureUses(t *testing.T) []fixtureUse {
	t.Helper()
	fixtureUsesOnce.Do(func() {
		var roots []string
		for _, pattern := range []string{"../langjs/testdata/javascript/*", "../langjs/testdata/typescript/*", "../langjs/testdata/express-login", "../langjs/testdata/string-flow", "../langpy/testdata/*", "../langphp/testdata/*", "../pipeline/testdata/mixed/*"} {
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				if info, err := os.Stat(m); err == nil && info.IsDir() {
					roots = append(roots, m)
				}
			}
		}
		sort.Strings(roots)
		for _, root := range roots {
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				continue // a fixture of one adapter's error paths
			}
			for _, u := range r.Uses {
				fixtureUses = append(fixtureUses, fixtureUse{root, u})
			}
		}
		if len(fixtureUses) == 0 {
			fixtureUsesErr = os.ErrNotExist
		}
	})
	if fixtureUsesErr != nil {
		t.Fatal("no judge fixture uses found")
	}
	return fixtureUses
}
