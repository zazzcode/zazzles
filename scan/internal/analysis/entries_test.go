package analysis_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func origin(file string, start int) analysis.Evidence {
	return analysis.Evidence{Kind: "definition", Text: "source is evidence", SHA256: strings.Repeat("a", 64), Span: analysis.Span{File: file, StartLine: 1, EndLine: 2, StartByte: start, EndByte: start + 10}}
}

func modelCatalog() analysis.EntryCatalog {
	site := origin("server.ts", 0)
	body := origin("handler.ts", 20)
	return analysis.EntryCatalog{
		Entries: []analysis.EntryPoint{
			{ID: "entry:guarded", Kind: "http", Name: "POST /guarded", InstanceID: "server:one", Location: site, HTTP: &analysis.HTTPEntryMetadata{Method: "POST", Path: "/guarded"}},
			{ID: "entry:raw", Kind: "graphql", Name: "Mutation.create", InstanceID: "schema:one", Location: site, GraphQL: &analysis.GraphQLEntryMetadata{Type: "Mutation", Field: "create", Operation: "mutation"}},
		},
		Registrations: []analysis.EntryRegistration{
			{ID: "registration:guarded", EntryID: "entry:guarded", Origin: site, Framework: "express"},
			{ID: "registration:raw", EntryID: "entry:raw", Origin: site, Framework: "apollo"},
		},
		Callables: []analysis.Callable{
			{ID: "callable:shared", Name: "create", Language: "typescript", Definition: body},
			{ID: "callable:alternate", Name: "alternate", Language: "typescript", Definition: origin("handler.ts", 40)},
		},
		DispatchBindings: []analysis.DispatchBinding{
			{ID: "dispatch:guarded", EntryID: "entry:guarded", RegistrationID: "registration:guarded", CallableID: "callable:shared", Mechanism: "direct_registration", Resolution: "resolved"},
			{ID: "dispatch:raw", EntryID: "entry:raw", RegistrationID: "registration:raw", CallableID: "callable:shared", Mechanism: "schema_field", Resolution: "resolved", Alternative: "primary"},
			{ID: "dispatch:alternate", EntryID: "entry:raw", RegistrationID: "registration:raw", CallableID: "callable:alternate", Mechanism: "schema_field", Resolution: "resolved", Alternative: "fallback", Conditions: []analysis.Evidence{site}},
			{ID: "dispatch:unknown", EntryID: "entry:raw", RegistrationID: "registration:raw", Mechanism: "schema_field", Resolution: "unresolved", Alternative: "runtime", Gaps: []analysis.Gap{{Kind: "dynamic_target", Detail: "runtime target", At: site.Span}}},
		},
		InvocationContexts: []analysis.InvocationContext{
			{ID: "invocation:guarded", EntryID: "entry:guarded", DispatchBindingID: "dispatch:guarded", Inputs: []analysis.InputBinding{{Role: "http.body", Parameter: "req", Projection: []string{"body", "email"}, Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{site}}}}, Controls: []analysis.ApplicableControl{{InvocationContextID: "invocation:guarded", DispatchBindingID: "dispatch:guarded", Evidence: body}}},
			{ID: "invocation:raw", EntryID: "entry:raw", DispatchBindingID: "dispatch:raw", Inputs: []analysis.InputBinding{{Role: "graphql.args", Parameter: "args", Projection: []string{"email"}, Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{site}}}}},
		},
	}
}

func TestEntryCatalogContexts(t *testing.T) {
	c := modelCatalog()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Callables) != 2 || c.DispatchBindings[0].CallableID != c.DispatchBindings[1].CallableID {
		t.Fatal("shared callable identity lost")
	}
	if len(c.InvocationContexts[0].Controls) != 1 || len(c.InvocationContexts[1].Controls) != 0 {
		t.Fatal("controls crossed contexts")
	}
	if len(c.DispatchBindings) != 4 || c.DispatchBindings[3].CallableID != "" || len(c.DispatchBindings[3].Gaps) != 1 {
		t.Fatal("unknown alternative fabricated a target or lost its gap")
	}
	// Ordered stages and conditional alternatives are independent coordinates.
	c.DispatchBindings[1].Stage = 1
	c.DispatchBindings[2].Stage = 1
	c.DispatchBindings = append(c.DispatchBindings, analysis.DispatchBinding{ID: "dispatch:middleware", EntryID: "entry:raw", RegistrationID: "registration:raw", CallableID: "callable:alternate", Mechanism: "direct_registration", Resolution: "resolved", Stage: 0})
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.DispatchBindings[1].Stage != c.DispatchBindings[2].Stage || c.DispatchBindings[1].Alternative == c.DispatchBindings[2].Alternative {
		t.Fatal("stage order conflated with alternatives")
	}
}

func TestEntryCatalogIdentity(t *testing.T) {
	source := origin("handler.ts", 20)
	id, err := analysis.SnapshotRecordID("callable", source, "module:handler", "scope:create")
	if err != nil {
		t.Fatal(err)
	}
	same := source
	same.Text = "different excerpt/assessment display"
	same.Kind = "invoked_callable"
	got, err := analysis.SnapshotRecordID("callable", same, "module:handler", "scope:create")
	if err != nil || id != got {
		t.Fatal("presentation/evidence-role changes altered lexical identity", err)
	}
	for _, tc := range []struct {
		name, namespace, owner, discriminator string
		source                                analysis.Evidence
	}{
		{"kind", "entry", "module:handler", "scope:create", source},
		{"instance", "callable", "server:two", "scope:create", source},
		{"scope", "callable", "module:handler", "scope:other", source},
		{"file", "callable", "module:handler", "scope:create", origin("other.ts", 20)},
		{"span", "callable", "module:handler", "scope:create", origin("handler.ts", 30)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other, err := analysis.SnapshotRecordID(tc.namespace, tc.source, tc.owner, tc.discriminator)
			if err != nil || id == other {
				t.Fatalf("identity collision: %v", err)
			}
		})
	}
	changed := source
	changed.SHA256 = strings.Repeat("b", 64)
	other, _ := analysis.SnapshotRecordID("callable", changed, "module:handler", "scope:create")
	if id == other {
		t.Fatal("snapshot hash ignored")
	}
	c := modelCatalog()
	c.Gaps = []analysis.Gap{{Kind: "z-gap", At: source.Span}, {Kind: "a-gap", At: source.Span}}
	c.Entries[0].Gaps = append([]analysis.Gap{}, c.Gaps...)
	before, _ := json.Marshal(c)
	a, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// Canonical must not reorder the caller's mutable construction state.
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("canonicalization mutated input")
	}
	reverse(c.Gaps)
	reverse(c.Entries[0].Gaps)
	reverse(c.Entries)
	reverse(c.Registrations)
	reverse(c.DispatchBindings)
	reverse(c.Callables)
	reverse(c.InvocationContexts)
	b, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatal("construction order affected canonical JSON")
	}
	var decoded analysis.EntryCatalog
	if err := json.Unmarshal(aj, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, decoded) {
		t.Fatal("model JSON roundtrip lost evidence or context")
	}
}

func reverse[T any](items []T) {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
}

func TestEntryCatalogValidation(t *testing.T) {
	cases := []struct {
		name, want string
		mutate     func(*analysis.EntryCatalog)
	}{
		{"duplicate", "duplicate", func(c *analysis.EntryCatalog) { c.Entries[1].ID = c.Entries[0].ID }},
		{"registration entry", "entry", func(c *analysis.EntryCatalog) { c.Registrations[0].EntryID = "missing" }},
		{"dispatch registration", "registration", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].RegistrationID = "missing" }},
		{"dispatch entry ownership", "ownership", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].EntryID = "entry:raw" }},
		{"missing callable", "callable", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].CallableID = "missing" }},
		{"unknown target", "unresolved", func(c *analysis.EntryCatalog) { c.DispatchBindings[3].CallableID = "callable:shared" }},
		{"unknown without reason", "gap", func(c *analysis.EntryCatalog) { c.DispatchBindings[3].Gaps = nil }},
		{"resolved without target", "callable", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].CallableID = "" }},
		{"negative stage", "stage", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].Stage = -1 }},
		{"context binding", "dispatch", func(c *analysis.EntryCatalog) { c.InvocationContexts[0].DispatchBindingID = "missing" }},
		{"context entry ownership", "ownership", func(c *analysis.EntryCatalog) { c.InvocationContexts[0].EntryID = "entry:raw" }},
		{"borrowed control", "control", func(c *analysis.EntryCatalog) { c.InvocationContexts[1].Controls = c.InvocationContexts[0].Controls }},
		{"kind metadata", "metadata", func(c *analysis.EntryCatalog) { c.Entries[0].GraphQL = c.Entries[1].GraphQL }},
		{"missing metadata", "metadata", func(c *analysis.EntryCatalog) { c.Entries[0].HTTP = nil }},
		{"missing owner", "instance", func(c *analysis.EntryCatalog) { c.Entries[0].InstanceID = "" }},
		{"source hash", "sha256", func(c *analysis.EntryCatalog) { c.Callables[0].Definition.SHA256 = "not-a-hash" }},
		{"source escape", "relative", func(c *analysis.EntryCatalog) { c.Entries[0].Location.Span.File = "../outside.ts" }},
		{"source span", "span", func(c *analysis.EntryCatalog) { c.Entries[0].Location.Span.EndByte = -1 }},
		{"input origin", "origin", func(c *analysis.EntryCatalog) { c.InvocationContexts[0].Inputs[0].Origin.Kind = "trusted" }},
		{"unsubstantiated input", "evidence", func(c *analysis.EntryCatalog) { c.InvocationContexts[0].Inputs[0].Origin.Evidence = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := modelCatalog()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q rejection, got %v", tc.want, err)
			}
			if _, err := c.Canonical(); err == nil {
				t.Fatal("canonicalized invalid catalog")
			}
		})
	}
	t.Run("unknown zero-use entry", func(t *testing.T) {
		e := origin("events.ts", 0)
		c := analysis.EntryCatalog{Entries: []analysis.EntryPoint{{ID: "entry:future", Kind: "future-event", Name: "unknown event", InstanceID: "events:one", Location: e, UnknownMetadata: json.RawMessage(`{"event":"future"}`), Gaps: []analysis.Gap{{Kind: "unsupported_entry", At: e.Span}}}}}
		out, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(out)
		if !strings.Contains(string(data), "unsupported_entry") || !strings.Contains(string(data), "future-event") {
			t.Fatal("zero-use entry or gap dropped")
		}
	})
	t.Run("typed peer entries", func(t *testing.T) {
		c := modelCatalog()
		e := origin("events.ts", 0)
		c.Entries = append(c.Entries, analysis.EntryPoint{ID: "entry:browser", Kind: "browser", InstanceID: "page:one", Location: e, Browser: &analysis.BrowserEntryMetadata{Category: "event", Event: "input", Target: "document"}}, analysis.EntryPoint{ID: "entry:grpc", Kind: "grpc", InstanceID: "server:grpc", Location: e, GRPC: &analysis.GRPCEntryMetadata{Package: "accounts", Service: "Accounts", Method: "Create"}})
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Entries[2].HTTP != nil || c.Entries[3].HTTP != nil {
			t.Fatal("non-HTTP peers need HTTP metadata")
		}
	})
}

func TestSnapshotRecordIDRejectsInvalidSource(t *testing.T) {
	for _, tc := range []struct {
		name, namespace, owner string
		mutate                 func(*analysis.Evidence)
	}{
		{"namespace", "unknown", "scope", func(*analysis.Evidence) {}},
		{"owner", "entry", "", func(*analysis.Evidence) {}},
		{"absolute path", "entry", "scope", func(e *analysis.Evidence) { e.Span.File = "/tmp/a.ts" }},
		{"backslash", "entry", "scope", func(e *analysis.Evidence) { e.Span.File = `dir\a.ts` }},
		{"hash", "entry", "scope", func(e *analysis.Evidence) { e.SHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := origin("a.ts", 0)
			tc.mutate(&e)
			if _, err := analysis.SnapshotRecordID(tc.namespace, e, tc.owner, ""); err == nil {
				t.Fatal("invalid identity key accepted")
			}
		})
	}
}

func TestEntryCatalogPartialDispatchAndInputOrigins(t *testing.T) {
	c := modelCatalog()
	c.DispatchBindings[0].Resolution = "partial"
	c.DispatchBindings[0].Gaps = []analysis.Gap{{Kind: "unknown_wrapper", At: c.Registrations[0].Origin.Span}}
	// A partial known target and an unknown source remain distinct from a fully
	// resolved binding or a claim that a value is attacker-controlled.
	ctx := &c.InvocationContexts[0]
	ctx.Receiver = &analysis.InputBinding{Role: "receiver", Parameter: "this", Origin: analysis.InputOrigin{Kind: "unknown"}}
	ctx.Closures = []analysis.InputBinding{{Role: "closure", Parameter: "config", Origin: analysis.InputOrigin{Kind: "constant", Evidence: []analysis.Evidence{origin("server.ts", 30)}}}}
	ctx.Inputs = append(ctx.Inputs, analysis.InputBinding{Role: "parent", Parameter: "parent", Origin: analysis.InputOrigin{Kind: "derived", RelatedEntryID: "entry:raw", Evidence: []analysis.Evidence{origin("handler.ts", 60)}}})
	c.Entries[1].Transports = []analysis.TransportAssociation{{Kind: "http", EntryID: "entry:guarded", Evidence: []analysis.Evidence{origin("server.ts", 0)}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		mutate     func(*analysis.EntryCatalog)
	}{
		{"partial without gap", "gap", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].Gaps = nil }},
		{"partial without target", "callable", func(c *analysis.EntryCatalog) { c.DispatchBindings[0].CallableID = "" }},
		{"missing transport", "transport", func(c *analysis.EntryCatalog) { c.Entries[1].Transports[0].EntryID = "missing" }},
		{"wrong transport kind", "transport", func(c *analysis.EntryCatalog) { c.Entries[1].Transports[0].Kind = "grpc" }},
		{"missing transport evidence", "evidence", func(c *analysis.EntryCatalog) { c.Entries[1].Transports[0].Evidence = nil }},
		{"related origin entry", "entry", func(c *analysis.EntryCatalog) { c.InvocationContexts[0].Inputs[1].Origin.RelatedEntryID = "missing" }},
		{"unknown target parameter binding", "parameter", func(c *analysis.EntryCatalog) {
			c.InvocationContexts[0].DispatchBindingID = "dispatch:unknown"
			c.InvocationContexts[0].EntryID = "entry:raw"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Independent decoding prevents fixture mutations from affecting sibling cases.
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var changed analysis.EntryCatalog
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&changed)
			if err := changed.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestEntryCatalogSameDispatchControlIsolation(t *testing.T) {
	c := modelCatalog()
	sibling := c.InvocationContexts[0]
	sibling.ID = "invocation:other-inputs"
	sibling.Inputs = []analysis.InputBinding{{Role: "http.body", Parameter: "req", Origin: analysis.InputOrigin{Kind: "unknown"}}}
	c.InvocationContexts = append(c.InvocationContexts, sibling)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "control ownership") {
		t.Fatalf("borrowed control in same dispatch accepted: %v", err)
	}
	c.InvocationContexts[2].Controls = nil
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
