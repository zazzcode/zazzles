package analysispacks

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func nosqlSelectionUse() analysis.CandidateUse {
	return analysis.CandidateUse{Kind: "nosql_query_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: "server.js"}}, APIModel: NoSQLContract("marsdb-collection-v1"), Completeness: &analysis.Completeness{ClaimKind: "injection", Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
}

func validationSelectionUse(file string, claim bool) analysis.CandidateUse {
	u := analysis.CandidateUse{Kind: "input_validation_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}}}
	if claim {
		u.Completeness = &analysis.Completeness{ClaimKind: "validation", Required: []string{"input_source", "field_policy", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"field_policy": {{Kind: "form_field_requirement"}}}}
	}
	return u
}

func TestFamilyComponentSelection(t *testing.T) {
	families := map[string][]string{"sql": nil, "nosql": nil, "validation": nil, "xss": nil, "outbound": nil, "command": nil}
	for _, fam := range Families() {
		if _, ok := families[fam.Name]; !ok {
			t.Fatalf("unexpected family %s", fam.Name)
		}
		families[fam.Name] = fam.QuestionNames
	}
	if !reflect.DeepEqual(families["nosql"], []string{"validation", "protection", "injection_protection", "all_paths_protected", "source_coverage", "library_coverage", "guard_coverage", "path_coverage"}) {
		t.Fatalf("nosql question protocol: %v", families["nosql"])
	}
	if !reflect.DeepEqual(families["validation"], []string{"field_requirement", "validation", "enforcement_coverage"}) {
		t.Fatalf("validation question protocol: %v", families["validation"])
	}
	if !reflect.DeepEqual(families["sql"], []string{"validation", "protection", "injection_protection"}) {
		t.Fatalf("sql question protocol: %v", families["sql"])
	}

	// The three families select independently from their own packs, guidance,
	// contracts and evidence obligations.
	sql, err := Select(selectionUse())
	if err != nil {
		t.Fatal(err)
	}
	nosql, err := Select(nosqlSelectionUse())
	if err != nil {
		t.Fatal(err)
	}
	validation, err := Select(validationSelectionUse("server.ts", false))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		family        string
		selection     *analysis.ComponentSelection
		want, notWant []string
	}{
		{"sql", sql, []string{"pack.sql", "claim.sql", "evidence.sql", "language.javascript", "entry.http", "flow.local", "api.sequelize-raw-query-v1"}, nil},
		{"nosql", nosql, []string{"pack.nosql", "claim.nosql", "evidence.nosql", "language.nosql.javascript", "entry.http", "flow.local", "api.marsdb-collection-v1"}, []string{"language.javascript", "pack.sql", "api.sequelize-raw-query-v1"}},
		{"validation", validation, []string{"pack.validation", "claim.validation", "evidence.validation", "language.validation.javascript", "flow.local"}, []string{"api.", "entry.", "language.javascript"}},
	} {
		ids := []string{}
		for _, ref := range tt.selection.Components {
			ids = append(ids, ref.ID)
		}
		joined := strings.Join(ids, ",")
		for _, want := range tt.want {
			if !strings.Contains(joined, want) {
				t.Fatalf("%s selection missing %s: %v", tt.family, want, ids)
			}
		}
		for _, notWant := range tt.notWant {
			if strings.Contains(joined, notWant) {
				t.Fatalf("%s selection borrowed %s: %v", tt.family, notWant, ids)
			}
		}
		if tt.selection.Digest == "" || tt.selection.Pack.ID != "pack."+tt.family {
			t.Fatalf("%s pack identity: %+v", tt.family, tt.selection.Pack)
		}
	}
	if sql.Digest == nosql.Digest || nosql.Digest == validation.Digest {
		t.Fatal("family selections share digests")
	}
	if !strings.Contains(strings.Join(validation.Required, ","), "field_policy") {
		t.Fatalf("validation obligations lost field policy: %v", validation.Required)
	}
	if !strings.Contains(strings.Join(nosql.Required, ","), "sink_binding") {
		t.Fatalf("nosql obligations lost sink binding: %v", nosql.Required)
	}

	// NoSQL candidates under supported non-HTTP entries select the same
	// family without broadening the adapters behind those entries.
	for _, entry := range []string{"http", "graphql", "grpc"} {
		u := nosqlSelectionUse()
		u.EntryKind = entry
		if _, err := Select(u); err != nil {
			t.Fatalf("nosql entry %s: %v", entry, err)
		}
	}

	// Mongoose query and path-ID contracts are distinct selectable operations.
	for _, id := range []string{"mongoose-model-query-v1", "mongoose-model-query-v2", "mongoose-path-id-objectid-v1"} {
		u := nosqlSelectionUse()
		u.APIModel = NoSQLContract(id)
		if _, err := Select(u); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}

	// Standalone validation needs no API model, claim completeness or entry
	// capability; JS field records and Python policy claims both select.
	for _, u := range []analysis.CandidateUse{validationSelectionUse("server.js", false), validationSelectionUse("app.py", true), validationSelectionUse("route.ts", false)} {
		if _, err := Select(u); err != nil {
			t.Fatalf("api-less validation: %v", err)
		}
	}

	// Invalid or unsupported facts stay explicit failures; none may borrow
	// another family's trusted contract or fall through to generic selection.
	for _, tt := range []struct {
		name string
		use  analysis.CandidateUse
	}{
		{"python nosql", func() analysis.CandidateUse { u := nosqlSelectionUse(); u.Sink.Span.File = "app.py"; return u }()},
		{"nosql without verified api", func() analysis.CandidateUse { u := nosqlSelectionUse(); u.APIModel = nil; return u }()},
		{"nosql with sql contract", func() analysis.CandidateUse {
			u := nosqlSelectionUse()
			u.APIModel = SQLContract("sequelize-raw-query-v1")
			return u
		}()},
		{"nosql mutated contract", func() analysis.CandidateUse {
			u := nosqlSelectionUse()
			c := *u.APIModel
			c.Semantics += " changed"
			u.APIModel = &c
			return u
		}()},
		{"nosql missing binding", func() analysis.CandidateUse {
			u := nosqlSelectionUse()
			u.Completeness.Evidence = map[string][]analysis.Evidence{}
			return u
		}()},
		{"nosql unknown entry", func() analysis.CandidateUse { u := nosqlSelectionUse(); u.EntryKind = "browser"; return u }()},
		{"nosql go source", func() analysis.CandidateUse { u := nosqlSelectionUse(); u.Sink.Span.File = "sink.go"; return u }()},
		{"validation go source", func() analysis.CandidateUse { u := validationSelectionUse("sink.go", false); return u }()},
	} {
		u := tt.use
		Attach(&u)
		if u.Components == nil || u.Components.Failure == "" || len(u.Components.Components) != 0 {
			t.Fatalf("%s: unsupported facts gained selection %+v", tt.name, u.Components)
		}
	}

	// Unregistered kinds keep their existing runtime paths: no selection is
	// attached and none is required for their requests.
	for _, kind := range []string{"xss_data_candidate", "log_sink_candidate"} {
		u := analysis.CandidateUse{Kind: kind, Sink: analysis.Evidence{Span: analysis.Span{File: "server.ts"}}}
		Attach(&u)
		if u.Components != nil {
			t.Fatalf("%s acquired component selection", kind)
		}
		if FamFamily(kind) != nil {
			t.Fatalf("%s registered as component family", kind)
		}
	}
}

func TestFamilyCatalogValidation(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	roots := []string{"pack.sql", "claim.sql", "evidence.sql", "pack.nosql", "claim.nosql", "evidence.nosql", "pack.validation", "claim.validation", "evidence.validation", "language.javascript", "language.python", "language.nosql.javascript", "language.validation.javascript", "language.validation.python", "flow.local", "entry.http", "entry.graphql", "entry.grpc", "api.sequelize-raw-query-v1", "api.python-sqlite3-dbapi-v1", "api.marsdb-collection-v1", "api.mongoose-model-query-v1", "api.mongoose-model-query-v2"}
	for _, missing := range roots {
		t.Run(missing, func(t *testing.T) {
			items, err := descriptors()
			if err != nil {
				t.Fatal(err)
			}
			filtered := items[:0]
			for _, item := range items {
				if item.ID != missing {
					filtered = append(filtered, item)
				}
			}
			if _, err := newCatalog(filtered); err == nil {
				t.Fatal("missing registered family root accepted")
			}
		})
	}
	for _, mutate := range []struct {
		name   string
		change func([]Component) []Component
	}{
		{"unknown protocol", func(c []Component) []Component { c[0].Compatibility = []string{"future-components-v1"}; return c }},
		{"claim question drift", func(c []Component) []Component {
			for i := range c {
				if c[i].ID == "claim.nosql" {
					c[i].Material = strings.Replace(c[i].Material, "all_paths_protected", "renamed_question", 1)
				}
			}
			return c
		}},
		{"claim choice drift", func(c []Component) []Component {
			for i := range c {
				if c[i].ID == "claim.validation" {
					c[i].Material = strings.Replace(c[i].Material, "field_requirement", "renamed_question", 1)
				}
			}
			return c
		}},
		{"guidance family conflict", func(c []Component) []Component {
			for i := range c {
				if c[i].ID == "language.validation.javascript" {
					c[i].Applicability = []string{"python"}
				}
			}
			return c
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			if _, err := newCatalog(mutate.change(catalogItems(t))); err == nil {
				t.Fatal("invalid family registration accepted")
			}
		})
	}
}

// Measured family material stays bounded; new-family payloads are measured in
// the judge payload tests. Fixture measurements, not repository guarantees.
func TestFamilyMaterialSizes(t *testing.T) {
	for _, tt := range []struct {
		name string
		use  analysis.CandidateUse
	}{
		{"nosql", nosqlSelectionUse()},
		{"validation-javascript", validationSelectionUse("server.js", false)},
		{"validation-python", validationSelectionUse("app.py", true)},
	} {
		selected, err := Select(tt.use)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		size, components := 0, 0
		for _, ref := range selected.Components {
			size += len(embedded.components[ref.ID].Material)
			components++
		}
		if size > MaxMaterialBytes {
			t.Fatalf("%s material %d exceeds %d", tt.name, size, MaxMaterialBytes)
		}
		t.Logf("%s selected_material=%d bytes components=%d", tt.name, size, components)
	}
}
