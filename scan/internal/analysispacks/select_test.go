package analysispacks

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func selectionUse() analysis.CandidateUse {
	return analysis.CandidateUse{Kind: "sql_query_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: "server.ts"}}, APIModel: SQLContract("sequelize-raw-query-v1"), Completeness: &analysis.Completeness{Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
}

func TestSelectionDeterminism(t *testing.T) {
	u := selectionUse()
	first, err := Select(u)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		next, err := Select(u)
		if err != nil || !reflect.DeepEqual(first, next) {
			t.Fatal("unstable selection")
		}
	}
	items, err := descriptors()
	if err != nil {
		t.Fatal(err)
	}
	for i := range items {
		if items[i].ID == "language.javascript" {
			items[i].Material += " "
		}
	}
	changed, err := newCatalog(items)
	if err != nil {
		t.Fatal(err)
	}
	next, err := changed.selectUse(u)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == next.Digest || reflect.DeepEqual(first.Components, next.Components) {
		t.Fatal("changed bytes with unchanged version retained digest")
	}
	items, err = descriptors()
	if err != nil {
		t.Fatal(err)
	}
	for i := range items {
		if items[i].ID == "evidence.sql" {
			items[i].Required = append(items[i].Required, "custom_operand")
		}
	}
	extra, err := newCatalog(items)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := extra.selectUse(u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(selected.Required, ","), "custom_operand") || len(selected.Required) != 5 {
		t.Fatal("additional obligations lost")
	}
}

func TestSQLApplicability(t *testing.T) {
	for _, driver := range []string{"sqlite3", "psycopg", "psycopg2", "pymysql", "mysql.connector"} {
		u := selectionUse()
		u.Sink.Span.File = "app.py"
		u.APIModel = PythonContract(driver)
		s, err := Select(u)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(s.Limits, " "), "version not inferred") {
			t.Fatal("unknown actual library version lost")
		}
	}
	for _, entry := range []string{"http", "graphql", "grpc"} {
		u := selectionUse()
		u.EntryKind = entry
		if _, err := Select(u); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*analysis.CandidateUse){
		func(u *analysis.CandidateUse) { u.APIModel = nil },
		func(u *analysis.CandidateUse) { u.APIModel = &analysis.APIModel{ID: "sequelize-raw-query-v1"} },
		func(u *analysis.CandidateUse) { u.Completeness.Evidence = map[string][]analysis.Evidence{} },
		func(u *analysis.CandidateUse) { u.EntryKind = "unknown" },
		func(u *analysis.CandidateUse) {
			u.EntryKind = "grpc"
			u.Sink.Span.File = "app.py"
			u.APIModel = PythonContract("sqlite3")
		},
		func(u *analysis.CandidateUse) { u.Sink.Span.File = "app.go" },
	} {
		u := selectionUse()
		change(&u)
		Attach(&u)
		if u.Components == nil || u.Components.Failure == "" {
			t.Fatal("unsupported facts acquired component selection")
		}
	}
	items, err := descriptors()
	if err != nil {
		t.Fatal(err)
	}
	for i := range items {
		if items[i].ID == "language.javascript" {
			items[i].Applicability = []string{"python"}
		}
	}
	// Contradictory language applicability is broken embedded configuration;
	// it fails catalog validation before any candidate is selected.
	if _, err := newCatalog(items); err == nil {
		t.Fatal("contradictory descriptor applicability ignored")
	}
}

func TestSQLMaterialAndSelectionLimits(t *testing.T) {
	for _, kind := range []string{"missing", "conflicting", "version", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			items, err := descriptors()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				items = items[1:]
			case "conflicting":
				for i := range items {
					if items[i].ID == "pack.sql" {
						items[i].Dependencies = append(items[i].Dependencies, Requirement{"language.javascript", "5"}, Requirement{"language.python", "3"})
					}
				}
			case "version":
				items[0].Dependencies[0].Version = "999"
			case "oversize":
				for i := range items {
					if items[i].ID == "language.javascript" {
						var g map[string]any
						json.Unmarshal([]byte(items[i].Material), &g)
						g["body"] = strings.Repeat("x", MaxMaterialBytes+1)
						items[i].Material = encoded(g)
					}
				}
			}
			c, err := newCatalog(items)
			if err != nil {
				if kind == "oversize" {
					t.Fatal(err)
				}
				return
			}
			selected, err := c.selectUse(selectionUse())
			if err != nil {
				if kind != "missing" {
					t.Fatal(err)
				}
				return
			}
			if _, err := c.material(FamFamily("sql_query_candidate"), selected); err == nil {
				t.Fatal("invalid/oversized material accepted")
			}
		})
	}
}

func BenchmarkSQLComponentSelection(b *testing.B) {
	u := selectionUse()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Select(u); err != nil {
			b.Fatal(err)
		}
	}
}

func TestComponentContentChangesInvalidateSelection(t *testing.T) {
	original, err := Select(selectionUse())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pack.sql", "language.javascript", "api.sequelize-raw-query-v1", "claim.sql", "evidence.sql"} {
		items, err := descriptors()
		if err != nil {
			t.Fatal(err)
		}
		for i := range items {
			if items[i].ID == id {
				items[i].Limits = append(items[i].Limits, "changed same-version descriptor")
				if items[i].Material != "" {
					items[i].Material += " "
				}
			}
		}
		c, err := newCatalog(items)
		if err != nil {
			t.Fatal(err)
		}
		current, err := c.selectUse(selectionUse())
		if err != nil {
			t.Fatal(err)
		}
		if current.Digest == original.Digest || reflect.DeepEqual(current.Components, original.Components) {
			t.Fatalf("changed same-version %s retained old effective selection", id)
		}
	}
}

func TestSQLMaterialSizes(t *testing.T) {
	for _, source := range []string{"server.js", "server.ts", "app.py"} {
		u := selectionUse()
		u.Sink.Span.File = source
		if source == "app.py" {
			u.APIModel = PythonContract("sqlite3")
		}
		selected, err := Select(u)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		for _, ref := range selected.Components {
			size += len(embedded.components[ref.ID].Material)
		}
		if size > MaxMaterialBytes {
			t.Fatal("baseline SQL material exceeds bound")
		}
		t.Logf("%s selected_material=%d bytes components=%d", source, size, len(selected.Components))
	}
	s, _ := Select(selectionUse())
	s.Components = make([]analysis.ComponentRef, MaxComponents+1)
	if _, err := embedded.material(FamFamily("sql_query_candidate"), s); err == nil {
		t.Fatal("component count limit ignored")
	}
}
