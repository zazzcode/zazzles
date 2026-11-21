package analysispacks

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func catalogItems(t *testing.T) []Component {
	t.Helper()
	items, err := descriptors()
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestCatalogValidation(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name   string
		change func([]Component) []Component
	}{
		{"duplicate", func(c []Component) []Component { return append(c, c[0]) }},
		{"missing dependency", func(c []Component) []Component {
			c[0].Dependencies = []Requirement{{ID: "missing", Version: "1"}}
			return c
		}},
		{"dependency cycle", func(c []Component) []Component {
			c[0].Dependencies = []Requirement{{ID: c[0].ID, Version: c[0].Version}}
			return c
		}},
		{"unknown protocol", func(c []Component) []Component {
			c[0].Compatibility = []string{"future-components-v1"}
			return c
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			if _, err := newCatalog(mutate.change(catalogItems(t))); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestCatalogMissingSelectorRoots(t *testing.T) {
	for _, missing := range []string{"pack.sql", "language.javascript", "language.python", "entry.http", "entry.graphql", "entry.grpc", "api.sequelize-raw-query-v1", "api.python-sqlite3-dbapi-v1", "api.python-psycopg-dbapi-v1", "api.python-psycopg2-dbapi-v1", "api.python-pymysql-dbapi-v1", "api.python-mysql.connector-dbapi-v1", "pack.nosql", "claim.nosql", "evidence.nosql", "language.nosql.javascript", "api.marsdb-collection-v1", "api.mongoose-model-query-v1", "api.mongoose-model-query-v2", "pack.validation", "claim.validation", "evidence.validation", "language.validation.javascript", "language.validation.python"} {
		t.Run(missing, func(t *testing.T) {
			items := catalogItems(t)
			filtered := items[:0]
			for _, item := range items {
				if item.ID != missing {
					filtered = append(filtered, item)
				}
			}
			if _, err := newCatalog(filtered); err == nil {
				t.Fatal("missing selector root accepted as valid embedded configuration")
			}
		})
	}
}

func TestOutboundCatalogValidation(t *testing.T) {
	f := FamFamily("outbound_http_candidate")
	for _, missing := range f.rootIDs() {
		items := catalogItems(t)
		filtered := []Component{}
		for _, v := range items {
			if v.ID != missing {
				filtered = append(filtered, v)
			}
		}
		if _, err := newCatalog(filtered); err == nil {
			t.Fatalf("missing %s accepted", missing)
		}
	}
	items := catalogItems(t)
	for i := range items {
		if items[i].ID == f.Claim {
			items[i].Kind = "claim_questions"
		}
	}
	if _, err := newCatalog(items); err == nil {
		t.Fatal("observation questionnaire accepted")
	}
}

func TestOutboundMaterialBounds(t *testing.T) {
	for _, bad := range []string{"", "{", `{"id":"trusted-js-fetch"}`} {
		items := catalogItems(t)
		for i := range items {
			if items[i].ID == "api.python-http-destination-v1" {
				items[i].Material = bad
			}
		}
		if _, err := newCatalog(items); err == nil {
			t.Fatal("malformed destination contract accepted")
		}
	}
	items := catalogItems(t)
	for i := range items {
		if items[i].ID == "observation.outbound" {
			items[i].Material = strings.Repeat("x", MaxMaterialBytes+1)
		}
	}
	c, err := newCatalog(items)
	if err != nil {
		t.Fatal(err)
	}
	u := analysis.CandidateUse{Kind: "outbound_http_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "server.js"}}}
	s, err := c.selectUse(u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.material(FamFamily(u.Kind), s); err == nil {
		t.Fatal("oversized observation material accepted")
	}
	for _, file := range []string{"server.js", "app.py"} {
		u.Sink.Span.File = file
		if file == "app.py" {
			u.APIModel = OutboundContract("requests")
			u.Context = []analysis.Evidence{{Kind: "sink_binding"}}
		}
		s, err := Select(u)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		for _, ref := range s.Components {
			size += len(embedded.components[ref.ID].Material)
		}
		t.Logf("%s observation components=%d material=%d request=0", file, len(s.Components), size)
	}
}

func BenchmarkOutboundComponentSelection(b *testing.B) {
	u := analysis.CandidateUse{Kind: "outbound_http_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "server.js"}}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Select(u); err != nil {
			b.Fatal(err)
		}
	}
}
