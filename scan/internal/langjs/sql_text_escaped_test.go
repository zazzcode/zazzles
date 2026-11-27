package langjs

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Specification 21 follow-up: a request value escaped (quote doubling) and then
// placed outside quotes (inj) or inside a quoted literal (safe). The records carry
// the placement of each hole; the judge decides what the escape means there.
func TestSQLTextEscapedFixtures(t *testing.T) {
	for dir, want := range map[string]string{
		"inj":  "{1}: outside quotes",
		"safe": "{1}: inside a single-quoted literal",
	} {
		t.Run(dir, func(t *testing.T) {
			uses := sqlTextRecords(t, "testdata/sql-text/escaped/"+dir)
			if len(uses) != 2 {
				t.Fatalf("records %d, want 2 (oracledb, mssql): %v", len(uses), sinks(uses))
			}
			for _, u := range uses {
				if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
					t.Errorf("%s: contract %v", u.Sink.Text, u.APIModel)
				}
				p := u.Completeness.Evidence[parse.SQLTextPlacementKind]
				if len(p) != 1 || p[0].ModelText != want {
					t.Errorf("%s: placement %+v, want %q", u.Sink.Text, p, want)
				}
			}
		})
	}
}

// Specification 21 follow-up: six tagged-template forms in one application. Today
// the hook records every one as sql-text-v1 with the tag as template_tag; the
// definition of a tag function declared in the source is attached as a
// helper_definition, a library tag has none.
func TestSQLTextTagForms(t *testing.T) {
	type form struct {
		tag, placement string
		defined        bool
	}
	want := map[string]form{
		"/library-tag":      {"sql", "{1}: outside quotes", false},
		"/concat-tag":       {"raw", "{1}: inside a single-quoted literal", true},
		"/bound-tag":        {"bound", "{1}: outside quotes", true},
		"/concat-run":       {"run", "{1}: outside quotes", true},
		"/prisma-tag":       {"prisma.$queryRaw", "{1}: outside quotes", false},
		"/template-strings": {"SQL", "{1}: outside quotes", false},
	}
	uses := sqlTextRecords(t, "testdata/sql-text/tags")
	if len(uses) != len(want) {
		t.Fatalf("records %d, want %d: %v", len(uses), len(want), sinks(uses))
	}
	var got []string
	for _, u := range uses {
		if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
			t.Errorf("%s: contract %v", u.Sink.Text, u.APIModel)
		}
		var route string
		for _, e := range u.Context {
			if e.Kind == "route_registration" {
				route = strings.Split(strings.SplitN(e.Text, "'", 3)[1], "'")[0]
			}
		}
		w, ok := want[route]
		if !ok {
			t.Errorf("unexpected record %q at route %q", u.Sink.Text, route)
			continue
		}
		got = append(got, route)
		if tags := u.Completeness.Evidence["template_tag"]; len(tags) != 1 || tags[0].Text != w.tag {
			t.Errorf("%s: template_tag %+v, want %s", route, tags, w.tag)
		}
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(p) != 1 || p[0].ModelText != w.placement {
			t.Errorf("%s: placement %+v, want %q", route, p, w.placement)
		}
		if has := len(contextOf(u, "helper_definition")) > 0; has != w.defined {
			t.Errorf("%s: tag definition attached %v, want %v", route, has, w.defined)
		}
		if w.defined && !holds(u, "server.js", "function "+w.tag+"(") {
			t.Errorf("%s: the definition of %s is not held", route, w.tag)
		}
		if !sinkCovered(u) {
			t.Errorf("%s: sink not covered", route)
		}
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Errorf("routes recorded %v", got)
	}
}
