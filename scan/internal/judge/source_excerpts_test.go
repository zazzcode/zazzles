package judge

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSharedSourceExcerptsPreserveEveryWitness(t *testing.T) {
	source := "alpha\nbeta\ngamma\n"
	evidence := func(kind string, start, end int, hash string) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: source[start:end], SHA256: hash, Span: analysis.Span{File: "source.py", StartByte: start, EndByte: end, StartLine: 1, EndLine: 3}}
	}
	table := []analysis.Evidence{evidence("handler", 0, len(source), "snapshot"), evidence("invoked_callable", 0, len(source), "snapshot"), evidence("control_statement", 6, 11, "snapshot"), evidence("operation", 11, len(source), "snapshot"), evidence("other_snapshot", 0, len(source), "different")}
	table = append(table, analysis.Evidence{Kind: "derived_label", Text: "field", SHA256: "snapshot", Span: table[0].Span})
	original := append([]analysis.Evidence{}, table...)
	records, excerpts := sharedSourceExcerpts(table)
	if len(records) != len(table) || len(excerpts) != 2 {
		t.Fatalf("records/excerpts=%d/%d", len(records), len(excerpts))
	}
	for i, record := range records {
		e := record.Evidence
		if record.TextRef != "" {
			j, err := strconv.Atoi(strings.TrimPrefix(record.TextRef, "s"))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := excerpts[j]
			if e.SHA256 != snapshot.SHA256 || e.Span.File != snapshot.Span.File {
				t.Fatal("mixed snapshots")
			}
			e.Text = snapshot.Text[e.Span.StartByte-snapshot.Span.StartByte : e.Span.EndByte-snapshot.Span.StartByte]
		}
		if e != table[i] {
			t.Fatalf("lost role/span/hash/text at %d", i)
		}
	}
	if !reflect.DeepEqual(original, table) {
		t.Fatal("canonical evidence was modified")
	}
	again, againExcerpts := sharedSourceExcerpts(table)
	if !reflect.DeepEqual(records, again) || !reflect.DeepEqual(excerpts, againExcerpts) {
		t.Fatal("wire excerpts are nondeterministic")
	}
}
