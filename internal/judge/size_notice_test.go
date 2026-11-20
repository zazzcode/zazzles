package judge

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// TestSizeNotices (D-4) builds a record with 43 omissions and a group with
// 17 withheld paths, the sizes DVWA reached. Each notice states counts by
// kind and by file, keeps its closing sentence and stays under 700 bytes; the
// assessment still lists every omission.
func TestSizeNotices(t *testing.T) {
	t.Run("omissions", func(t *testing.T) {
		u := identityUse()
		files := []string{"lib/a.js", "lib/b.js", "lib/c.js"}
		for i := 0; i < 43; i++ {
			file := files[i%3]
			kind := "helper_definition"
			if i%4 == 0 {
				kind = "middleware_handler"
			}
			text := fmt.Sprintf("function h%d(v) { return String(v).split(',').map((p) => p.length * %d).join('-') }", i, i)
			line := 10 + i*3
			u.Context = append(u.Context, analysis.Evidence{Kind: kind, Text: text, Span: analysis.Span{File: file, StartLine: line, EndLine: line + 1, StartByte: line * 200, EndByte: line*200 + len(text)}})
		}
		c := offlineClient(t)
		reduced, omitted := budgetUse(u, func(r analysis.CandidateUse) bool { return len(r.Context) <= len(u.Context)-43 })
		if len(omitted) != 43 {
			t.Fatalf("fixture shed %d items", len(omitted))
		}
		fits, err := c.payloadForm(reduced, true)
		if err != nil {
			t.Fatal(err)
		}
		withRequestLimit(t, len(fits))
		a := c.Assess(context.Background(), u)
		if len(a.EvidenceOmissions) != 43 {
			t.Fatalf("assessment lists %d omissions, want 43 (%s)", len(a.EvidenceOmissions), a.Reason)
		}
		var gap *analysis.Gap
		for i, g := range reduced.Gaps {
			if g.Kind == "evidence_omitted_for_size" {
				gap = &reduced.Gaps[i]
			}
		}
		if gap == nil {
			t.Fatal("no omission notice")
		}
		kinds := map[string]int{}
		perFile := map[string][3]int{}
		for _, o := range omitted {
			kinds[o.Kind]++
			f := perFile[o.Span.File]
			if f[2] == 0 || o.Span.StartLine < f[0] {
				f[0] = o.Span.StartLine
			}
			f[1] = max(f[1], o.Span.EndLine)
			f[2]++
			perFile[o.Span.File] = f
		}
		want := []string{"43 context evidence item(s)", "Do not treat omitted context as absent protection or absent risk."}
		for k, n := range kinds {
			want = append(want, fmt.Sprintf("%s x%d", k, n))
		}
		for file, f := range perFile {
			want = append(want, fmt.Sprintf("%s: %d-%d (%d)", file, f[0], f[1], f[2]))
		}
		for _, w := range want {
			if !strings.Contains(gap.Detail, w) {
				t.Errorf("notice lacks %q: %s", w, gap.Detail)
			}
		}
		if !strings.HasSuffix(gap.Detail, "Do not treat omitted context as absent protection or absent risk.") {
			t.Error("closing sentence is not last")
		}
		if len(gap.Detail) >= 700 {
			t.Errorf("omission notice is %d bytes: %s", len(gap.Detail), gap.Detail)
		}
	})
	t.Run("path group", func(t *testing.T) {
		u := identityUse()
		u.Completeness = &analysis.Completeness{Evidence: map[string][]analysis.Evidence{}}
		u.Dependencies = nil
		files := map[int]string{0: "src/low.php", 1: "src/medium.php", 2: "src/high.php", 3: "src/impossible.php"}
		for i := 0; i < 20; i++ {
			file := files[i%4]
			text := fmt.Sprintf("$_GET['v%d']", i)
			u.Dependencies = append(u.Dependencies, analysis.Dependency{Source: analysis.Evidence{Kind: "input_source", Text: text, Span: analysis.Span{File: file, StartLine: 5 + i, EndLine: 5 + i, StartByte: i * 50, EndByte: i*50 + len(text)}}})
		}
		g := pathGroup{key: "src/low.php", deps: []int{0, 4, 8}}
		out := groupUse(u, g, nil)
		var gap *analysis.Gap
		for i, c := range out.Completeness.Coverage {
			if c.Kind == "path_group_omitted" {
				gap = &out.Completeness.Coverage[i]
			}
		}
		if gap == nil {
			t.Fatal("no path-group notice")
		}
		withheld := map[string]int{}
		for i, d := range u.Dependencies {
			if i%4 != 0 || i > 8 {
				withheld[d.Source.Span.File]++
			}
		}
		want := []string{"src/low.php", "3 of the record's 20 dependency paths", "17 paths", "Judge only the supplied paths; a withheld path is neither absent nor protected."}
		for file, n := range withheld {
			want = append(want, fmt.Sprintf("%s (%d)", file, n))
		}
		for _, w := range want {
			if !strings.Contains(gap.Detail, w) {
				t.Errorf("notice lacks %q: %s", w, gap.Detail)
			}
		}
		if strings.Contains(gap.Detail, "$_GET") {
			t.Errorf("notice still lists withheld source text: %s", gap.Detail)
		}
		if !strings.HasSuffix(gap.Detail, "a withheld path is neither absent nor protected.") {
			t.Error("closing sentence is not last")
		}
		if len(gap.Detail) >= 700 {
			t.Errorf("path-group notice is %d bytes: %s", len(gap.Detail), gap.Detail)
		}
	})
}
