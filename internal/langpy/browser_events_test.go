package langpy

import (
	"crypto/sha256"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"testing"
)

func TestBrowserEventPipeline(t *testing.T) {
	t.Run("Python inline snapshot", func(t *testing.T) {
		source := "<html>\n<p>Original prefix</p>\n<script>\nfunction render(e){document.body.innerHTML=e.data;}\nwindow.addEventListener('message',render);\n</script>\n</html>"
		root := pythonFixture(t, map[string]string{"app.py": "from flask import Flask, render_template\napp=Flask(__name__)\n@app.get('/')\ndef index():\n    return render_template('page.html')\n", "templates/page.html": source})
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		events, uses := 0, 0
		for _, e := range r.Entries {
			if e.Browser != nil && e.Browser.Category == "event" {
				events++
				if e.Location.Span.StartLine != 5 {
					t.Fatalf("rebased registration: %+v", e.Location)
				}
			}
		}
		for _, u := range r.Uses {
			if u.EntryKind != "browser" {
				continue
			}
			uses++
			for _, e := range append([]analysis.Evidence{u.Sink, u.Dependencies[0].Source, u.EntryFacts.Location}, u.Context...) {
				if e.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) || source[e.Span.StartByte:e.Span.EndByte] != e.Text {
					t.Fatalf("snapshot mismatch: %+v", e)
				}
			}
			if u.Sink.Span.StartLine != 4 || u.EntryFacts.Browser.Category != "event" {
				t.Fatal("wrong inline event context")
			}
		}
		if events != 1 || uses != 1 {
			t.Fatalf("lost/duplicate inline event: %d/%d", events, uses)
		}
	})
}
