package guidelines

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// TestXSSCookieAndPathContextGuidance (judge evidence quality K): the selected
// XSS guidance of every language states how a cookie source bears on
// exposure, and PHP's states that a path's own output_context is where its
// value lands.
func TestXSSCookieAndPathContextGuidance(t *testing.T) {
	for _, language := range []lang.Language{lang.PHP, lang.JavaScript, lang.Python} {
		g, err := FamilyBody(language, "xss")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(g.Body, "A cookie value is request input the client sends") || !strings.Contains(g.Body, "it alone does not make exposure unknown") {
			t.Errorf("%s XSS guidance lacks the cookie rule", language)
		}
		if language == lang.PHP && !strings.Contains(g.Body, "states its own `output_context`") {
			t.Errorf("PHP XSS guidance lacks the per-path context rule")
		}
	}
}
