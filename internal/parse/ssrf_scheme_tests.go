package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// schemeOnlyPattern is a regex that anchors only a URL scheme: ^https?:\/\/,
// ^https?:, ^(http|https):\/\/ and similar, with nothing host-bearing after it.
var schemeOnlyPattern = regexp.MustCompile(`^\^\(?(?:https\?|http\|https|https\|http|https?)\)?:(?:\\/\\/|//)?$`)

// urlSchemeOnlyTests reports that the SSRF handler's raw-text URL tests are all
// scheme-only: every regex .test/.match and startsWith on a value in the
// invoked handler fixes at most the scheme (http/https), never a host. Such a
// test does not limit the destination host. It is false when the handler has
// no such test, or any test could constrain a host.
func (s *moduleSet) urlSchemeOnlyTests(u *analysis.CandidateUse, c *analysis.Completeness) bool {
	var handlers []analysis.Evidence
	handlers = append(handlers, c.Evidence["invoked_callable"]...)
	tests, schemeOnly := 0, true
	skip := s.ssrfNonEnforcingChecks(u, c)
	seen := map[string]bool{}
	for _, h := range handlers {
		m := s.modules[h.Span.File]
		if m == nil || seen[h.Span.File+string(rune(h.Span.StartByte))] {
			continue
		}
		seen[h.Span.File+string(rune(h.Span.StartByte))] = true
		body := nodeAt(m.tree.RootNode(), h.Span.StartByte, h.Span.EndByte)
		if body == nil {
			continue
		}
		walkCalls(body, func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() != 1 {
				return
			}
			// A check that only sets a flag, or runs after the call, restricts nothing.
			if h.Span.File == u.Sink.Span.File && skip[call.StartByte()] {
				return
			}
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj == nil || prop == nil {
				return
			}
			switch prop.Utf8Text(m.src) {
			case "test":
				if obj.Kind() != "regex" {
					return
				}
				tests++
				if !schemeOnlyPattern.MatchString(regexPart(m, obj, "pattern")) {
					schemeOnly = false
				}
			case "match":
				if a := args.NamedChild(0); a.Kind() == "regex" {
					tests++
					if !schemeOnlyPattern.MatchString(regexPart(m, a, "pattern")) {
						schemeOnly = false
					}
				}
			case "startsWith":
				lit, ok := stringLiteral(args.NamedChild(0), m.src)
				if !ok {
					tests++
					schemeOnly = false
					return
				}
				if strings.HasPrefix(strings.ToLower(lit), "http") {
					tests++
					l := strings.ToLower(lit)
					if l != "http://" && l != "https://" && l != "http:" && l != "https:" && l != "http" && l != "https" {
						schemeOnly = false
					}
				}
			}
		})
	}
	return tests > 0 && schemeOnly
}
