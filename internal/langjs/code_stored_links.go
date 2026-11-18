package langjs

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// maxStoredCodePaths bounds the writer origins one code operand may carry.
const maxStoredCodePaths = 16

// linkStoredCode makes the write-to-read storage link, built for stored XSS,
// available to a code-family operand. A code use whose operand is read from a
// storage column with at least one request-derived writer has that dependency
// replaced by the writers' origins, each carrying the write, the read and the
// read's own transfers. A setter on the model is a write-side transfer; whether
// it restricts code is decided by the code claim's own constraint evidence, never
// by HTML sanitizing. A column with no established request writer (seed-only,
// another column, unknown writer) keeps its storage read unresolved.
//
// It runs after linkStoredXSS and before the interpreter claims are assembled.
func (s *moduleSet) linkStoredCode(report *analysis.AnalysisReport) {
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Code == nil {
			continue
		}
		var deps []analysis.Dependency
		// origin maps each new dependency index to the old one, so each writer
		// origin inherits the stored read's operand path (protection, controls).
		var origin []int
		changed := false
		for old, read := range u.Dependencies {
			writes := s.codeWrites(read)
			if len(writes) == 0 {
				deps = append(deps, read)
				origin = append(origin, old)
				continue
			}
			linked := 0
			for _, write := range writes {
				for _, writer := range write.value.deps {
					if linked >= maxStoredCodePaths {
						break
					}
					linked++
					writer.SinkSlot = read.SinkSlot
					writer.Transfers = append(append([]analysis.Evidence{}, writer.Transfers...), write.sink, read.Source)
					writer.Transfers = append(writer.Transfers, read.Transfers...)
					deps = append(deps, writer)
					origin = append(origin, old)
				}
			}
			changed = changed || linked > 0
			if linked == 0 {
				deps = append(deps, read)
				origin = append(origin, old)
			}
		}
		if changed {
			u.Dependencies = deps
			u.Code.Paths = remapCodePaths(u.Code.Paths, origin)
		}
	}
}

// codeWrites returns the request-derived writes of a storage-read dependency in
// a stable order; a dependency that is not a storage read has none.
func (s *moduleSet) codeWrites(read analysis.Dependency) []storageWrite {
	if !s.codeLinkableColumn(read.StorageKey) {
		return nil
	}
	writes := append([]storageWrite{}, s.storageWrites[read.StorageKey]...)
	sort.SliceStable(writes, func(i, j int) bool {
		a, b := writes[i].sink.Span, writes[j].sink.Span
		if a.File != b.File {
			return a.File < b.File
		}
		return a.StartByte < b.StartByte
	})
	return writes
}

var sequelizeStringType = regexp.MustCompile(`^\w+\.(?:STRING|TEXT)\b`)

// codeLinkableColumn reports whether a Sequelize column may carry a stored code
// operand from its writers: a string-typed attribute with no write-side restriction
// the scanner cannot judge. A validator, a non-string type, an unreadable
// definition or a setter doing more than HTML sanitizing leaves the read
// unresolved rather than claiming either a path or its protection.
func (s *moduleSet) codeLinkableColumn(key string) bool {
	dot := strings.LastIndex(key, ".")
	if dot < 0 || !strings.HasPrefix(key, "sequelize:") {
		return false
	}
	model, field := key[:dot], key[dot+1:]
	m, attributes := s.sequelizeAttributes(model)
	if attributes == nil {
		return false
	}
	definition := property(attributes, field, m.src)
	if definition == nil {
		return false
	}
	if definition.Kind() != "object" {
		return sequelizeStringType.MatchString(strings.TrimSpace(definition.Utf8Text(m.src)))
	}
	typ := property(definition, "type", m.src)
	if typ == nil || !sequelizeStringType.MatchString(strings.TrimSpace(typ.Utf8Text(m.src))) || property(definition, "validate", m.src) != nil {
		return false
	}
	for i := uint(0); i < definition.NamedChildCount(); i++ {
		c := definition.NamedChild(i)
		if name := c.ChildByFieldName("name"); c.Kind() == "method_definition" && name != nil && name.Utf8Text(m.src) == "set" {
			return s.htmlOnlySetter(m, c, field)
		}
	}
	return true
}

// htmlOnlySetter accepts a setter whose only effect on the value is reassigning the
// parameter through a verified HTML sanitizer, under conditions that do not test
// the parameter, and storing it with setDataValue. An HTML sanitizer removes
// markup; it is not a code restriction, so such a setter keeps the code path open.
// Any other statement, including a test of the value, a throw or another
// transformation, is a write-side control whose adequacy is unknown here.
func (s *moduleSet) htmlOnlySetter(m *sourceModule, setter *sitter.Node, field string) bool {
	params, ok := functionParameters(setter, m.src)
	if !ok || len(params) != 1 {
		return false
	}
	name := params[0].name
	mention := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	var allowed func(*sitter.Node, int) bool
	allowed = func(n *sitter.Node, depth int) bool {
		if n == nil || depth > 6 {
			return false
		}
		switch n.Kind() {
		case "statement_block":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				if c := n.NamedChild(i); c.Kind() != "comment" && c.Kind() != "empty_statement" && !allowed(c, depth+1) {
					return false
				}
			}
			return true
		case "if_statement":
			cond := n.ChildByFieldName("condition")
			if cond == nil || mention.MatchString(cond.Utf8Text(m.src)) || !allowed(n.ChildByFieldName("consequence"), depth+1) {
				return false
			}
			if alt := n.ChildByFieldName("alternative"); alt != nil {
				for i := uint(0); i < alt.NamedChildCount(); i++ {
					if !allowed(alt.NamedChild(i), depth+1) {
						return false
					}
				}
			}
			return true
		case "expression_statement":
			if n.NamedChildCount() != 1 {
				return false
			}
			e := n.NamedChild(0)
			switch e.Kind() {
			case "assignment_expression":
				left, right := e.ChildByFieldName("left"), e.ChildByFieldName("right")
				if left == nil || left.Utf8Text(m.src) != name || right == nil || right.Kind() != "call_expression" {
					return false
				}
				args := right.ChildByFieldName("arguments")
				return args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Utf8Text(m.src) == name && s.htmlSanitizerCall(m, right, 0)
			case "call_expression":
				fn, args := e.ChildByFieldName("function"), e.ChildByFieldName("arguments")
				if fn == nil || args == nil || fn.Utf8Text(m.src) != "this.setDataValue" || args.NamedChildCount() != 2 {
					return false
				}
				key, _ := stringLiteral(args.NamedChild(0), m.src)
				return key == field && args.NamedChild(1).Utf8Text(m.src) == name
			}
		}
		return false
	}
	return allowed(setter.ChildByFieldName("body"), 0)
}

// htmlSanitizerCall reports a call that resolves to a function which only strips
// markup: it calls an import of sanitize-html, or removes `<`-led tag patterns with
// a regular-expression replace, directly or through at most two local wrappers.
// The callee's name is never evidence.
func (s *moduleSet) htmlSanitizerCall(m *sourceModule, call *sitter.Node, depth int) bool {
	if depth > 2 {
		return false
	}
	target, fn := s.resolveCall(m, call)
	if target == nil || fn == nil {
		return false
	}
	found := false
	walkCalls(fn, func(inner *sitter.Node) {
		callee := inner.ChildByFieldName("function")
		args := inner.ChildByFieldName("arguments")
		if callee == nil || args == nil {
			return
		}
		if callee.Kind() == "identifier" {
			if imp, ok := target.imports[callee.Utf8Text(target.src)]; ok {
				found = found || imp.module == "sanitize-html"
			} else if !found && inner != call {
				// One more local hop: a wrapper over the sanitizer library.
				found = s.htmlSanitizerCall(target, inner, depth+1)
			}
			return
		}
		if callee.Kind() == "member_expression" && args.NamedChildCount() >= 1 {
			if prop := callee.ChildByFieldName("property"); prop != nil && prop.Utf8Text(target.src) == "replace" && args.NamedChild(0).Kind() == "regex" && strings.HasPrefix(args.NamedChild(0).Utf8Text(target.src), "/<") {
				found = true
			}
		}
	})
	return found
}

// remapCodePaths gives every new dependency the operand path of the dependency
// it replaced. A replaced dependency with no path yields none, so coverage is
// never invented: validation still reports a missing path.
func remapCodePaths(paths []analysis.CommandPath, origin []int) []analysis.CommandPath {
	byDep := map[int]analysis.CommandPath{}
	for _, p := range paths {
		byDep[p.Dependency] = p
	}
	out := []analysis.CommandPath{}
	for i, old := range origin {
		p, ok := byDep[old]
		if !ok {
			continue
		}
		p.Dependency = i
		p.Controls = append([]int(nil), p.Controls...)
		out = append(out, p)
	}
	return out
}
