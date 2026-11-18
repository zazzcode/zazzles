package langjs

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

var requestContainers = map[string]bool{
	"body": true, "query": true, "params": true, "headers": true, "cookies": true, "payload": true,
	"path": true, "url": true, "originalUrl": true, "baseUrl": true, "file": true, "files": true,
}

// morgan's predefined formats all include :url, which is the original URL with its query string.
var urlLogFormats = map[string]bool{"combined": true, "common": true, "dev": true, "short": true, "tiny": true}

type credentialDestination struct {
	dep  analysis.Dependency
	pair analysis.Evidence
}

// requestParts resolves a destructured request parameter such as
// ({ query, headers }) so its container members become request sources.
// Other destructured members stay explicit as a partial-projection gap.
func requestParts(m *sourceModule, body *sitter.Node, gaps []analysis.Gap) (map[string]string, []analysis.Gap) {
	fn := body.Parent()
	if fn == nil {
		return nil, gaps
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() == 0 {
		return nil, gaps
	}
	p := params.NamedChild(0)
	if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
		p = p.ChildByFieldName("pattern")
	}
	if p == nil || p.Kind() != "object_pattern" {
		return nil, gaps
	}
	parts := map[string]string{}
	var other []string
	for i := uint(0); i < p.NamedChildCount(); i++ {
		c := p.NamedChild(i)
		name := c.Utf8Text(m.src)
		if c.Kind() == "shorthand_property_identifier_pattern" && requestContainers[name] {
			parts[name] = name
		} else {
			other = append(other, name)
		}
	}
	if len(parts) == 0 {
		return nil, gaps
	}
	out := make([]analysis.Gap, 0, len(gaps)+1)
	for _, g := range gaps {
		if g.Kind != "request_projection_unresolved" {
			out = append(out, g)
		}
	}
	if len(other) > 0 {
		out = append(out, analysis.Gap{Kind: "request_projection_partial", Detail: "destructured request members other than body/query/params/headers/cookies are not modeled as sources: " + strings.Join(other, ", "), At: parse.Span(m.file, p)})
	}
	return parts, out
}

// partField returns the first-level member (query.x) of a destructured request
// container, unless a local binding has replaced that container name.
func (f *flow) partField(n *sitter.Node) *sitter.Node {
	if len(f.parts) == 0 {
		return nil
	}
	src := f.module.src
	for cur := n; cur != nil && (cur.Kind() == "member_expression" || cur.Kind() == "subscript_expression"); {
		obj := cur.ChildByFieldName("object")
		if obj == nil {
			return nil
		}
		if obj.Kind() == "identifier" {
			name := obj.Utf8Text(src)
			if _, local := f.env[name]; local || f.parts[name] == "" {
				return nil
			}
			return cur
		}
		cur = obj
	}
	return nil
}

// noteCredentialDestination records a request value assigned to a property whose
// key names a credential, such as update({ password: value }). This is evidence
// about where the value goes, independent of the request field's own name.
func (f *flow) noteCredentialDestination(pair *sitter.Node, v value) {
	if f.facts == nil || f.module == nil {
		return
	}
	key := pair.ChildByFieldName("key")
	if key == nil {
		return
	}
	name := strings.Trim(key.Utf8Text(f.module.src), `'"`)
	if parse.LexiconHint(name) != "credential" {
		return
	}
	for _, d := range v.deps {
		if d.Source.Kind != "input_source" {
			continue
		}
		container, field := requestKey(d)
		id := container + "\x00" + field
		if _, ok := f.facts.credentialDest[id]; !ok {
			f.facts.credentialDest[id] = credentialDestination{dep: d, pair: f.module.evidence("credential_destination", pair)}
		}
	}
}

// noteCredentialComparison records a request value compared for equality with a
// credential-named property, such as hash(value) !== user.password.
func (f *flow) noteCredentialComparison(n, left *sitter.Node, l value, right *sitter.Node, r value) {
	op := n.ChildByFieldName("operator")
	if f.facts == nil || f.module == nil || op == nil || left == nil || right == nil {
		return
	}
	switch op.Utf8Text(f.module.src) {
	case "===", "!==", "==", "!=":
	default:
		return
	}
	for _, side := range []struct {
		other *sitter.Node
		v     value
	}{{right, l}, {left, r}} {
		if side.other.Kind() != "member_expression" {
			continue
		}
		prop := side.other.ChildByFieldName("property")
		if prop == nil || parse.LexiconHint(prop.Utf8Text(f.module.src)) != "credential" {
			continue
		}
		for _, d := range side.v.deps {
			if d.Source.Kind != "input_source" {
				continue
			}
			container, field := requestKey(d)
			id := container + "\x00" + field
			if _, ok := f.facts.credentialDest[id]; !ok {
				f.facts.credentialDest[id] = credentialDestination{dep: d, pair: f.module.evidence("credential_comparison", n)}
			}
		}
	}
}

// requestLineLogs adds a logging claim when request-line logging registered on
// the route's receiver, before the route, records the URL and the route reads a
// credential from the URL query.
func (s *moduleSet) requestLineLogs(f *flow, m *sourceModule, route *sitter.Node, receiver string) {
	if f.facts == nil {
		return
	}
	use, binding, format, notes := s.requestLogger(m, route, receiver, f.entry.HTTP.Path)
	if use == nil {
		return
	}
	var claims []analysis.Gap
	var deps []analysis.Dependency
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, binding, format)
	claimed := map[string]bool{}
	keys := make([]string, 0, len(f.facts.credentialDest))
	for k := range f.facts.credentialDest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dest := f.facts.credentialDest[k]
		container, field := requestKey(dest.dep)
		if container != "query" || field == "" {
			continue
		}
		claimed[field] = true
		deps = append(deps, dest.dep)
		context = append(context, dest.pair)
		claims = append(claims, analysis.Gap{Kind: "log_request_line_credential", Detail: fmt.Sprintf("request query field %s reaches credential evidence %q and the URL with its query string is recorded by request logging (%s)", field, dest.pair.Text, format.Text), At: dest.pair.Span})
	}
	inputs := make([]string, 0, len(f.facts.inputs))
	for k := range f.facts.inputs {
		inputs = append(inputs, k)
	}
	sort.Strings(inputs)
	for _, k := range inputs {
		source := f.facts.inputs[k]
		container, field := requestKey(analysis.Dependency{Source: source})
		if container != "query" || field == "" || claimed[field] || parse.LexiconHint(field) == "" {
			continue
		}
		claimed[field] = true
		deps = append(deps, analysis.Dependency{Source: source, Transfers: []analysis.Evidence{}})
		claims = append(claims, analysis.Gap{Kind: "log_request_line_hint", Detail: fmt.Sprintf("request query field %s has a %s field-name hint and the URL with its query string is recorded by request logging (%s)", field, parse.LexiconHint(field), format.Text), At: source.Span})
	}
	if len(claims) == 0 {
		return
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), claims...)
	gaps = append(gaps, notes...)
	gaps = append(gaps, analysis.Gap{Kind: "log_destination_unresolved", Detail: "access-log stream destination, retention and readers are not modeled", At: parse.Span(m.file, use)})
	f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("log:%s:%s:%d", f.invocation.ID, m.file, use.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: "log_sink_candidate", Sink: m.evidence("log_sink_candidate", use), Dependencies: deps, Context: context, Gaps: gaps, Assessment: analysis.Assessment{Status: "not_run"}})
}

// requestLogger finds `<receiver>.use(morgan(format))` in the route's own function
// scope, registered before the route, whose format records the URL.
func (s *moduleSet) requestLogger(m *sourceModule, route *sitter.Node, receiver, path string) (*sitter.Node, analysis.Evidence, analysis.Evidence, []analysis.Gap) {
	var found *sitter.Node
	var binding, format analysis.Evidence
	var notes []analysis.Gap
	scope := enclosingFunction(route)
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if found != nil || call.StartByte() >= route.StartByte() || !sameNode(enclosingFunction(call), scope) {
			return
		}
		fn := call.ChildByFieldName("function")
		args := call.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Kind() != "member_expression" {
			return
		}
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Utf8Text(m.src) != receiver || prop.Utf8Text(m.src) != "use" {
			return
		}
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if prefix, ok := stringLiteral(a, m.src); ok && i == 0 {
				if !strings.HasPrefix(path, prefix) {
					return
				}
				continue
			}
			if a.Kind() != "call_expression" {
				continue
			}
			callee := a.ChildByFieldName("function")
			margs := a.ChildByFieldName("arguments")
			if callee == nil || margs == nil || callee.Kind() != "identifier" || margs.NamedChildCount() == 0 {
				continue
			}
			name := callee.Utf8Text(m.src)
			imp, ok := m.imports[name]
			if !ok || imp.module != "morgan" || imp.name != "default" || shadowed(a, name, m.src) {
				continue
			}
			f0 := margs.NamedChild(0)
			text, literal := stringLiteral(f0, m.src)
			if !literal || !(urlLogFormats[text] || strings.Contains(text, ":url")) {
				continue
			}
			found = call
			binding = m.evidence("logger_binding", imp.declaration)
			format = m.evidence("log_format", f0)
			if margs.NamedChildCount() > 1 && property(margs.NamedChild(1), "skip", m.src) != nil {
				notes = append(notes, analysis.Gap{Kind: "log_request_line_conditional", Detail: "a skip option may exclude some requests from the access log", At: parse.Span(m.file, margs.NamedChild(1))})
			}
			if conditionalWithin(call, scope) {
				notes = append(notes, analysis.Gap{Kind: "log_request_line_conditional", Detail: "request logging is registered under a condition", At: parse.Span(m.file, call)})
			}
			return
		}
	})
	return found, binding, format, notes
}

func enclosingFunction(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_declaration", "function_expression", "arrow_function", "method_definition", "function", "generator_function_declaration":
			return p
		}
	}
	return nil
}

func sameNode(a, b *sitter.Node) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

func conditionalWithin(n, scope *sitter.Node) bool {
	for p := n.Parent(); p != nil && !sameNode(p, scope); p = p.Parent() {
		switch p.Kind() {
		case "if_statement", "ternary_expression", "switch_statement", "conditional_expression":
			return true
		}
	}
	return false
}
