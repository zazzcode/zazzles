package langjs

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// Finite bindings always refer to original syntax nodes, never rewritten source.
type registrationSeeds map[string]*sitter.Node

func literalRegistrationValue(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string", "number", "true", "false", "null":
		return true
	}
	return false
}

func (s *moduleSet) finiteRoutes(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node, receiver string) bool {
	return s.finiteRoutesAt(out, m, m, call, receiver, "", nil)
}

func (s *moduleSet) finiteRoutesAt(out *analysis.AnalysisReport, m, owner *sourceModule, call *sitter.Node, receiver, prefix string, derived []analysis.Evidence) bool {
	args := call.ChildByFieldName("arguments")
	fn := call.ChildByFieldName("function")
	if args == nil || args.NamedChildCount() < 2 || fn == nil {
		return false
	}
	method := methods[textNode(fn.ChildByFieldName("property"), m.src)]
	if method == "" || method == "USE" {
		return false
	}
	var loop *sitter.Node
	for p := call.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			break
		}
		if p.Kind() == "for_in_statement" {
			loop = p
			break
		}
	}
	if loop == nil {
		return false
	}
	_, literalPath := stringLiteral(args.NamedChild(0), m.src)
	dynamicPath := !literalPath
	gap := func(detail string) {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "dynamic_registration_unresolved", Detail: detail, At: parse.Span(m.file, call)})
	}
	if !strings.Contains(loop.Utf8Text(m.src), " of ") {
		gap("Only finite for-of registration is modeled")
		return dynamicPath
	}
	left, right := loop.ChildByFieldName("left"), loop.ChildByFieldName("right")
	if left == nil || right == nil {
		gap("Unsupported finite loop binding")
		return dynamicPath
	}
	table := right
	if right.Kind() == "identifier" {
		table = nil
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			d := root.NamedChild(i)
			if d.Kind() != "lexical_declaration" || !strings.HasPrefix(d.Utf8Text(m.src), "const ") {
				continue
			}
			for j := uint(0); j < d.NamedChildCount(); j++ {
				v := d.NamedChild(j)
				if textNode(v.ChildByFieldName("name"), m.src) == right.Utf8Text(m.src) {
					table = v.ChildByFieldName("value")
				}
			}
		}
	}
	state := newBrowserEvents(out, m)
	if table == nil || table.Kind() != "array" || state.mutated(right.Utf8Text(m.src), true) {
		gap("Registration table is not an immutable local literal array")
		return dynamicPath
	}
	invalid := false
	walkCalls(m.tree.RootNode(), func(n *sitter.Node) {
		f := n.ChildByFieldName("function")
		if f != nil && strings.HasPrefix(f.Utf8Text(m.src), right.Utf8Text(m.src)+".") {
			invalid = true
		}
	})
	if invalid {
		gap("Registration table has unsupported method calls")
		return dynamicPath
	}
	for i := uint(0); i < table.NamedChildCount(); i++ {
		row := table.NamedChild(i)
		if row.Kind() == "comment" {
			continue
		}
		if i >= 128 || len(out.Entries)+len(out.DispatchBindings)+len(out.InvocationContexts) >= 10000 {
			gap("Finite registration limit reached (128/site or 10000 derived records/scan); remainder unexpanded")
			break
		}
		seeds := registrationSeeds{}
		invalid = false
		if left.Kind() == "identifier" && literalRegistrationValue(row) {
			seeds[left.Utf8Text(m.src)] = row
		} else if left.Kind() == "array_pattern" && row.Kind() == "array" && left.NamedChildCount() == row.NamedChildCount() {
			for j := uint(0); j < left.NamedChildCount(); j++ {
				name, v := left.NamedChild(j), row.NamedChild(j)
				if name.Kind() != "identifier" || !literalRegistrationValue(v) && !(v.Kind() == "identifier" && m.funcs[v.Utf8Text(m.src)] != nil && !state.mutated(v.Utf8Text(m.src), true)) && !isFunction(v) {
					invalid = true
					break
				}
				seeds[name.Utf8Text(m.src)] = v
			}
		} else {
			invalid = true
		}
		if invalid {
			gap("Unsupported finite registration row/projection")
			continue
		}
		for name := range seeds {
			if state.mutated(name, true) {
				invalid = true
			}
		}
		if invalid {
			gap("Loop binding is mutated; closure projection unresolved")
			continue
		}
		pathNode := args.NamedChild(0)
		if pathNode.Kind() == "identifier" {
			pathNode = seeds[pathNode.Utf8Text(m.src)]
		}
		if state.mutated(receiver, true) {
			gap("Express receiver or registration method is mutated")
			return true
		}
		path, ok := stringLiteral(pathNode, m.src)
		if !ok || !strings.HasPrefix(path, "/") {
			gap("Finite path does not resolve to a literal URL")
			continue
		}
		r := analysis.Route{ID: fmt.Sprintf("route:%s:%d:%s:%s:%d", m.file, call.StartByte(), method, path, i), Method: method, PathPattern: path, Framework: "express", Registration: parse.Span(m.file, call)}
		provenance := []analysis.Evidence{m.evidence("generation_site", loop), m.evidence("generation_row", row)}
		if prefix != "" {
			s.mountedOrigins[parse.HTTPEntry(r, m.evidence("entry_registration", call), m.file+":"+m.hash+":"+receiver).ID] = true
			r.PathPattern = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
			r.ID += ":mount:" + owner.file + ":" + prefix
		}
		provenance = append(provenance, derived...)
		s.analyzeSeededRoute(out, m, owner, r, call, receiver, provenance, path, prefix, seeds)
	}
	return true
}

func textNode(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(src)
}

func (s *moduleSet) literalFactory(m *sourceModule, h *sitter.Node, inherited registrationSeeds) (*sourceModule, *sitter.Node, string, registrationSeeds, []analysis.Evidence, bool) {
	if h == nil || h.Kind() != "call_expression" {
		return nil, nil, "", nil, nil, false
	}
	args, fn := h.ChildByFieldName("arguments"), h.ChildByFieldName("function")
	if args == nil || args.NamedChildCount() == 0 || fn == nil || fn.Kind() != "identifier" {
		return nil, nil, "", nil, nil, false
	}
	target, factory := s.resolve(m, fn.Utf8Text(m.src))
	if target != m || factory == nil || shadowed(h, fn.Utf8Text(m.src), m.src) {
		return nil, nil, "", nil, nil, false
	}
	state := newBrowserEvents(nil, m)
	if state.mutated(fn.Utf8Text(m.src), true) {
		return nil, nil, "", nil, nil, false
	}
	params, valid := functionParameters(factory, m.src)
	if !valid || len(params) != int(args.NamedChildCount()) {
		return nil, nil, "", nil, nil, false
	}
	seeds := registrationSeeds{}
	provenance := []analysis.Evidence{m.evidence("factory_call", h), m.evidence("factory_definition", factory)}
	for i, p := range params {
		v := args.NamedChild(uint(i))
		if v.Kind() == "identifier" {
			v = inherited[v.Utf8Text(m.src)]
		}
		if !literalRegistrationValue(v) || state.mutated(p.name, true) {
			return nil, nil, "", nil, nil, false
		}
		seeds[p.name] = v
		provenance = append(provenance, m.evidence("factory_argument", v))
	}
	body := factory.ChildByFieldName("body")
	var returned *sitter.Node
	if body != nil && isFunction(body) {
		returned = body
	} else if body != nil {
		for i := uint(0); i < body.NamedChildCount(); i++ {
			n := body.NamedChild(i)
			if n.Kind() == "comment" {
				continue
			}
			if n.Kind() != "return_statement" || n.NamedChildCount() != 1 || !isFunction(n.NamedChild(0)) || returned != nil {
				return nil, nil, "", nil, nil, false
			}
			returned = n.NamedChild(0)
		}
	}
	if returned == nil {
		return nil, nil, "", nil, nil, false
	}
	hp, valid := functionParameters(returned, m.src)
	if !valid || len(hp) == 0 {
		return nil, nil, "", nil, nil, false
	}
	return m, returned.ChildByFieldName("body"), hp[0].name, seeds, provenance, true
}

func registrationClosures(m *sourceModule, seeds registrationSeeds) []analysis.InputBinding {
	keys := make([]string, 0, len(seeds))
	for k := range seeds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []analysis.InputBinding
	for _, k := range keys {
		var constant *string
		origin := "derived"
		if literalRegistrationValue(seeds[k]) {
			text := seeds[k].Utf8Text(m.src)
			if decoded, ok := stringLiteral(seeds[k], m.src); ok {
				text = decoded
			}
			constant = &text
			origin = "constant"
		}
		out = append(out, analysis.InputBinding{Constant: constant, Role: "closure", Parameter: k, Origin: analysis.InputOrigin{Kind: origin, Evidence: []analysis.Evidence{m.evidence("closure_binding", seeds[k])}}})
	}
	return out
}

func (f *flow) registrationCondition(n *sitter.Node) (bool, bool) {
	if n == nil || len(f.constants) == 0 {
		return false, false
	}
	if n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		return f.registrationCondition(n.NamedChild(0))
	}
	literal := func(n *sitter.Node) (string, bool) {
		if n == nil {
			return "", false
		}
		if n.Kind() == "identifier" {
			n = f.constants[n.Utf8Text(f.module.src)]
		}
		if !literalRegistrationValue(n) {
			return "", false
		}
		text := n.Utf8Text(f.module.src)
		if n.Kind() == "string" {
			if strings.Contains(text, "\\") {
				return "", false
			}
			text, _ = stringLiteral(n, f.module.src)
		}
		return n.Kind() + ":" + text, true
	}
	if n.Kind() == "identifier" || n.Kind() == "true" || n.Kind() == "false" {
		v, ok := literal(n)
		if ok && (v == "true:true" || v == "false:false") {
			return v == "true:true", true
		}
		return false, false
	}
	if n.Kind() == "binary_expression" {
		a, aok := literal(n.ChildByFieldName("left"))
		b, bok := literal(n.ChildByFieldName("right"))
		if !aok || !bok {
			return false, false
		}
		switch textNode(n.ChildByFieldName("operator"), f.module.src) {
		case "===":
			return a == b, true
		case "!==":
			return a != b, true
		}
	}
	return false, false
}
