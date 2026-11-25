package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Redirect destination-normalization facts. A browser resolves a Location or
// navigation target with the WHATWG URL parser: a backslash is a slash for
// http(s), so `/\host` and `\\host` select another host like `//host`, and
// percent-escapes (`%2f%2f`, `%5c`) are not decoded before resolution. An
// escaped form is therefore a bypass only when the code decodes the value
// after the check. These facts are derived per recorded validator predicate.
//
// Fact vocabulary on Completeness.ModelFacts:
//
//	redirect_predicate_bypass: <forms>    forms a recorded predicate permits
//	redirect_predicate_excludes: <forms>  forms every recorded predicate excludes
//	redirect_normalization: ...           how the API/browser normalizes
//
// Bypass forms: absolute_url, backslash_prefix, protocol_relative,
// slash_backslash, percent_encoded_after_decode, origin_prefix,
// parsed_origin_unfixed, checked_operand_differs, reassigned_after_check.
// With no recognized predicate no fact is recorded.

var redirectRelativeForms = []string{"absolute_url", "backslash_prefix", "protocol_relative", "slash_backslash"}

type redirectAtoms struct {
	recognized bool // a relative-path predicate atom was found
	excluded   map[string]bool
	bypass     map[string]bool
	parsedOK   bool // an enforcing parsed-origin comparison bound to the operand
}

func newRedirectAtoms() *redirectAtoms {
	return &redirectAtoms{excluded: map[string]bool{}, bypass: map[string]bool{}}
}

func (s *moduleSet) redirectPredicateFacts(u *analysis.CandidateUse, c *analysis.Completeness) {
	m := s.modules[u.Sink.Span.File]
	if m == nil || strings.HasSuffix(u.Sink.Span.File, ".py") {
		return
	}
	sink := parse.NodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if sink == nil {
		return
	}
	names := []string{}
	for _, d := range u.Dependencies {
		names = append(names, parse.CommandDepNames(d)...)
	}
	for _, group := range s.commandDerivedNames(u) {
		names = append(names, group...)
	}
	sinkText := sink.Utf8Text(m.src)
	var fn *sitter.Node
	for p := sink.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			fn = p
			break
		}
	}
	bypass, excludedEvery, any := map[string]bool{}, map[string]bool{}, false
	first := true
	for _, p := range u.CodePaths() {
		a := newRedirectAtoms()
		for _, index := range p.Controls {
			if index < 0 || index >= len(u.Context) {
				continue
			}
			e := u.Context[index]
			owner := s.modules[e.Span.File]
			if owner == nil || owner != m {
				continue
			}
			node := parse.NodeAt(owner.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if node != nil {
				a.scan(m, node, fn, sink, sinkText, names)
			}
		}
		if !a.recognized && len(a.bypass) == 0 && !a.parsedOK {
			continue
		}
		any = true
		for k := range a.bypass {
			bypass[k] = true
		}
		if a.recognized && !a.parsedOK {
			for _, f := range redirectRelativeForms {
				if !a.excluded[f] {
					bypass[f] = true
				}
			}
		}
		for _, f := range append(append([]string{}, redirectRelativeForms...), "percent_encoded") {
			ex := a.excluded[f] || a.parsedOK || f == "percent_encoded" && !a.bypass["percent_encoded_after_decode"]
			if first {
				excludedEvery[f] = ex
			} else {
				excludedEvery[f] = excludedEvery[f] && ex
			}
		}
		first = false
	}
	if !any {
		return
	}
	list := func(set map[string]bool) string {
		out := []string{}
		for k, v := range set {
			if v {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := list(bypass); got != "" {
		c.ModelFacts = append(c.ModelFacts, "redirect_predicate_bypass: "+got)
	}
	if got := list(excludedEvery); got != "" {
		c.ModelFacts = append(c.ModelFacts, "redirect_predicate_excludes: "+got)
	}
	c.ModelFacts = append(c.ModelFacts, "redirect_normalization: "+u.Redirect.ContractID+" delivers the destination to the browser URL parser; backslash is a slash for http(s); percent-escapes are not decoded")
}

var (
	redirectRegexClass = regexp.MustCompile(`^\[\^([^\]]*)\]`)
	redirectRegexLook  = regexp.MustCompile(`^\(\?!([^)]*)\)`)
)

func (a *redirectAtoms) scan(m *sourceModule, node, fn, sink *sitter.Node, sinkText string, names []string) {
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Kind() {
		case "call_expression":
			a.callAtom(m, n, node, fn, sink, sinkText, names)
		case "binary_expression":
			a.originAtom(m, n, node, fn, sink, sinkText, names)
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(node)
}

// operandNames returns the tracked names an atom's operand text mentions.
func redirectOperandNames(text string, names []string) []string {
	out := []string{}
	for _, n := range names {
		if n != "" && parse.MentionsAny(text, []string{n}) {
			out = append(out, n)
		}
	}
	return out
}

// bindOperand records the same-operand obligations for an atom: the redirect
// must use the checked value, which must not be reassigned or decoded after
// the check. It returns false when the atom is unrelated to the operand.
func (a *redirectAtoms) bindOperand(m *sourceModule, operand string, extraSink []string, control, fn, sink *sitter.Node, sinkText string, names []string) bool {
	matched := redirectOperandNames(operand, names)
	if len(matched) == 0 {
		return false
	}
	if !parse.MentionsAny(sinkText, append(append([]string{}, matched...), extraSink...)) {
		a.bypass["checked_operand_differs"] = true
	}
	if fn != nil {
		body := fn.ChildByFieldName("body")
		walkCalls(body, func(call *sitter.Node) {
			if call.StartByte() < control.EndByte() || call.StartByte() >= sink.EndByte() {
				return
			}
			callee, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if callee == nil || args == nil || callee.Kind() != "identifier" {
				return
			}
			switch callee.Utf8Text(m.src) {
			case "decodeURIComponent", "decodeURI", "unescape":
				if parse.MentionsAny(args.Utf8Text(m.src), matched) {
					a.bypass["percent_encoded_after_decode"] = true
				}
			}
		})
		for _, name := range matched {
			if parse.PlainIdentifier.MatchString(name) && writtenBetween(body, name, m.src, control.EndByte(), sink.EndByte()) {
				a.bypass["reassigned_after_check"] = true
			}
		}
	}
	return true
}

func writtenBetween(n *sitter.Node, name string, src []byte, from, to uint) bool {
	if n == nil || n.EndByte() <= from || n.StartByte() >= to {
		return false
	}
	switch n.Kind() {
	case "assignment_expression", "augmented_assignment_expression":
		if l := n.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(src) == name && n.StartByte() >= from && n.StartByte() < to {
			return true
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if writtenBetween(n.NamedChild(i), name, src, from, to) {
			return true
		}
	}
	return false
}

func unescapeJS(s string) string { return strings.ReplaceAll(s, `\\`, `\`) }

func (a *redirectAtoms) callAtom(m *sourceModule, call, control, fn, sink *sitter.Node, sinkText string, names []string) {
	callee, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if callee == nil || args == nil || args.NamedChildCount() == 0 || callee.Kind() != "member_expression" {
		return
	}
	obj, prop := callee.ChildByFieldName("object"), callee.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() == "array" {
		return
	}
	method := prop.Utf8Text(m.src)
	if obj.Kind() == "regex" && method == "test" {
		a.regexAtom(m, obj, args.NamedChild(0).Utf8Text(m.src), control, fn, sink, sinkText, names)
		return
	}
	receiver := obj.Utf8Text(m.src)
	// value.match(/pattern/) tests the same literal pattern as /pattern/.test(value)
	// (hardening 3 D-10).
	if first := args.NamedChild(0); method == "match" && first.Kind() == "regex" {
		a.regexAtom(m, first, receiver, control, fn, sink, sinkText, names)
		return
	}
	if strings.HasSuffix(receiver, ".hostname") || strings.HasSuffix(receiver, ".host") || strings.HasSuffix(receiver, ".origin") {
		return
	}
	lit, ok := stringLiteral(args.NamedChild(0), m.src)
	if !ok {
		return
	}
	lit = unescapeJS(lit)
	switch method {
	case "startsWith":
		if parsed, err := url.Parse(lit); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.Path == "" && !strings.Contains(lit[len(parsed.Scheme)+3:], "/") {
			if a.bindOperand(m, receiver, nil, control, fn, sink, sinkText, names) {
				a.bypass["origin_prefix"] = true
			}
			return
		}
		switch lit {
		case "/":
			if a.bindOperand(m, receiver, nil, control, fn, sink, sinkText, names) {
				a.recognized = true
				a.excluded["absolute_url"], a.excluded["backslash_prefix"] = true, true
			}
		case "//":
			if a.bindOperand(m, receiver, nil, control, fn, sink, sinkText, names) {
				a.recognized = true
				a.excluded["protocol_relative"] = true
			}
		case `/\`:
			if a.bindOperand(m, receiver, nil, control, fn, sink, sinkText, names) {
				a.recognized = true
				a.excluded["slash_backslash"] = true
			}
		}
	case "includes", "indexOf":
		if lit == `\` && a.bindOperand(m, receiver, nil, control, fn, sink, sinkText, names) {
			a.recognized = true
			a.excluded["slash_backslash"], a.excluded["backslash_prefix"] = true, true
		}
	}
}

func (a *redirectAtoms) regexAtom(m *sourceModule, re *sitter.Node, operand string, control, fn, sink *sitter.Node, sinkText string, names []string) {
	text := re.Utf8Text(m.src)
	end := strings.LastIndex(text, "/")
	if len(text) < 2 || text[0] != '/' || end < 1 {
		return
	}
	pat := text[1:end]
	rest := ""
	switch {
	case strings.HasPrefix(pat, `^\/`):
		rest = pat[3:]
	case strings.HasPrefix(pat, "^/"):
		rest = pat[2:]
	default:
		return
	}
	if !a.bindOperand(m, operand, nil, control, fn, sink, sinkText, names) {
		return
	}
	a.recognized = true
	a.excluded["absolute_url"], a.excluded["backslash_prefix"] = true, true
	set := ""
	if g := redirectRegexClass.FindStringSubmatch(rest); g != nil {
		set = g[1]
	} else if g := redirectRegexLook.FindStringSubmatch(rest); g != nil {
		set = g[1]
	}
	if strings.Contains(set, "/") {
		a.excluded["protocol_relative"] = true
	}
	if strings.Contains(set, `\\`) {
		a.excluded["slash_backslash"] = true
	}
}

// originAtom recognizes `new URL(x, base).origin === fixed` (also .host and
// .hostname), directly or through a const holding the parsed URL.
func (a *redirectAtoms) originAtom(m *sourceModule, bin, control, fn, sink *sitter.Node, sinkText string, names []string) {
	op := bin.ChildByFieldName("operator")
	if op == nil || !containsString([]string{"===", "==", "!==", "!="}, op.Utf8Text(m.src)) {
		return
	}
	for _, side := range [][2]string{{"left", "right"}, {"right", "left"}} {
		lhs, rhs := unwrapTS(bin.ChildByFieldName(side[0])), unwrapTS(bin.ChildByFieldName(side[1]))
		if lhs == nil || rhs == nil || lhs.Kind() != "member_expression" {
			continue
		}
		prop := lhs.ChildByFieldName("property")
		if prop == nil || !containsString([]string{"origin", "host", "hostname"}, prop.Utf8Text(m.src)) {
			continue
		}
		parsed := unwrapTS(lhs.ChildByFieldName("object"))
		parsedName := ""
		if parsed != nil && parsed.Kind() == "identifier" {
			parsedName = parsed.Utf8Text(m.src)
			if bindingReassigned(m, parsedName) {
				a.bypass["reassigned_after_check"] = true
				return
			}
			init := localInitializer(m, parsed, parsedName)
			if init == nil || !constDeclarator(init) {
				return
			}
			parsed = unwrapTS(init)
		}
		if parsed == nil || parsed.Kind() != "new_expression" {
			return
		}
		ctor, args := parsed.ChildByFieldName("constructor"), parsed.ChildByFieldName("arguments")
		if ctor == nil || args == nil || args.NamedChildCount() == 0 || ctor.Utf8Text(m.src) != "URL" || topLevelBinding(m, "URL") || shadowed(parsed, "URL", m.src) {
			return
		}
		operand := args.NamedChild(0).Utf8Text(m.src)
		base := ""
		if args.NamedChildCount() > 1 {
			base = args.NamedChild(1).Utf8Text(m.src)
		}
		extra := []string{}
		if parsedName != "" {
			extra = append(extra, parsedName)
		}
		if !a.bindOperand(m, operand, extra, control, fn, sink, sinkText, names) {
			return
		}
		if !fixedOriginOperand(m, rhs, base) {
			a.bypass["parsed_origin_unfixed"] = true
			return
		}
		a.parsedOK = true
		return
	}
}

// fixedOriginOperand accepts a string literal, a const bound to one, or the
// base's own origin as the right side of a parsed-origin comparison.
func fixedOriginOperand(m *sourceModule, n *sitter.Node, base string) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string":
		return true
	case "identifier":
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return false
		}
		init := localInitializer(m, n, name)
		return init != nil && constDeclarator(init) && unwrapTS(init) != nil && unwrapTS(init).Kind() == "string"
	case "member_expression":
		prop, obj := n.ChildByFieldName("property"), unwrapTS(n.ChildByFieldName("object"))
		if prop == nil || obj == nil || base == "" || !containsString([]string{"origin", "host", "hostname"}, prop.Utf8Text(m.src)) {
			return false
		}
		if obj.Kind() == "new_expression" {
			args := obj.ChildByFieldName("arguments")
			return args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Utf8Text(m.src) == base
		}
	}
	return false
}
