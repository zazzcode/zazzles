package langphp

import (
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// shellURLClient records an ssrf_candidate when a request value occupies a
// URL position of a literal curl or wget command. The command candidate is
// left as it was.
func (f *phpFlow) shellURLClient(n *sitter.Node, shellMode, argvShape string, values []phpValue, nodes []*sitter.Node) {
	switch {
	case argvShape == "literal_list":
		f.shellArgvURL(n, values, nodes)
	case shellMode == "enabled" && len(values) > 0:
		node := n
		if len(nodes) > 0 && nodes[0] != nil {
			node = nodes[0]
		}
		f.shellTextURL(n, node, values[0])
	}
}

type shellFrag struct {
	text    string
	dynamic bool
	val     phpValue
	node    *sitter.Node
}

type shellWord struct {
	frags []shellFrag
}

func (w shellWord) literal() (string, bool) {
	if len(w.frags) != 1 || w.frags[0].dynamic {
		return "", false
	}
	return w.frags[0].text, true
}

func (w shellWord) dynamic() bool {
	for _, fr := range w.frags {
		if fr.dynamic {
			return true
		}
	}
	return false
}

func (w shellWord) text() string {
	var b strings.Builder
	for _, fr := range w.frags {
		if !fr.dynamic {
			b.WriteString(fr.text)
		}
	}
	return b.String()
}

func (w shellWord) value() phpValue {
	var v phpValue
	for _, fr := range w.frags {
		if fr.dynamic {
			v = phpCombine(v, fr.val)
		}
	}
	return v
}

func (f *phpFlow) shellTextURL(call, node *sitter.Node, v phpValue) {
	frags := f.shellFrags(node, v)
	words := shellWords(frags)
	if len(words) == 0 {
		return
	}
	program, ok := words[0].literal()
	if !ok || (program != "curl" && program != "wget") {
		return
	}
	for i := 1; i < len(words); i++ {
		lit, isLit := words[i].literal()
		if isLit && isOption(lit) {
			if takesValue(program, lit) {
				if i+1 < len(words) {
					next := words[i+1]
					if urlOption(lit) && next.dynamic() {
						f.emitShellURL(call, program, next, operandOf(lit))
					}
					i++
				}
				continue
			}
			continue
		}
		if words[i].dynamic() {
			f.emitShellURL(call, program, words[i], "")
		}
	}
}

func (f *phpFlow) shellArgvURL(call *sitter.Node, values []phpValue, nodes []*sitter.Node) {
	if len(values) == 0 {
		return
	}
	program, ok := phpStringLiteral(f.module, nodeAt(nodes, 0))
	if !ok {
		if text, yes := wordsLiteral(values[0]); yes {
			program = text
		}
	}
	if program != "curl" && program != "wget" {
		return
	}
	for i := 1; i < len(values); i++ {
		lit, isLit := argvLiteral(f.module, values[i], nodeAt(nodes, i))
		if isLit && isOption(lit) {
			if takesValue(program, lit) && i+1 < len(values) {
				nextLit, nextIs := argvLiteral(f.module, values[i+1], nodeAt(nodes, i+1))
				if urlOption(lit) && !nextIs {
					f.emitShellURL(call, program, shellWord{frags: []shellFrag{{dynamic: true, val: values[i+1], node: nodeAt(nodes, i+1)}}}, operandOf(lit))
				}
				_ = nextLit
				i++
			}
			continue
		}
		if !isLit && len(values[i].deps) > 0 {
			f.emitShellURL(call, program, shellWord{frags: []shellFrag{{dynamic: true, val: values[i], node: nodeAt(nodes, i)}}}, "")
		}
	}
}

func (f *phpFlow) emitShellURL(call *sitter.Node, program string, word shellWord, operand string) {
	val := word.value()
	var deps []phpDep
	for _, d := range val.deps {
		if d.dep.Source.Kind != "input_source" && d.dep.Source.Kind != "storage_source" {
			continue
		}
		d.dep.SinkSlot = analysis.OutboundSlotDestination
		deps = append(deps, d)
	}
	if len(deps) == 0 {
		return
	}
	node := call
	if len(word.frags) > 0 && word.frags[0].node != nil {
		node = word.frags[0].node
	}
	u := f.addUse("ssrf_candidate", call, phpValue{deps: deps, gaps: val.gaps})
	binding := f.module.evidence("sink_binding", phpCallee(call))
	u.Context = append(u.Context, binding)
	u.APIModel = analysispacks.SSRFContract(analysispacks.PHPShellURLClient)
	u.Outbound = &analysis.OutboundFacts{
		Operation: program, ContractID: analysispacks.PHPShellURLClient,
		DestinationOrigin: analysis.DestinationRequest, Transport: "shell_client", Operand: operand,
	}
	operandNode := node
	evidence := f.module.evidence("destination_operand", operandNode)
	u.Context = append(u.Context, evidence)
	prefix := strings.TrimSpace(word.text())
	if phpFixedAuthority(prefix) {
		pre := f.module.evidence("destination_prefix", operandNode)
		pre.Text, pre.ModelText = prefix, prefix
		u.Context = append(u.Context, pre)
	}
	for i, dep := range deps {
		path := analysis.CommandPath{Dependency: i, Operand: analysis.OutboundSlotDestination, Protection: "raw"}
		if dep.protection == "unknown" || dep.protection == phpUnwritten {
			path.Protection = "unknown"
		}
		if guard, ok := phpFilterEvidence(dep); ok {
			// The filter is evidence on the candidate. A URL-format check is
			// not a destination restriction, so the path stays raw.
			u.Context = append(u.Context, guard)
		}
		u.Outbound.Paths = append(u.Outbound.Paths, path)
	}
	var blockers []analysis.Gap
	for _, gap := range val.gaps {
		switch gap.Kind {
		case "php_parameter_unresolved", "symfony_argument_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, gap)
		}
	}
	u.Completeness = parse.SSRFCompleteness(u, map[string][]analysis.Evidence{
		"sink_binding":        {binding},
		"invoked_callable":    {f.entryEvidence()},
		"destination_operand": {evidence},
		"control_flow":        append([]analysis.Evidence{f.module.evidence("operation", call)}, f.context...),
	}, blockers, u.Gaps)
}

func (f *phpFlow) shellFrags(n *sitter.Node, v phpValue) []shellFrag {
	if n != nil && stringConstruct(n) {
		if fr := f.walkFrags(n); len(fr) > 0 {
			return fr
		}
	}
	var fr []shellFrag
	if v.prefix != "" {
		fr = append(fr, shellFrag{text: v.prefix})
	} else if phpConstantText(v) {
		fr = append(fr, shellFrag{text: v.literals[0].text})
	}
	if len(v.deps) > 0 {
		fr = append(fr, shellFrag{dynamic: true, val: v, node: n})
	}
	return fr
}

func stringConstruct(n *sitter.Node) bool {
	switch n.Kind() {
	case "binary_expression", "encapsed_string", "string", "shell_command_expression", "parenthesized_expression":
		return true
	}
	return false
}

func (f *phpFlow) walkFrags(n *sitter.Node) []shellFrag {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "parenthesized_expression":
		return f.walkFrags(firstNamedChild(n))
	case "shell_command_expression":
		var fr []shellFrag
		for i := uint(0); i < n.NamedChildCount(); i++ {
			fr = append(fr, f.walkFrags(n.NamedChild(i))...)
		}
		return fr
	case "string":
		if text, ok := phpStringLiteral(f.module, n); ok {
			return []shellFrag{{text: text, node: n}}
		}
		return f.walkFrags(firstNamedChild(n))
	case "encapsed_string":
		var fr []shellFrag
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" || !c.IsNamed() && strings.TrimSpace(c.Utf8Text(f.module.src)) != "" && c.Kind() != "\"" && c.Kind() != "'" {
				if c.Kind() == "string_content" {
					fr = append(fr, shellFrag{text: c.Utf8Text(f.module.src), node: c})
				}
				continue
			}
			if !c.IsNamed() {
				continue
			}
			fr = append(fr, shellFrag{dynamic: true, val: f.eval(c), node: c})
		}
		return fr
	case "binary_expression":
		if phpOperator(f.module, n) != "." {
			return []shellFrag{{dynamic: true, val: f.eval(n), node: n}}
		}
		return append(f.walkFrags(phpField(n, "left")), f.walkFrags(phpField(n, "right"))...)
	default:
		return []shellFrag{{dynamic: true, val: f.eval(n), node: n}}
	}
}

func shellWords(frags []shellFrag) []shellWord {
	var words []shellWord
	var cur shellWord
	flush := func() {
		if len(cur.frags) > 0 {
			words = append(words, cur)
			cur = shellWord{}
		}
	}
	for _, fr := range frags {
		if fr.dynamic {
			cur.frags = append(cur.frags, fr)
			continue
		}
		quote := byte(0)
		var b strings.Builder
		pushLit := func() {
			if b.Len() > 0 {
				cur.frags = append(cur.frags, shellFrag{text: b.String()})
				b.Reset()
			}
		}
		for i := 0; i < len(fr.text); i++ {
			c := fr.text[i]
			if quote != 0 {
				if c == quote {
					quote = 0
					continue
				}
				b.WriteByte(c)
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
				continue
			}
			if unicode.IsSpace(rune(c)) {
				pushLit()
				flush()
				continue
			}
			b.WriteByte(c)
		}
		pushLit()
	}
	flush()
	return words
}

func isOption(tok string) bool {
	return strings.HasPrefix(tok, "-") && tok != "-"
}

func takesValue(program, tok string) bool {
	base, _, _ := strings.Cut(tok, "=")
	if program == "curl" {
		switch base {
		case "-o", "-d", "-H", "-u", "-A", "-e", "-b", "-c", "-x", "-X", "-w", "-T", "-F", "-m",
			"--output", "--header", "--user", "--proxy", "--request", "--write-out", "--connect-timeout", "--max-time", "--url":
			return true
		}
		return strings.HasPrefix(base, "--data")
	}
	switch base {
	case "-O", "-o", "-P", "-U", "-t", "-T", "--header", "--user", "--password", "--post-data", "--output-document":
		return true
	}
	return false
}

func urlOption(tok string) bool {
	base, _, _ := strings.Cut(tok, "=")
	return base == "-x" || base == "--proxy" || base == "--url"
}

func operandOf(tok string) string {
	base, _, _ := strings.Cut(tok, "=")
	if base == "--url" {
		return "url"
	}
	if base == "-x" || base == "--proxy" {
		return "proxy"
	}
	return ""
}

func nodeAt(nodes []*sitter.Node, i int) *sitter.Node {
	if i < len(nodes) {
		return nodes[i]
	}
	return nil
}

func argvLiteral(m *phpModule, v phpValue, n *sitter.Node) (string, bool) {
	if n != nil {
		if text, ok := phpStringLiteral(m, n); ok {
			return text, true
		}
	}
	return wordsLiteral(v)
}

func wordsLiteral(v phpValue) (string, bool) {
	if phpConstantText(v) {
		return v.literals[0].text, true
	}
	if v.prefix != "" && len(v.deps) == 0 {
		return v.prefix, true
	}
	return "", false
}
