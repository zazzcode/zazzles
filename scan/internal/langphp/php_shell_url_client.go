package langphp

import (
	"path"
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// shellURLContract turns the shell URL client contract on. A test turns it
// off to prove the command candidate does not depend on it.
var shellURLContract = true

// phpPiece is one part of a concatenated or interpolated string: literal
// text, or a value with the node that produced it.
type phpPiece struct {
	text    string
	dynamic bool
	val     phpValue
	module  *phpModule
	node    *sitter.Node
}

// phpMaxPieces bounds the parts kept on one string value.
const phpMaxPieces = 64

// phpPiecesOf returns the parts of v. A value that was not built by
// concatenation is one part: its constant text, or itself.
func phpPiecesOf(v phpValue, m *phpModule, n *sitter.Node) []phpPiece {
	if v.pieces != nil {
		return v.pieces
	}
	if phpConstantText(v) && len(v.deps) == 0 {
		return []phpPiece{{text: v.literals[0].text}}
	}
	return []phpPiece{{dynamic: true, val: v, module: m, node: n}}
}

// phpBoundPieces copies the parts so no two values share a backing array,
// and drops them past the bound.
func phpBoundPieces(pieces []phpPiece) []phpPiece {
	if len(pieces) == 0 || len(pieces) > phpMaxPieces {
		return nil
	}
	return append([]phpPiece{}, pieces...)
}

// shellCommandValue evaluates a backtick command and keeps its parts.
func (f *phpFlow) shellCommandValue(n *sitter.Node) phpValue {
	var v phpValue
	var pieces []phpPiece
	for i := uint(0); i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil || !c.IsNamed() {
			continue
		}
		if c.Kind() == "string_content" {
			pieces = append(pieces, phpPiece{text: c.Utf8Text(f.module.src)})
		}
		part := f.eval(c)
		if c.Kind() != "string_content" {
			pieces = append(pieces, phpPiecesOf(part, f.module, c)...)
		}
		v = phpCombine(v, part)
	}
	v.pieces = phpBoundPieces(pieces)
	return v
}

// shellWord is one shell word: its parts, and the evaluated value that
// holds the complete dependency paths of those parts.
type shellWord struct {
	parts []phpPiece
	whole phpValue
}

func (w shellWord) dynamic() bool {
	for _, p := range w.parts {
		if p.dynamic {
			return true
		}
	}
	return false
}

// lead is the literal text the word starts with.
func (w shellWord) lead() string {
	var b strings.Builder
	for _, p := range w.parts {
		if p.dynamic {
			break
		}
		b.WriteString(p.text)
	}
	return b.String()
}

// shellURLClient records an ssrf_candidate when a request value occupies a
// URL position of a literal curl or wget command. It reads the values the
// command candidate was built from and evaluates nothing, so it adds a
// record and changes none.
func (f *phpFlow) shellURLClient(call *sitter.Node, shellMode, argvShape string, values []phpValue, nodes []*sitter.Node) {
	if !shellURLContract || len(values) == 0 {
		return
	}
	var words []shellWord
	switch {
	case argvShape == "literal_list":
		for i, v := range values {
			words = append(words, shellWord{parts: phpPiecesOf(v, f.module, nodeAt(nodes, i)), whole: v})
		}
	case shellMode == "enabled":
		words = shellWords(phpPiecesOf(values[0], f.module, nodeAt(nodes, 0)), values[0])
	}
	if len(words) == 0 || words[0].dynamic() {
		return
	}
	program := path.Base(words[0].lead())
	if program != "curl" && program != "wget" {
		return
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		option := w.lead()
		if !strings.HasPrefix(option, "-") || option == "-" {
			if w.dynamic() {
				f.emitShellURL(call, program, w, "")
			}
			continue
		}
		name, _, attached := strings.Cut(option, "=")
		operand := shellURLOperand(program, name)
		switch {
		case attached || w.dynamic():
			// The value is in the same word: --proxy=VALUE or -xVALUE.
			if operand != "" && w.dynamic() {
				f.emitShellURL(call, program, w, operand)
			}
		case shellOptionTakesValue(program, name) && i+1 < len(words):
			i++
			if operand != "" && words[i].dynamic() {
				f.emitShellURL(call, program, words[i], operand)
			}
		}
	}
}

// shellWords splits the parts of shell text into words on white space
// outside quotes. A value stays in the word it is written in.
func shellWords(pieces []phpPiece, whole phpValue) []shellWord {
	var words []shellWord
	cur := shellWord{whole: whole}
	var b strings.Builder
	literal := func() {
		if b.Len() > 0 {
			cur.parts = append(cur.parts, phpPiece{text: b.String()})
			b.Reset()
		}
	}
	flush := func() {
		literal()
		if len(cur.parts) > 0 {
			words = append(words, cur)
			cur = shellWord{whole: whole}
		}
	}
	quote := byte(0)
	for _, p := range pieces {
		if p.dynamic {
			literal()
			cur.parts = append(cur.parts, p)
			continue
		}
		for i := 0; i < len(p.text); i++ {
			c := p.text[i]
			switch {
			case quote != 0 && c == quote:
				quote = 0
			case quote != 0:
				b.WriteByte(c)
			case c == '"' || c == '\'':
				quote = c
			case unicode.IsSpace(rune(c)):
				flush()
			default:
				b.WriteByte(c)
			}
		}
	}
	flush()
	return words
}

// curlValueOptions and wgetValueOptions are the options whose next word is
// the option's value, so that word is not a URL position.
var curlValueOptions = []string{
	"-o", "-d", "-H", "-u", "-A", "-e", "-b", "-c", "-x", "-X", "-w", "-T", "-F", "-m", "-K", "-E", "-r", "-U", "-C", "-y", "-Y", "-z",
	"--output", "--header", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--proxy", "--proxy-user",
	"--request", "--write-out", "--upload-file", "--form", "--form-string", "--connect-timeout", "--max-time", "--url",
	"--config", "--cert", "--key", "--cacert", "--capath", "--range", "--retry", "--retry-delay", "--retry-max-time",
	"--max-redirs", "--limit-rate", "--resolve", "--connect-to", "--interface", "--output-dir", "--oauth2-bearer",
	"--continue-at", "--speed-time", "--speed-limit", "--time-cond",
}

var wgetValueOptions = []string{
	"-O", "-o", "-a", "-P", "-U", "-t", "-T", "-e", "-i", "-w", "-Q", "-l", "-A", "-R", "-D", "-I", "-X",
	"--header", "--user", "--password", "--post-data", "--post-file", "--output-document", "--output-file",
	"--append-output", "--directory-prefix", "--user-agent", "--referer", "--tries", "--timeout", "--execute",
	"--input-file", "--wait", "--quota", "--level", "--load-cookies", "--save-cookies", "--http-user", "--http-password",
	"--method", "--body-data", "--body-file", "--ca-certificate", "--certificate", "--private-key", "--limit-rate",
}

// shellOptionTakesValue reports an option whose value is the next word. A
// cluster of short flags takes a value when its last flag does.
func shellOptionTakesValue(program, name string) bool {
	list := wgetValueOptions
	if program == "curl" {
		if strings.HasPrefix(name, "--data") {
			return true
		}
		list = curlValueOptions
	}
	if len(name) > 2 && name[1] != '-' {
		name = "-" + name[len(name)-1:]
	}
	for _, option := range list {
		if option == name {
			return true
		}
	}
	return false
}

// shellURLOperand names the options whose value is itself a destination.
func shellURLOperand(program, name string) string {
	if program != "curl" {
		return ""
	}
	switch {
	case name == "--url":
		return "url"
	case name == "--proxy", strings.HasPrefix(name, "-x"):
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

// emitShellURL records the candidate for one word. The dependencies come
// from the whole operand value, which carries each path to the sink; the
// word's own parts select which of them reach this word.
func (f *phpFlow) emitShellURL(call *sitter.Node, program string, word shellWord, operand string) {
	var part *phpPiece
	sources := map[analysis.Span]bool{}
	var gaps []analysis.Gap
	for i, p := range word.parts {
		if !p.dynamic {
			continue
		}
		if part == nil {
			part = &word.parts[i]
		}
		for _, d := range p.val.deps {
			sources[d.dep.Source.Span] = true
		}
		gaps = append(gaps, p.val.gaps...)
	}
	var deps []phpDep
	for _, d := range word.whole.deps {
		if !sources[d.dep.Source.Span] || (d.dep.Source.Kind != "input_source" && d.dep.Source.Kind != "storage_source") {
			continue
		}
		d.dep.SinkSlot = analysis.OutboundSlotDestination
		deps = append(deps, d)
	}
	if len(deps) == 0 {
		return
	}
	u := f.addUse("ssrf_candidate", call, phpValue{deps: deps, gaps: gaps})
	binding := f.module.evidence("sink_binding", phpCallee(call))
	u.Context = append(u.Context, binding)
	u.APIModel = analysispacks.SSRFContract(analysispacks.PHPShellURLClient)
	u.Outbound = &analysis.OutboundFacts{
		Operation: program, ContractID: analysispacks.PHPShellURLClient,
		DestinationOrigin: analysis.DestinationRequest, Transport: "shell_client", Operand: operand,
	}
	evidence := f.module.evidence("destination_operand", call)
	if part.module != nil && part.node != nil {
		evidence = part.module.evidence("destination_operand", part.node)
	}
	u.Context = append(u.Context, evidence)
	if prefix := word.lead(); phpFixedAuthority(prefix) {
		pre := evidence
		pre.Kind, pre.Text, pre.ModelText = "destination_prefix", prefix, prefix
		u.Context = append(u.Context, pre)
	}
	for i, dep := range deps {
		// A filter is evidence on the candidate. A URL-format check is not a
		// destination restriction, so the path stays raw.
		p := analysis.CommandPath{Dependency: i, Operand: analysis.OutboundSlotDestination, Protection: "raw"}
		if dep.protection == "unknown" || dep.protection == phpUnwritten {
			p.Protection = "unknown"
		}
		if guard, ok := phpFilterEvidence(dep); ok {
			u.Context = append(u.Context, guard)
		}
		u.Outbound.Paths = append(u.Outbound.Paths, p)
	}
	var blockers []analysis.Gap
	for _, gap := range gaps {
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
