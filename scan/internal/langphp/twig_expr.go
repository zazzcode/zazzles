package langphp

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type twigToken struct{ text, kind string }

type twigNode struct {
	kind, text string
	args       []*twigNode
}

type twigParser struct {
	tokens    []twigToken
	at, depth int
	bad       bool
}

func newTwigParser(input string) *twigParser {
	p := &twigParser{}
	for i := 0; i < len(input) && len(p.tokens) < 512; {
		c := input[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		start := i
		if c == '"' || c == '\'' {
			var value strings.Builder
			i++
			closed := false
			for i < len(input) {
				if input[i] == c {
					closed = true
					i++
					break
				}
				if input[i] == '\\' && i+1 < len(input) {
					i++
					switch input[i] {
					case 'n':
						value.WriteByte('\n')
					case 'r':
						value.WriteByte('\r')
					case 't':
						value.WriteByte('\t')
					default:
						value.WriteByte(input[i])
					}
				} else {
					value.WriteByte(input[i])
				}
				i++
			}
			if !closed {
				p.bad = true
				break
			}
			p.tokens = append(p.tokens, twigToken{value.String(), "literal"})
			continue
		}
		if twigIdentifierStart(c) {
			i++
			for i < len(input) && (twigIdentifierStart(input[i]) || input[i] >= '0' && input[i] <= '9') {
				i++
			}
			p.tokens = append(p.tokens, twigToken{input[start:i], "name"})
			continue
		}
		if c >= '0' && c <= '9' {
			i++
			for i < len(input) && (input[i] >= '0' && input[i] <= '9' || input[i] == '.') {
				i++
			}
			if _, err := strconv.ParseFloat(input[start:i], 64); err != nil {
				p.bad = true
				break
			}
			p.tokens = append(p.tokens, twigToken{input[start:i], "literal"})
			continue
		}
		matched := false
		for _, op := range []string{"===", "!==", "??", "?:", "==", "!=", ">=", "<=", "=>"} {
			if strings.HasPrefix(input[i:], op) {
				p.tokens = append(p.tokens, twigToken{op, "punctuation"})
				i += len(op)
				matched = true
				break
			}
		}
		if !matched {
			p.tokens = append(p.tokens, twigToken{input[i : i+1], "punctuation"})
			i++
		}
	}
	if len(p.tokens) >= 512 {
		p.bad = true
	}
	return p
}

func twigIdentifierStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func twigIdentifier(s string) bool {
	if s == "" || !twigIdentifierStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !twigIdentifierStart(c) && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (p *twigParser) peek() twigToken {
	if p.at < len(p.tokens) {
		return p.tokens[p.at]
	}
	return twigToken{}
}
func (p *twigParser) next() twigToken {
	t := p.peek()
	if p.at < len(p.tokens) {
		p.at++
	}
	return t
}
func (p *twigParser) take(text string) bool {
	t := p.peek()
	if t.kind == "literal" || t.text != text {
		return false
	}
	p.at++
	return true
}
func (p *twigParser) need(text string) {
	if !p.take(text) {
		p.bad = true
	}
}

func twigPrecedence(op string) int {
	switch op {
	case "?", "?:":
		return 1
	case "??":
		return 2
	case "or":
		return 3
	case "and":
		return 4
	case "in", "not", "is", "==", "===", "!=", "!==", "<", "<=", ">", ">=":
		return 5
	case "~":
		return 6
	case "|":
		return 7
	case ".", "[":
		return 8
	}
	return 0
}

func (p *twigParser) expression(min int) *twigNode {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 48 || p.bad {
		p.bad = true
		return nil
	}
	left := p.atom()
	for left != nil && !p.bad {
		token := p.peek()
		op := token.text
		prec := twigPrecedence(op)
		if token.kind == "literal" || prec <= min {
			break
		}
		p.next()
		switch op {
		case ".":
			field := p.next()
			if field.kind != "name" {
				p.bad = true
				break
			}
			if p.take("(") {
				args := p.sequence(")")
				left = &twigNode{kind: "method", text: field.text, args: append([]*twigNode{left}, args...)}
			} else {
				left = &twigNode{kind: "property", text: field.text, args: []*twigNode{left}}
			}
		case "[":
			key := p.next()
			if key.kind != "literal" {
				p.bad = true
				break
			}
			p.need("]")
			left = &twigNode{kind: "property", text: key.text, args: []*twigNode{left}}
		case "|":
			filter := p.next()
			if filter.kind != "name" {
				p.bad = true
				break
			}
			var args []*twigNode
			if p.take("(") {
				args = p.sequence(")")
			}
			if p.take(".") {
				// Twig's method-style suffix on a filter result (e.g. u.truncate).
				name := p.next()
				p.need("(")
				args = append(args, p.sequence(")")...)
				if name.kind != "name" {
					p.bad = true
					break
				}
				value := &twigNode{kind: "filter", text: filter.text, args: []*twigNode{left}}
				left = &twigNode{kind: "method", text: name.text, args: append([]*twigNode{value}, args...)}
			} else {
				left = &twigNode{kind: "filter", text: filter.text, args: append([]*twigNode{left}, args...)}
			}
		case "?", "?:":
			yes := left
			if op == "?" && !p.take(":") {
				yes = p.expression(0)
				p.need(":")
			}
			no := p.expression(0)
			left = &twigNode{kind: "choice", args: []*twigNode{yes, no}}
		case "??":
			left = &twigNode{kind: "choice", args: []*twigNode{left, p.expression(prec - 1)}}
		case "~":
			left = &twigNode{kind: "concat", args: []*twigNode{left, p.expression(prec)}}
		case "is":
			p.take("not")
			name := p.next()
			if name.kind != "name" {
				p.bad = true
			}
			if name.text == "same" || name.text == "divisible" {
				p.take("as")
				p.take("by")
			}
			if p.take("(") {
				p.sequence(")")
			}
			left = &twigNode{kind: "boolean"}
		default:
			if op == "not" {
				p.need("in")
			}
			if p.expression(prec) == nil {
				p.bad = true
			}
			left = &twigNode{kind: "boolean"}
		}
	}
	return left
}

func (p *twigParser) atom() *twigNode {
	token := p.next()
	if token.kind == "literal" {
		return &twigNode{kind: "literal", text: token.text}
	}
	switch token.text {
	case "true", "false", "null":
		return &twigNode{kind: "literal", text: token.text}
	case "not":
		if p.expression(5) == nil {
			p.bad = true
		}
		return &twigNode{kind: "boolean"}
	case "-":
		number := p.next()
		if number.kind != "literal" {
			p.bad = true
			return nil
		}
		if _, err := strconv.ParseFloat(number.text, 64); err != nil {
			p.bad = true
			return nil
		}
		return &twigNode{kind: "literal", text: "-" + number.text}
	case "(":
		x := p.expression(0)
		p.need(")")
		return x
	case "[":
		return &twigNode{kind: "list", args: p.sequence("]")}
	case "{":
		x := &twigNode{kind: "map"}
		for !p.bad && !p.take("}") {
			key := p.next()
			if key.kind != "name" && key.kind != "literal" {
				p.bad = true
				break
			}
			p.need(":")
			value := p.expression(0)
			x.args = append(x.args, &twigNode{kind: "pair", text: key.text, args: []*twigNode{value}})
			if !p.take(",") {
				p.need("}")
				break
			}
		}
		return x
	}
	if token.kind == "name" {
		if p.take("(") {
			return &twigNode{kind: "function", text: token.text, args: p.sequence(")")}
		}
		return &twigNode{kind: "variable", text: token.text}
	}
	p.bad = true
	return nil
}

func (p *twigParser) sequence(end string) []*twigNode {
	var result []*twigNode
	for !p.bad && !p.take(end) {
		if p.peek().kind == "name" && p.at+1 < len(p.tokens) && p.tokens[p.at+1].text == "=" {
			p.next()
			p.next()
		}
		x := p.expression(0)
		if x == nil {
			p.bad = true
			break
		}
		result = append(result, x)
		if !p.take(",") {
			p.need(end)
			break
		}
	}
	return result
}

type twigResult struct {
	value phpValue
	mode  string
}

func twigLiteral(text string) phpValue {
	return phpValue{constant: true, literals: []phpLiteral{{text: text}}, prefix: text}
}

func (t *twigScope) eval(expr string, at analysis.Evidence) (phpValue, string) {
	p := newTwigParser(expr)
	node := p.expression(0)
	if node == nil || p.bad || p.at != len(p.tokens) {
		gap := analysis.Gap{Kind: "twig_expression_unresolved", Detail: "Twig expression is outside the supported source subset", At: at.Span}
		t.flow.gaps = append(t.flow.gaps, gap)
		return phpValue{unknown: true, gaps: []analysis.Gap{gap}}, "unknown"
	}
	r := t.value(node, at)
	if r.mode == "" {
		r.mode = "auto"
	}
	return r.value, r.mode
}

func (t *twigScope) value(node *twigNode, at analysis.Evidence) twigResult {
	if node == nil {
		return twigResult{value: phpValue{unknown: true}}
	}
	var v phpValue
	switch node.kind {
	case "literal":
		v = twigLiteral(node.text)
	case "variable":
		var ok bool
		v, ok = t.vars[node.text]
		if !ok {
			v.unknown = true
		}
	case "boolean":
		v = twigLiteral("true")
	case "property", "method":
		base := t.value(node.args[0], at).value
		args := t.arguments(node.args[1:], at)
		v = t.property(base, node.text, args, node.kind == "method", at)
	case "choice":
		v = phpJoin(t.value(node.args[0], at).value, t.value(node.args[1], at).value)
	case "concat":
		a, b := t.value(node.args[0], at).value, t.value(node.args[1], at).value
		v = phpCombine(a, b)
		v.prefix = a.prefix
		if a.constant {
			v.prefix += b.prefix
		}
	case "function", "filter":
		return t.apply(node.kind, node.text, t.arguments(node.args, at), at)
	case "list", "map":
		v.fields = map[string]phpValue{}
		for i, child := range node.args {
			key := strconv.Itoa(i)
			if child.kind == "pair" {
				key, child = child.text, child.args[0]
			}
			item := t.value(child, at).value
			v = phpCombine(v, item)
			v.fields[key] = item
		}
	}
	return twigResult{value: v}
}

func (t *twigScope) arguments(nodes []*twigNode, at analysis.Evidence) []phpValue {
	var args []phpValue
	for _, n := range nodes {
		args = append(args, t.value(n, at).value)
	}
	return args
}
