package parse

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type graphqlField struct {
	typ, name string
	args      []string
	evidence  analysis.Evidence
}
type graphqlToken struct {
	text       string
	start, end int
}
type graphqlSDL struct {
	src        []byte
	file, hash string
	base       int
	tokens     []graphqlToken
	pos        int
}

// The SDL reader accepts object/input fields, scalar and enum declarations. It
// deliberately rejects extensions, directives, defaults and executable composition.
// Offsets always refer to the original source, including embedded literal SDL.
func (p *graphqlSDL) evidence(start, end int) analysis.Evidence {
	a, b := p.base+start, p.base+end
	return analysis.Evidence{Kind: "graphql_schema_field", Text: string(p.src[a:b]), SHA256: p.hash, Span: analysis.Span{File: p.file, StartByte: a, EndByte: b, StartLine: strings.Count(string(p.src[:a]), "\n") + 1, EndLine: strings.Count(string(p.src[:b]), "\n") + 1}}
}
func graphqlName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (p *graphqlSDL) lex(text string) error {
	for i := 0; i < len(text); {
		c := text[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' {
			i++
			continue
		}
		if c == '#' {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			continue
		}
		start := i
		i++
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			for i < len(text) && (text[i] == '_' || text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z' || text[i] >= '0' && text[i] <= '9') {
				i++
			}
		} else if !strings.ContainsRune("{}():![]", rune(c)) {
			return fmt.Errorf("unsupported SDL token at byte %d", start)
		}
		p.tokens = append(p.tokens, graphqlToken{text[start:i], start, i})
		if len(p.tokens) > 32768 {
			return fmt.Errorf("SDL token limit 32768 reached; remainder unexpanded")
		}
	}
	return nil
}
func (p *graphqlSDL) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos].text
}
func (p *graphqlSDL) take(s string) bool {
	if p.peek() != s {
		return false
	}
	p.pos++
	return true
}
func (p *graphqlSDL) name() string {
	s := p.peek()
	if !graphqlName(s) {
		return ""
	}
	p.pos++
	return s
}
func (p *graphqlSDL) fieldType(depth int) bool {
	if depth >= 16 {
		return false
	}
	if p.take("[") {
		if !p.fieldType(depth+1) || !p.take("]") {
			return false
		}
	} else if p.name() == "" {
		return false
	}
	p.take("!")
	return true
}
func (p *graphqlSDL) read(text string) ([]graphqlField, error) {
	if err := p.lex(text); err != nil {
		return nil, err
	}
	var fields []graphqlField
	seen := map[string]bool{}
	for p.peek() != "" {
		kind := p.name()
		typ := p.name()
		if typ == "" {
			return fields, fmt.Errorf("missing SDL type name")
		}
		if seen[typ] {
			return fields, fmt.Errorf("duplicate/composed SDL type %s", typ)
		}
		seen[typ] = true
		switch kind {
		case "scalar":
			continue
		case "enum":
			if !p.take("{") {
				return fields, fmt.Errorf("unsupported enum %s", typ)
			}
			count := 0
			for p.name() != "" {
				count++
			}
			if count == 0 || !p.take("}") {
				return fields, fmt.Errorf("unsupported enum body %s", typ)
			}
			continue
		case "type", "input":
		default:
			return fields, fmt.Errorf("unsupported SDL declaration %s", kind)
		}
		if !p.take("{") {
			return fields, fmt.Errorf("unsupported SDL type header %s", typ)
		}
		fieldNames := map[string]bool{}
		count := 0
		for p.peek() != "}" && p.peek() != "" {
			start := p.tokens[p.pos].start
			name := p.name()
			if name == "" || fieldNames[name] {
				return fields, fmt.Errorf("unsupported/duplicate field in %s", typ)
			}
			fieldNames[name] = true
			count++
			var args []string
			if p.take("(") {
				argNames := map[string]bool{}
				for p.peek() != ")" && p.peek() != "" {
					arg := p.name()
					if arg == "" || argNames[arg] || !p.take(":") || !p.fieldType(0) {
						return fields, fmt.Errorf("unsupported argument on %s.%s", typ, name)
					}
					argNames[arg] = true
					args = append(args, arg)
				}
				if len(args) == 0 || !p.take(")") {
					return fields, fmt.Errorf("invalid arguments")
				}
			}
			if !p.take(":") || !p.fieldType(0) {
				return fields, fmt.Errorf("unsupported field type %s.%s", typ, name)
			}
			if kind == "type" {
				fields = append(fields, graphqlField{typ, name, args, p.evidence(start, p.tokens[p.pos-1].end)})
			}
			if len(fields) > 4096 {
				return fields, fmt.Errorf("SDL field limit 4096 reached; remainder unexpanded")
			}
		}
		if count == 0 || !p.take("}") {
			return fields, fmt.Errorf("unterminated/empty SDL type %s", typ)
		}
	}
	if len(fields) == 0 {
		return fields, fmt.Errorf("no supported SDL object fields")
	}
	return fields, nil
}

func (s *moduleSet) graphqlSchema(m *sourceModule, n *sitter.Node) ([]graphqlField, []analysis.Gap) {
	at := m.evidence("graphql_schema", m.tree.RootNode())
	if n != nil {
		at = m.evidence("graphql_schema", n)
	}
	fail := func(detail string) ([]graphqlField, []analysis.Gap) {
		return nil, []analysis.Gap{{Kind: "graphql_schema_unresolved", Detail: detail, At: at.Span}}
	}
	if n == nil {
		return fail("Missing literal typeDefs")
	}
	if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
		name := n.Utf8Text(m.src)
		if graphqlShadowed(n, name, m.src) {
			return fail("SDL binding is shadowed")
		}
		if bindingReassigned(m, name) {
			return fail("Mutable typeDefs binding")
		}
		if imp, ok := m.imports[name]; ok && imp.name == "default" && strings.HasSuffix(imp.module, ".graphql") {
			file := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(m.file), imp.module)))
			if !strings.HasPrefix(imp.module, ".") || file == ".." || strings.HasPrefix(file, "../") {
				return fail("Local SDL path escapes selected root")
			}
			full := filepath.Join(s.root, filepath.FromSlash(file))
			real, err := filepath.EvalSymlinks(full)
			if err != nil {
				return fail("Local SDL unavailable")
			}
			root, err := filepath.EvalSymlinks(s.root)
			if err != nil {
				return fail("Selected root unavailable")
			}
			rel, err := filepath.Rel(root, real)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fail("Local SDL symlink escapes selected root")
			}
			info, err := os.Stat(real)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
				return fail("Local SDL exceeds 2 MiB or is not regular")
			}
			src, err := os.ReadFile(real)
			if err != nil {
				return fail("Local SDL read failed")
			}
			p := graphqlSDL{src: src, file: file, hash: fmt.Sprintf("%x", sha256.Sum256(src))}
			fields, err := p.read(string(src))
			s.texts().Add(file, p.evidence(0, len(src)))
			if err != nil {
				return fields, []analysis.Gap{{Kind: "graphql_sdl_unsupported", Detail: err.Error(), At: p.evidence(0, len(src)).Span}}
			}
			return fields, nil
		}
		n = browserLocalValue(m, n)
	}
	if n == nil || (n.Kind() != "template_string" && n.Kind() != "string") {
		return fail("typeDefs is not literal SDL or a local .graphql import")
	}
	text := n.Utf8Text(m.src)
	if len(text) < 2 || strings.Contains(text, "\\") {
		return fail("Escaped SDL literal is unsupported")
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "template_substitution" {
			return fail("Interpolated SDL composition is unsupported")
		}
	}
	p := graphqlSDL{src: m.src, file: m.file, hash: m.hash, base: int(n.StartByte()) + 1}
	fields, err := p.read(text[1 : len(text)-1])
	if err != nil {
		return fields, []analysis.Gap{{Kind: "graphql_sdl_unsupported", Detail: err.Error(), At: at.Span}}
	}
	return fields, nil
}
