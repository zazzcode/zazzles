package langjs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type grpcMethod struct {
	pkg, service, name, request, response string
	clientStream, serverStream            bool
	evidence                              analysis.Evidence
	fields                                []string
	messages                              []analysis.Evidence
}
type grpcProtoReader struct {
	src        []byte
	file, hash string
	tokens     []graphqlToken
	pos        int
}
type grpcProtoResult struct {
	methods []grpcMethod
	gaps    []analysis.Gap
}

func (p *grpcProtoReader) evidence(start, end int) analysis.Evidence {
	return analysis.Evidence{Kind: "grpc_proto_method", Text: string(p.src[start:end]), SHA256: p.hash, Span: analysis.Span{File: p.file, StartByte: start, EndByte: end, StartLine: strings.Count(string(p.src[:start]), "\n") + 1, EndLine: strings.Count(string(p.src[:end]), "\n") + 1}}
}
func (p *grpcProtoReader) lex() error {
	text := string(p.src)
	for i := 0; i < len(text); {
		c := text[i]
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			i++
			continue
		}
		if strings.HasPrefix(text[i:], "//") {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			continue
		}
		if strings.HasPrefix(text[i:], "/*") {
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return fmt.Errorf("unterminated proto comment at %d", i)
			}
			i += end + 4
			continue
		}
		start := i
		i++
		switch {
		case c == '"' || c == '\'':
			for i < len(text) && text[i] != c {
				if text[i] == '\\' {
					return fmt.Errorf("escaped proto literal unsupported at %d", i)
				}
				i++
			}
			if i == len(text) {
				return fmt.Errorf("unterminated proto string at %d", start)
			}
			i++
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			for i < len(text) && (text[i] == '_' || text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z' || text[i] >= '0' && text[i] <= '9') {
				i++
			}
		case strings.ContainsRune("{}();=.", rune(c)):
		default:
			return fmt.Errorf("unsupported proto token at byte %d", start)
		}
		p.tokens = append(p.tokens, graphqlToken{text[start:i], start, i})
		if len(p.tokens) > 32768 {
			return fmt.Errorf("proto token limit 32768 reached; remainder unexpanded")
		}
	}
	return nil
}
func (p *grpcProtoReader) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos].text
}
func (p *grpcProtoReader) take(s string) bool {
	if p.peek() != s {
		return false
	}
	p.pos++
	return true
}
func (p *grpcProtoReader) name() string {
	s := p.peek()
	if !graphqlName(s) {
		return ""
	}
	p.pos++
	return s
}
func (p *grpcProtoReader) qualified() string {
	prefix := ""
	if p.take(".") {
		prefix = "."
	}
	n := p.name()
	if n == "" {
		return ""
	}
	prefix += n
	for p.take(".") {
		n = p.name()
		if n == "" {
			return ""
		}
		prefix += "." + n
	}
	return prefix
}

// This reader rejects composition and options instead of silently inferring runtime semantics.
func (p *grpcProtoReader) read() ([]grpcMethod, error) {
	if err := p.lex(); err != nil {
		return nil, err
	}
	if !p.take("syntax") || !p.take("=") || !(p.take(`"proto3"`) || p.take(`'proto3'`)) || !p.take(";") {
		return nil, fmt.Errorf("literal proto3 syntax declaration required")
	}
	pkg := ""
	if p.take("package") {
		pkg = p.qualified()
		if pkg == "" || strings.HasPrefix(pkg, ".") || !p.take(";") {
			return nil, fmt.Errorf("invalid package")
		}
	}
	messages := map[string][]string{}
	messageEvidence := map[string]analysis.Evidence{}
	var fieldTypes []string
	seen := map[string]bool{}
	var methods []grpcMethod
	for p.peek() != "" {
		start := p.pos
		kind := p.name()
		name := p.name()
		if name == "" || seen[name] {
			return methods, fmt.Errorf("unsupported/duplicate proto declaration %s", kind)
		}
		seen[name] = true
		if !p.take("{") {
			return methods, fmt.Errorf("unsupported %s header", kind)
		}
		switch kind {
		case "message":
			fields := []string{}
			names := map[string]bool{}
			numbers := map[int]bool{}
			for p.peek() != "}" && p.peek() != "" {
				if !p.take("optional") {
					p.take("repeated")
				}
				typ := p.qualified()
				field := p.name()
				if typ == "" || field == "" || names[field] || !p.take("=") {
					return methods, fmt.Errorf("unsupported message %s field", name)
				}
				fieldTypes = append(fieldTypes, typ)
				num, err := strconv.Atoi(p.peek())
				if err != nil || num <= 0 || num > 536870911 || num >= 19000 && num <= 19999 || numbers[num] {
					return methods, fmt.Errorf("invalid message field number")
				}
				p.pos++
				if !p.take(";") {
					return methods, fmt.Errorf("message options/nesting unsupported")
				}
				names[field] = true
				numbers[num] = true
				fields = append(fields, field)
			}
			messages[name] = fields
		case "service":
			names := map[string]bool{}
			for p.peek() != "}" && p.peek() != "" {
				start := p.pos
				if !p.take("rpc") {
					return methods, fmt.Errorf("unsupported service member")
				}
				method := p.name()
				if method == "" || names[method] || !p.take("(") {
					return methods, fmt.Errorf("invalid/duplicate rpc")
				}
				names[method] = true
				cs := p.take("stream")
				req := p.qualified()
				if req == "" || !p.take(")") || !p.take("returns") || !p.take("(") {
					return methods, fmt.Errorf("invalid rpc request")
				}
				ss := p.take("stream")
				resp := p.qualified()
				if resp == "" || !p.take(")") || !p.take(";") {
					return methods, fmt.Errorf("invalid rpc response/options")
				}
				methods = append(methods, grpcMethod{pkg: pkg, service: name, name: method, request: req, response: resp, clientStream: cs, serverStream: ss, evidence: p.evidence(p.tokens[start].start, p.tokens[p.pos-1].end)})
				if len(methods) > 4096 {
					return methods, fmt.Errorf("proto method limit 4096 reached; remainder unexpanded")
				}
			}
		default:
			return methods, fmt.Errorf("unsupported proto declaration %s", kind)
		}
		if !p.take("}") {
			return methods, fmt.Errorf("unterminated %s", kind)
		}
		if kind == "message" {
			e := p.evidence(p.tokens[start].start, p.tokens[p.pos-1].end)
			e.Kind = "grpc_proto_message"
			messageEvidence[name] = e
		}
	}
	for _, typ := range fieldTypes {
		switch typ {
		case "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes":
			continue
		}
		typ = strings.TrimPrefix(typ, ".")
		if pkg != "" {
			typ = strings.TrimPrefix(typ, pkg+".")
		}
		if _, ok := messages[typ]; !ok {
			return methods, fmt.Errorf("message field type missing or imported")
		}
	}
	for i := range methods {
		resolve := func(name string) ([]string, bool) {
			name = strings.TrimPrefix(name, ".")
			if pkg != "" {
				name = strings.TrimPrefix(name, pkg+".")
			}
			fields, ok := messages[name]
			return fields, ok
		}
		fields, ok := resolve(methods[i].request)
		_, responseOK := resolve(methods[i].response)
		if !ok || !responseOK {
			return methods, fmt.Errorf("rpc message type missing or imported")
		}
		methods[i].fields = fields
		for _, typ := range []string{methods[i].request, methods[i].response} {
			typ = strings.TrimPrefix(typ, ".")
			if pkg != "" {
				typ = strings.TrimPrefix(typ, pkg+".")
			}
			methods[i].messages = append(methods[i].messages, messageEvidence[typ])
		}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no proto service methods")
	}
	return methods, nil
}
func (s *moduleSet) grpcProto(path string, at analysis.Span) grpcProtoResult {
	fail := func(detail string) grpcProtoResult {
		return grpcProtoResult{gaps: []analysis.Gap{{Kind: "grpc_proto_unresolved", Detail: detail, At: at}}}
	}
	// Literal loadSync paths are interpreted under the selected root (the assumed process cwd).
	file := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) || file == ".." || strings.HasPrefix(file, "../") || filepath.Ext(file) != ".proto" {
		return fail("Proto path must be a local .proto inside the selected root")
	}
	if result, ok := s.grpcProtos[file]; ok {
		return result
	}
	real, err := filepath.EvalSymlinks(filepath.Join(s.root, filepath.FromSlash(file)))
	if err != nil {
		return fail("Local proto unavailable; generated stubs are unsupported")
	}
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return fail("Selected root unavailable")
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fail("Proto symlink escapes selected root")
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return fail("Proto exceeds 2 MiB or is not regular")
	}
	src, err := os.ReadFile(real)
	if err != nil {
		return fail("Proto read failed")
	}
	p := grpcProtoReader{src: src, file: file, hash: fmt.Sprintf("%x", sha256.Sum256(src))}
	methods, err := p.read()
	result := grpcProtoResult{methods: methods}
	if err != nil {
		result.gaps = []analysis.Gap{{Kind: "grpc_proto_unsupported", Detail: err.Error(), At: p.evidence(0, len(src)).Span}}
	}
	s.texts().Add(file, p.evidence(0, len(src)))
	if s.grpcProtos == nil {
		s.grpcProtos = map[string]grpcProtoResult{}
	}
	s.grpcProtos[file] = result
	return result
}
