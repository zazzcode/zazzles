package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// zodHelper is a verified request-validation helper summary: a resolved
// function whose schema parameter's safeParse/parse result data is what it
// returns. Its effect on the value is a model question; the summary only says
// where the data comes from and which schema the source declares.
type zodHelper struct {
	module    *sourceModule
	fn        *sitter.Node
	parse     *sitter.Node // the schema.safeParse(...) / schema.parse(...) call
	reader    *sitter.Node // request.text()/json()/formData() inside the helper
	readerOp  string
	inputIdx  int
	schemaIdx int
	checked   bool // the helper guards result.success before returning data
}

var zodParseMethods = map[string]bool{"safeParse": true, "safeParseAsync": true, "parse": true, "parseAsync": true}

// zodHelperSummary verifies the shape of a validation helper. It needs a schema
// parameter whose parse method is called and a return of that call's `.data`
// (safeParse) or of the parse result itself.
func (s *moduleSet) zodHelperSummary(hm *sourceModule, fn *sitter.Node) (zodHelper, bool) {
	h := zodHelper{module: hm, fn: fn, inputIdx: 0, schemaIdx: -1}
	params, ok := functionParameters(fn, hm.src)
	if !ok || len(params) < 2 {
		return h, false
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return h, false
	}
	resultName := ""
	walkCalls(body, func(call *sitter.Node) {
		callee := call.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "member_expression" {
			return
		}
		obj, prop := callee.ChildByFieldName("object"), callee.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" {
			return
		}
		for i, p := range params {
			if obj.Utf8Text(hm.src) == p.name && zodParseMethods[prop.Utf8Text(hm.src)] && h.parse == nil {
				h.parse, h.schemaIdx = call, i
				parent := call.Parent()
				if parent != nil && parent.Kind() == "await_expression" {
					parent = parent.Parent()
				}
				if parent != nil && parent.Kind() == "variable_declarator" {
					if id := parent.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
						resultName = id.Utf8Text(hm.src)
					}
				}
			}
			if i == 0 && obj.Utf8Text(hm.src) == p.name {
				switch prop.Utf8Text(hm.src) {
				case "text", "json", "formData":
					h.reader, h.readerOp = call, prop.Utf8Text(hm.src)
				}
			}
		}
	})
	if h.parse == nil || h.schemaIdx == 0 || resultName == "" {
		return h, false
	}
	// The returned data must be the parse result's data.
	returnsData := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "return_statement" && n.NamedChildCount() == 1 {
			r := unwrapTS(n.NamedChild(0))
			if r.Kind() == "object" {
				if d := property(r, "data", hm.src); d != nil && strings.TrimSpace(d.Utf8Text(hm.src)) == resultName+".data" {
					returnsData = true
				}
			}
		}
		if n.Kind() == "if_statement" {
			if c := n.ChildByFieldName("condition"); c != nil && strings.Contains(c.Utf8Text(hm.src), resultName+".success") {
				h.checked = true
			}
		}
		if isFunction(n) && n != fn {
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(body)
	return h, returnsData
}

// validationHelperCall applies a verified helper summary at a call site. The
// result depends on the request part passed in (or the body the helper reads
// from the request), with the schema definition and parse call as validation
// evidence for the model. It never marks a value safe.
func (f *flow) validationHelperCall(n *sitter.Node, values []value) (value, bool) {
	if f.set == nil || f.web == nil {
		return value{}, false
	}
	hm, fn := f.set.resolveCall(f.module, n)
	if hm == nil || fn == nil || !supportedCallee(fn) {
		return value{}, false
	}
	h, ok := f.set.zodHelperSummary(hm, fn)
	if !ok || h.inputIdx >= len(values) || h.schemaIdx >= len(values) {
		return value{}, false
	}
	args := n.ChildByFieldName("arguments")
	input := values[h.inputIdx]
	var data value
	switch {
	case input.web == "request" && h.reader != nil:
		// The helper reads the body itself: the source is that read.
		source := hm.evidence("input_source", h.reader)
		f.rememberInput(source)
		f.set.recordWebOrigin(source, webOrigin{origin: "http.body", initialType: map[string]string{"text": "string", "json": "unknown", "formData": "FormData"}[h.readerOp]})
		data = value{deps: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{}}}}
	case len(input.deps) > 0:
		data = input
	default:
		return value{}, false
	}
	f.context = append(f.context, hm.evidence("helper_definition", fn), hm.evidence("validation_control", h.parse))
	if args != nil && int(args.NamedChildCount()) > h.schemaIdx {
		f.context = append(f.context, f.set.schemaEvidence(f.module, args.NamedChild(uint(h.schemaIdx)))...)
	}
	out := f.transfer(data, "validated_parse", n)
	out.web = ""
	return out, true
}

// schemaEvidence returns the declaration of a schema argument, through one
// named import.
func (s *moduleSet) schemaEvidence(m *sourceModule, arg *sitter.Node) []analysis.Evidence {
	arg = unwrapTS(arg)
	if arg == nil || arg.Kind() != "identifier" {
		return nil
	}
	name := arg.Utf8Text(m.src)
	target, local := m, name
	if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
		if imp.name == "*" || imp.name == "default" {
			return nil
		}
		d, l, _ := s.namedExport(m, imp.module, imp.name, 0)
		if d == nil {
			return nil
		}
		target, local = d, l
	}
	v := topVariable(target, local)
	if v == nil {
		return nil
	}
	decl := v
	if p := v.Parent(); p != nil && p.Kind() == "variable_declarator" {
		decl = p
	}
	return []analysis.Evidence{target.evidence("validation_schema", decl)}
}
