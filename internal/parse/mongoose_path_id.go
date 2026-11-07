package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// mongoosePathIDFacts selects a narrower operation contract only when the
// actual findById argument retains Express's primitive path-parameter type.
// It supplies evidence, never a verdict or an inherited historical answer.
func (s *moduleSet) mongoosePathIDFacts(use *analysis.CandidateUse) {
	c := use.Completeness
	if use.APIModel == nil || use.APIModel.ID != "mongoose-model-query-v2" || c == nil || len(c.Blockers) != 0 || len(use.Dependencies) != 1 || use.Check == nil || use.Check.Selector != nil {
		return
	}
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return
	}
	call := nodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() == 0 || args.NamedChildCount() > 2 {
		return
	}
	prop := fn.ChildByFieldName("property")
	model := fn.ChildByFieldName("object")
	if prop == nil || prop.Utf8Text(m.src) != "findById" || model == nil || model.Kind() != "identifier" || !contractBindingStable(m, model.Utf8Text(m.src)) {
		return
	}
	if args.NamedChildCount() == 2 && !isFunction(args.NamedChild(1)) {
		return
	}
	arg := args.NamedChild(0)
	if arg.Kind() != "member_expression" {
		return
	}
	params, key := arg.ChildByFieldName("object"), arg.ChildByFieldName("property")
	if params == nil || key == nil || params.Kind() != "member_expression" {
		return
	}
	req, field := params.ChildByFieldName("object"), params.ChildByFieldName("property")
	if req == nil || req.Kind() != "identifier" || field == nil || field.Utf8Text(m.src) != "params" {
		return
	}
	if use.Dependencies[0].Source.Text != arg.Utf8Text(m.src) {
		return
	}
	named := false
	for _, segment := range strings.Split(use.Check.Path, "/") {
		named = named || segment == ":"+key.Utf8Text(m.src)
	}
	if !named || !s.defaultObjectIDSchema(c) {
		return
	}
	// Every supplied application handler/middleware must preserve the request
	// object and its params. Unknown chains were rejected by completeness above.
	handler := false
	for _, e := range use.Context {
		if e.Kind == "route_registration" {
			module := s.modules[e.Span.File]
			if module == nil || hasParamRegistration(module) {
				return
			}
		}
		if e.Kind != "handler" && e.Kind != "middleware_handler" {
			continue
		}
		module := s.modules[e.Span.File]
		if module == nil {
			return
		}
		body := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if body == nil {
			return
		}
		owner := body.Parent()
		if owner == nil || !isFunction(owner) {
			return
		}
		parameters := parameterNames(owner, module.src)
		if len(parameters) == 0 || !requestParamsStable(module, body, parameters[0]) {
			return
		}
		if e.Kind == "handler" && e.Span.File == m.file && body.StartByte() <= call.StartByte() && body.EndByte() >= call.EndByte() && parameters[0] == req.Utf8Text(m.src) {
			handler = true
		}
	}
	if !handler {
		return
	}
	e := m.evidence("selector_path_string", arg)
	c.Evidence[e.Kind] = append(c.Evidence[e.Kind], e)
	use.Context = append(use.Context, e)
	c.Required = append(c.Required, e.Kind)
	c.ModelFacts = append(c.ModelFacts, "The exact findById input "+arg.Utf8Text(m.src)+" is the named URL segment in "+use.Check.Path+". It retains Express's decoded primitive string type in the supplied handler/middleware slice; no request/params write or object escape is modeled on this path. It remains externally controlled data, not an object-valued selector. Apply only the selected operation contract to this argument; authorization and business validation are separate.")
	use.APIModel = analysispacks.NoSQLContract("mongoose-path-id-objectid-v1")
}

// app.param callbacks run before route handlers and can replace a captured
// string. They are outside this bounded contract even when their body is known.
func hasParamRegistration(m *sourceModule) bool {
	found := false
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "member_expression" {
			if prop := fn.ChildByFieldName("property"); prop != nil && prop.Utf8Text(m.src) == "param" {
				found = true
			}
		}
	})
	return found
}

// Only the one-argument literal schema constructor with no explicit _id has
// the default ObjectId path. Options, spreads and custom IDs stay conservative.
func (s *moduleSet) defaultObjectIDSchema(c *analysis.Completeness) bool {
	if len(c.Evidence["model_schema"]) != 1 {
		return false
	}
	e := c.Evidence["model_schema"][0]
	m := s.modules[e.Span.File]
	if m == nil {
		return false
	}
	n := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
	if n == nil {
		return false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 || args.NamedChild(0).Kind() != "object" {
		return false
	}
	props, ok := jsOptions(m, args.NamedChild(0))
	return ok && props["_id"] == nil
}

// Reject writes and escapes of the request/params containers, including aliases
// and Object.assign(params,...). Passing a primitive field value is allowed.
func requestParamsStable(m *sourceModule, body *sitter.Node, name string) bool {
	stable := true
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !stable {
			return
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			p := n.Parent()
			if p == nil {
				stable = false
				return
			}
			if p.Kind() != "member_expression" && p.Kind() != "subscript_expression" {
				stable = false
				return
			}
			for p.Parent() != nil && (p.Parent().Kind() == "member_expression" || p.Parent().Kind() == "subscript_expression") {
				p = p.Parent()
			}
			parent := p.Parent()
			if parent == nil {
				stable = false
				return
			}
			switch parent.Kind() {
			case "call_expression":
				if fn := parent.ChildByFieldName("function"); fn != nil && fn.StartByte() == p.StartByte() {
					stable = false // an unmodeled request method can mutate params
				}
			case "assignment_expression", "augmented_assignment_expression":
				left := parent.ChildByFieldName("left")
				if left != nil && left.StartByte() == p.StartByte() {
					stable = false
				}
			case "update_expression", "unary_expression":
				stable = false
			}
			text := p.Utf8Text(m.src)
			if text == name+".params" || strings.HasPrefix(text, name+"[") {
				stable = false
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(body)
	return stable
}
