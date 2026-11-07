package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// mongoosePathIDFacts selects sink semantics independently of transport or
// framework. Source acquisition and value constraints live in InputFacts.
func (s *moduleSet) mongoosePathIDFacts(use *analysis.CandidateUse) {
	c := use.Completeness
	if use.APIModel == nil || use.APIModel.ID != "mongoose-model-query-v2" || c == nil || !s.defaultObjectIDSchema(c) {
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
	if fn == nil || args == nil || args.NamedChildCount() == 0 {
		return
	}
	prop, model := fn.ChildByFieldName("property"), fn.ChildByFieldName("object")
	if prop == nil || prop.Utf8Text(m.src) != "findById" || model == nil || model.Kind() != "identifier" || !contractBindingStable(m, model.Utf8Text(m.src)) {
		return
	}
	use.APIModel = analysispacks.NoSQLContract("mongoose-find-by-id-objectid-v1")
	if ctx := s.nodeHTTP[use.EntryID]; ctx != nil {
		s.nodeInputFacts(use, ctx)
	}
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
