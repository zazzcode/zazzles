package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pathLayoutValue projects only the effective layout option, preserving spread
// order. Closed objects without layout cannot overwrite a previous layout.
func (f *flow) pathLayoutValue(options *sitter.Node) (value, *sitter.Node, bool) {
	if options == nil {
		return value{}, nil, false
	}
	if options.Kind() != "object" {
		v := f.quiet(options)
		if field, ok := v.fields["layout"]; ok {
			return field, options, true
		}
		if v.pathObjectClosed {
			return value{}, nil, false
		}
		return f.transfer(v, "layout_projection", options), options, len(v.deps) > 0
	}
	var result value
	var operand *sitter.Node
	found := false
	for i := uint(0); i < options.NamedChildCount(); i++ {
		p := options.NamedChild(i)
		if p.Kind() == "shorthand_property_identifier" && p.Utf8Text(f.module.src) == "layout" {
			result, operand, found = f.quiet(p), p, true
			continue
		}
		if p.Kind() == "spread_element" && p.NamedChildCount() == 1 {
			source := p.NamedChild(0)
			v := f.quiet(source)
			if field, ok := v.fields["layout"]; ok {
				result, operand, found = field, source, true
				continue
			}
			if v.pathObjectClosed {
				continue
			}
			if len(v.deps) > 0 {
				result, operand, found = f.transfer(v, "layout_projection", p), source, true
			} else if found {
				result.gaps = append(result.gaps, f.gap("unknown_transfer", "later options spread may override layout", p))
			}
			continue
		}
		key := p.ChildByFieldName("key")
		child := p.ChildByFieldName("value")
		if key != nil && child != nil && strings.Trim(key.Utf8Text(f.module.src), "\"'") == "layout" {
			result, operand, found = f.quiet(child), child, true
		}
	}
	return result, operand, found
}

func (f *flow) pathRenderCall(call, fn, args *sitter.Node) bool {
	if !f.pathOnly {
		return false
	}
	if fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() < 2 {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || prop.Utf8Text(f.module.src) != "render" || obj.Kind() != "identifier" || obj.Utf8Text(f.module.src) != f.response {
		return false
	}
	engine, _, config := f.renderSettings()
	if engine != "hbs" || f.set.packageVersion("hbs") == "" {
		return false
	}
	// A custom renderer registered under the extension does not inherit hbs semantics.
	ambiguous := false
	if f.registration != nil {
		walkCalls(f.registration.tree.RootNode(), func(n *sitter.Node) {
			a := n.ChildByFieldName("arguments")
			c := n.ChildByFieldName("function")
			if c == nil || a == nil || a.NamedChildCount() < 2 || c.Kind() != "member_expression" {
				return
			}
			o, p := c.ChildByFieldName("object"), c.ChildByFieldName("property")
			if o == nil || p == nil || !f.registration.receivers[o.Utf8Text(f.registration.src)] {
				return
			}
			if p.Utf8Text(f.registration.src) == "engine" {
				if ext, ok := stringLiteral(a.NamedChild(0), f.registration.src); !ok || ext == "hbs" {
					ambiguous = true
				}
			}
			if p.Utf8Text(f.registration.src) == "set" {
				if key, _ := stringLiteral(a.NamedChild(0), f.registration.src); key == "view engine" {
					if e, ok := stringLiteral(a.NamedChild(1), f.registration.src); !ok || e != "hbs" {
						ambiguous = true
					}
				}
			}
		})
	}
	if ambiguous {
		return false
	}
	v, n, found := f.pathLayoutValue(args.NamedChild(1))
	if !found || n == nil {
		return true
	}
	b := &jsPathBuilder{f: f, facts: &analysis.PathFacts{Operation: "hbs.render.layout", ContractID: analysispacks.HbsLayoutContract, Platform: "posix", Role: "read", Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}}
	b.operand(analysis.PathSlotFile, "path_operand", n, v)
	if !b.request {
		return true
	}
	context := append([]analysis.Evidence{}, f.context...)
	for _, e := range config {
		e.Kind = "sink_binding"
		context = append(context, e)
	}
	context = append(context, f.module.evidence("sink_binding", fn))
	shift := len(context)
	context = append(context, b.context...)
	for i := range b.facts.Operands {
		for j := range b.facts.Operands[i].Context {
			b.facts.Operands[i].Context[j] += shift
		}
	}
	f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, call.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: "path_traversal_candidate", Sink: f.module.evidence("path_traversal_candidate", call), Dependencies: b.deps, Context: context, Gaps: append(append([]analysis.Gap{}, f.gaps...), b.gaps...), Path: b.facts, APIModel: analysispacks.PathContract(analysispacks.HbsLayoutContract), Assessment: analysis.Assessment{Status: "not_run"}})
	return true
}
