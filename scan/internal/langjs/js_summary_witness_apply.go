package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// A frame belongs to one concrete caller. The immutable plan retains static
// bindings; native operations retain their exact evaluation/probe order.
type jsWitnessFrame struct{ plan *jsWitnessPlan }

func (f *flow) summaryWitnessCall(call *sitter.Node, hm *sourceModule, helper *sitter.Node, args []value) (value, bool, bool) {
	if f.set == nil || f.helpers == nil || f.client != nil || f.web != nil || f.setterValue != nil {
		return value{}, false, false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || !jsWitnessStableName(f.module, summaryCalleeRoot(fn, f.module.src)) {
		return value{}, false, false
	}
	if name := jsWitnessDeclarationName(helper, hm.src); name != "" && !jsWitnessStableName(hm, name) {
		return value{}, false, false
	}
	plan := f.set.jsWitnessPlan(hm, helper)
	if !plan.supported() || len(args) != len(plan.params) || callHasSpread(call) {
		return value{}, false, false
	}
	return f.instantiateJSWitness(call, plan, args)
}

func (f *flow) instantiateJSWitness(call *sitter.Node, plan *jsWitnessPlan, args []value) (ret value, entered bool, precise bool) {
	if !plan.supported() || len(args) != len(plan.params) {
		return value{}, false, false
	}
	hm, helper := plan.module, plan.fn
	f.context = append(f.context, hm.evidence("helper_definition", helper))
	before := len(f.gaps)
	child := flow{
		client: f.client, registration: f.registration, module: hm, set: f.set,
		entry: f.entry, invocation: f.invocation, env: map[string]value{},
		context: append(append([]analysis.Evidence{}, f.context...), f.module.evidence("helper_call", call)),
		gaps:    append([]analysis.Gap{}, f.gaps...), depth: f.depth + 1,
		helpers: f.helpers, facts: f.facts, web: f.web,
		witness: &jsWitnessFrame{plan: plan},
	}
	for i, p := range plan.params {
		if nodes := call.ChildByFieldName("arguments"); nodes != nil && uint(i) < nodes.NamedChildCount() {
			arg := nodes.NamedChild(uint(i))
			if arg.Kind() == "identifier" {
				name := arg.Utf8Text(f.module.src)
				if f.request != "" && name == f.request {
					child.request = p.name
				}
				if (f.response != "" && name == f.response) || (f.redirectResponse != "" && name == f.redirectResponse) {
					child.redirectResponse = p.name
				}
			}
		}
		child.env[p.name] = child.transfer(args[i], "parameter_binding", p.node)
	}
	for _, stmt := range plan.statements {
		if helper.ChildByFieldName("body").Kind() != "statement_block" {
			child.returns = append(child.returns, child.transfer(child.eval(stmt), "return_value", stmt))
			break
		}
		if child.statement(stmt) {
			break
		}
	}
	f.uses = append(f.uses, child.uses...)
	for _, g := range child.gaps[before:] {
		switch g.Kind {
		case "work_limit", "helper_call_limit", "recursive_helper":
			f.gaps = append(f.gaps, g)
		}
	}
	for _, v := range child.returns {
		ret = combine(ret, v)
	}
	return ret, true, len(child.returns) > 0
}
