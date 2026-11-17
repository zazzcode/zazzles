package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// phpPathOps maps D-8 filesystem operations to their operand slot layout.
// move_uploaded_file's first operand ($_FILES tmp_name) is server-managed and
// never a request path source; the destination argument is the path operand.
func phpPathSlots(op string) []string {
	switch op {
	case "move_uploaded_file":
		return []string{"uploaded_tmp_name", "destination_path"}
	case "file_put_contents":
		return []string{"path", "data"}
	case "fopen":
		return []string{"path", "mode"}
	case "unlink", "readfile", "file", "file_get_contents":
		return []string{"path"}
	default: // include/require(_once)
		return []string{"path"}
	}
}

// phpPathRole maps an operation to read/write/execute/delete.
func phpPathRole(op string) string {
	switch op {
	case "file_put_contents", "move_uploaded_file":
		return "write"
	case "unlink":
		return "delete"
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression", "include", "require", "include_once", "require_once":
		return "execute"
	default:
		return "read"
	}
}

// pathUse records a path_traversal_candidate for a verified filesystem
// operation. include operands carry a file_inclusion execution-context fact.
func (f *phpFlow) pathUse(n *sitter.Node, op string, nodes []*sitter.Node, values []phpValue, contract, role string) {
	m := f.module
	slots := phpPathSlots(op)
	if role == "" {
		role = phpPathRole(op)
	}
	facts := &analysis.PathFacts{Operation: op, ContractID: contract, Platform: "posix", Role: role, Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}
	var context []analysis.Evidence
	var deps []phpDep
	request := false
	for i, slot := range slots {
		var v phpValue
		if i < len(values) {
			v = values[i]
		}
		o := analysis.PathOperand{Slot: slot}
		if i < len(nodes) {
			if text, ok := phpStringLiteral(m, nodes[i]); ok {
				o.Constant = text
			} else {
				o.Dynamic = true
			}
		}
		o.Context = append(o.Context, len(context))
		context = append(context, m.evidence("path_operand", iOrFallback(i, nodes, n)))
		for _, d := range v.deps {
			if slot == "uploaded_tmp_name" || slot == "data" || slot == "mode" {
				// Server-managed upload tmp names and written data are not path
				// sources; keep the dependency visible without a path claim.
				o.Dependencies = append(o.Dependencies, len(deps))
				deps = append(deps, d)
				continue
			}
			d.dep.SinkSlot = slot
			o.Dependencies = append(o.Dependencies, len(deps))
			protection, transforms, guard := "raw", phpPathTransforms(d), -1
			switch d.protection {
			case "component":
				protection = "guarded"
				guard = len(facts.Guards)
				facts.Guards = append(facts.Guards, analysis.PathGuard{Context: len(context) - 1, Kind: analysis.PathGuardComponentSanitizer})
			case "resolved":
				// realpath alone is not containment; the resolved value still
				// needs a boundary check before the operation.
				transforms = append(transforms, "realpath")
				protection = "raw"
			case "numeric", "non_content":
				protection = "guarded"
				guard = len(facts.Guards)
				facts.Guards = append(facts.Guards, analysis.PathGuard{Context: len(context) - 1, Kind: analysis.PathGuardPresenceOrType})
			case "unknown":
				protection = "unknown"
			}
			flow := analysis.PathFlow{Dependency: len(deps), Operand: slot, Protection: protection, Transforms: transforms}
			if guard >= 0 {
				flow.Controls = append(flow.Controls, guard)
			}
			facts.Paths = append(facts.Paths, flow)
			deps = append(deps, d)
			request = true
		}
		facts.Operands = append(facts.Operands, o)
	}
	if !request {
		return
	}
	u := f.addUse("path_traversal_candidate", n, phpValue{deps: deps})
	u.Path = facts
	u.APIModel = analysispacks.PathContract(contract)
	u.Context = append(u.Context, context...)
	u.Context = append(u.Context, m.evidence("sink_binding", phpCallee(n)))
	if role == "execute" {
		u.Gaps = append(u.Gaps, f.gap("file_inclusion", "include/require executes the resolved path (CWE-98 execution context)", n))
	}
	c := &analysis.Completeness{ClaimKind: "path", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "path_operands"}, Evidence: map[string][]analysis.Evidence{
		"sink_binding":     {m.evidence("sink_binding", phpCallee(n))},
		"invoked_callable": {f.entryEvidence()},
		"path_operands":    context,
		"control_flow":     append([]analysis.Evidence{m.evidence("operation", n)}, f.context...),
	}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "Bounded PHP source-to-file-operation flow; only the file-path operand is the claim."}
	for _, g := range append(append([]analysis.Gap{}, f.gaps...), u.Gaps...) {
		switch g.Kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			c.Blockers = append(c.Blockers, g)
		}
	}
	for _, d := range deps {
		if d.dep.Source.Kind == "input_source" || d.dep.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.dep.Source)
		}
	}
	u.Completeness = c
}

func iOrFallback(i int, nodes []*sitter.Node, fallback *sitter.Node) *sitter.Node {
	if i < len(nodes) {
		return nodes[i]
	}
	return fallback
}

func phpPathTransforms(d phpDep) []string {
	var out []string
	for _, t := range d.dep.Transfers {
		switch t.Kind {
		case "path_transform":
			out = append(out, "transform:"+t.Text)
		}
	}
	return out
}
