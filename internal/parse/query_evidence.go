package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

// refineQueryEvidence separates value/guard evidence assembled for this claim from
// unrelated limits inherited from discovery. Original gaps remain in the report.
func (s *moduleSet) refineQueryEvidence(use *analysis.CandidateUse) {
	c := use.Completeness
	if c == nil || c.ClaimKind != "injection" {
		return
	}
	c.Required = append(c.Required, "control_flow")
	// Missing middleware/helper bodies remain explicit blockers from chain assembly.
	chainSupplied := true
	for _, g := range c.Blockers {
		switch g.Kind {
		case "applicable_middleware_unresolved", "middleware_mount_unresolved", "input_helper_unresolved", "helper_context_limit", "unresolved_factory", "unresolved_handler":
			chainSupplied = false
		}
	}
	if use.Check != nil && use.Check.Selector != nil && use.Check.Selector.Kind == "graphql" {
		c.ModelFacts = []string{"scope_apollo_resolver"}
	} else if use.Check != nil && use.Check.Selector != nil && use.Check.Selector.Kind == "grpc" {
		c.ModelFacts = []string{"scope_grpc_unary"}
	} else if ctx := s.nodeHTTP[use.EntryID]; ctx != nil && ctx.entry.HTTP.Framework != "express" {
		c.ModelFacts = []string{"scope_node_framework: " + ctx.entry.HTTP.Framework}
		// Discovery's generic middleware warning is replaced only by the adapter's
		// explicitly bounded lifecycle context, retaining every adapter gap.
		kept := []analysis.Gap{}
		for _, g := range c.Coverage {
			if g.Kind == "middleware_unresolved" {
				c.Resolved = append(c.Resolved, g)
			} else {
				kept = append(kept, g)
			}
		}
		c.Coverage = kept
	} else if chainSupplied && len(s.contextLimits) == 0 {
		// Fixed interpretation is owned by the guidance fact notes (W6).
		c.ModelFacts = []string{"scope_express_direct"}
		coverage := []analysis.Gap{}
		for _, g := range c.Coverage {
			if g.Kind == "middleware_unresolved" {
				c.Resolved = append(c.Resolved, g)
			} else {
				coverage = append(coverage, g)
			}
		}
		c.Coverage = coverage
	}
	blockers := []analysis.Gap{}
	for _, g := range c.Blockers {
		covered := false
		m := s.modules[g.At.File]
		var n *sitter.Node
		if m != nil {
			n = nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
		}
		switch g.Kind {
		case "helper_call_limit":
			// Discovery's traversal differs from independently assembled input-helper context.
			// Missing relevant helper bodies still block via input_helper/context-limit gaps.
			covered = len(s.contextLimits) == 0 && len(c.Evidence["control_flow"]) > 0
		case "unknown_call_result", "unknown_transfer":
			covered = !gapTouchesSQLSource(g, *use, use.Check.Fields)
			if !covered && nativeStringOperation(m, n) {
				covered = true
				c.Evidence["transformation"] = append(c.Evidence["transformation"], m.evidence("transformation", n))
			}
		case "conditional_merge":
			if n != nil && n.Kind() == "ternary_expression" {
				covered = true
				c.Evidence["conditional_value"] = append(c.Evidence["conditional_value"], m.evidence("conditional_value", n))
			}
		case "unresolved_wrapper":
			// Source presence alone does not prove wrapper transparency.
			covered = false
		}
		if covered {
			c.Coverage = append(c.Coverage, g)
		} else {
			blockers = append(blockers, g)
		}
	}
	for _, e := range c.Evidence["transformation"] {
		module := s.modules[e.Span.File]
		if module == nil {
			continue
		}
		node := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if node == nil {
			continue
		}
		fn := node.ChildByFieldName("function")
		if fn != nil && fn.Utf8Text(module.src) == "Number" && nativeStringOperation(module, node) {
			c.ModelFacts = append(c.ModelFacts, "verified_number_call: "+e.Text+" at "+e.Span.File)
		}
	}
	c.Blockers = blockers
	seenHex := map[analysis.Span]bool{}
	for _, d := range use.Dependencies {
		for _, e := range d.Transfers {
			if e.Kind != "native_hash_hex" || seenHex[e.Span] {
				continue
			}
			seenHex[e.Span] = true
			module := s.modules[e.Span.File]
			if module == nil {
				continue
			}
			n := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			input, evidence := nativeHashHex(module, n)
			if input == nil {
				continue
			}
			for _, witness := range evidence {
				c.Evidence[witness.Kind] = append(c.Evidence[witness.Kind], witness)
			}
			c.ModelFacts = append(c.ModelFacts, "native_hash_hex: "+e.Text+" at "+e.Span.File)
		}
	}
	s.expressContractFacts(use)
	if use.Kind == "nosql_query_candidate" {
		c.ModelFacts = append(c.ModelFacts, "nosql_selector_semantics")
	}
	s.conditionalHelpers(use)
	s.queryConstraintReview(use)
	s.mongoosePathIDFacts(use)
}

func nativeStringOperation(m *sourceModule, n *sitter.Node) bool {
	if m == nil || n == nil || n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	text := fn.Utf8Text(m.src)
	if (text == "Number" || text == "String") && !shadowed(n, text, m.src) && m.funcs[text] == nil && topVariable(m, text) == nil {
		if _, ok := m.imports[text]; !ok {
			return true
		}
	}
	if fn.Kind() != "member_expression" {
		return false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	switch prop.Utf8Text(m.src) {
	case "substring", "substr", "slice", "replace", "trim":
		return true
	}
	return false
}

// wrapperContext includes verified local wrapper bodies for semantic assessment;
// names such as asyncHandler are never treated as protection by themselves.
func (s *moduleSet) wrapperContext(m *sourceModule, arg *sitter.Node) []analysis.Evidence {
	if arg == nil || arg.Kind() != "call_expression" {
		return nil
	}
	args := arg.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 {
		return nil
	}
	target, fn := s.resolveCall(m, arg)
	if target == nil || fn == nil {
		return nil
	}
	return []analysis.Evidence{target.evidence("wrapper_definition", fn)}
}

func (s *moduleSet) authenticationAdapter(m *sourceModule, arg *sitter.Node) []analysis.Evidence {
	if arg == nil || arg.Kind() != "call_expression" {
		return nil
	}
	target, fn := s.resolveCall(m, arg)
	if target == nil || fn == nil {
		return nil
	}
	body := fn.ChildByFieldName("body")
	if body == nil || body.Kind() != "call_expression" {
		return nil
	}
	callee := body.ChildByFieldName("function")
	args := body.ChildByFieldName("arguments")
	if callee == nil || args == nil || args.NamedChildCount() != 1 {
		return nil
	}
	imp, ok := target.imports[callee.Utf8Text(target.src)]
	if !ok || imp.module != "express-jwt" {
		return nil
	}
	config := args.NamedChild(0)
	for config != nil && (config.Kind() == "as_expression" || config.Kind() == "parenthesized_expression") {
		config = config.NamedChild(0)
	}
	if config == nil || config.Kind() != "object" {
		return nil
	}
	for i := uint(0); i < config.NamedChildCount(); i++ {
		pair := config.NamedChild(i)
		key := pair.ChildByFieldName("key")
		if key == nil {
			return nil
		}
		switch strings.Trim(key.Utf8Text(target.src), "'\"") {
		case "secret", "algorithms", "credentialsRequired":
		default:
			return nil
		}
	}
	return []analysis.Evidence{target.evidence("authentication_adapter", fn), target.evidence("authentication_adapter", imp.declaration)}
}

func (s *moduleSet) conditionalHelpers(use *analysis.CandidateUse) {
	c := use.Completeness
	seen := map[string]bool{}
	var include func(*sourceModule, *sitter.Node, int)
	include = func(m *sourceModule, n *sitter.Node, depth int) {
		if depth > 2 {
			return
		}
		walkCalls(n, func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			if fn == nil {
				return
			}
			name := fn.Utf8Text(m.src)
			if nativeStringOperation(m, call) {
				return
			}
			target, helper := s.resolveCall(m, call)
			if target != nil && helper != nil {
				key := target.file + ":" + helper.Utf8Text(target.src)
				if seen[key] {
					return
				}
				seen[key] = true
				evidence := target.evidence("condition_helper", helper)
				use.Context = append(use.Context, evidence)
				c.Evidence["condition_helper"] = append(c.Evidence["condition_helper"], evidence)
				if body := helper.ChildByFieldName("body"); body != nil {
					include(target, body, depth+1)
				}
			} else if depth == 0 {
				c.Blockers = append(c.Blockers, analysis.Gap{Kind: "condition_helper_unresolved", Detail: "condition callee lacks a supported definition: " + name, At: spanOf(m.file, call)})
			}
		})
	}
	for _, e := range c.Evidence["conditional_value"] {
		m := s.modules[e.Span.File]
		if m == nil {
			continue
		}
		n := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if n == nil {
			continue
		}
		if condition := n.ChildByFieldName("condition"); condition != nil {
			include(m, condition, 0)
		}
		conditionalConstraints(m, n, c)
	}
	if len(c.Evidence["conditional_value"]) > 0 {
		c.ModelFacts = append(c.ModelFacts, "conditional_value_paths")
	}
}
