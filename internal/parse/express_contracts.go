package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// importedContractCall accepts immutable direct imports only. Aliases, writes,
// escapes and shadowing cannot borrow the original library's behavior.
func importedContractCall(m *sourceModule, call *sitter.Node) (importBinding, string, bool) {
	if m == nil || call == nil || call.Kind() != "call_expression" {
		return importBinding{}, "", false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return importBinding{}, "", false
	}
	root, method := fn.Utf8Text(m.src), ""
	if fn.Kind() == "member_expression" {
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" {
			return importBinding{}, "", false
		}
		root, method = obj.Utf8Text(m.src), prop.Utf8Text(m.src)
	} else if fn.Kind() != "identifier" {
		return importBinding{}, "", false
	}
	imp, ok := m.imports[root]
	if !ok || (imp.name != "*" && imp.name != "default") || shadowed(call, root, m.src) || !contractBindingStable(m, root) {
		return importBinding{}, "", false
	}
	return imp, method, true
}

func contractBindingStable(m *sourceModule, name string, allowed ...*sitter.Node) bool {
	if m.contractBindings == nil {
		m.contractBindings = map[string]bool{}
	}
	if stable, ok := m.contractBindings[name]; ok && len(allowed) == 0 {
		return stable
	}
	stable := !bindingReassigned(m, name)
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !stable {
			return
		}
		var left *sitter.Node
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			left = n.ChildByFieldName("left")
		case "update_expression":
			left = n.ChildByFieldName("argument")
		}
		if left != nil {
			text := left.Utf8Text(m.src)
			if text == name || strings.HasPrefix(text, name+".") || strings.HasPrefix(text, name+"[") {
				stable = false
				return
			}
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			if p := n.Parent(); p != nil {
				switch p.Kind() {
				case "arguments", "return_statement", "spread_element":
					permitted := false
					for _, item := range allowed {
						if item != nil && n.StartByte() == item.StartByte() && n.EndByte() == item.EndByte() {
							permitted = true
						}
					}
					if !permitted {
						stable = false
					}
				case "variable_declarator":
					if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == n.StartByte() {
						stable = false
					}
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	if len(allowed) == 0 {
		m.contractBindings[name] = stable
	}
	return stable
}

func literalContractOptions(m *sourceModule, n *sitter.Node, depth int, session bool) bool {
	if n == nil || depth > 4 {
		return false
	}
	switch n.Kind() {
	case "string", "number", "true", "false", "null":
		return true
	case "object":
		if n.NamedChildCount() > 32 {
			return false
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			pair := n.NamedChild(i)
			if pair.Kind() != "pair" {
				return false
			}
			key, value := pair.ChildByFieldName("key"), pair.ChildByFieldName("value")
			if key == nil {
				return false
			}
			if session && depth == 0 {
				name := strings.Trim(key.Utf8Text(m.src), "\"'")
				switch name {
				case "secret", "name", "cookie", "resave", "saveUninitialized", "rolling", "unset", "proxy":
				default:
					return false
				}
			}
			if !literalContractOptions(m, value, depth+1, false) {
				return false
			}
		}
		return true
	}
	return false
}

func middlewareAdapterEvidence(m *sourceModule, call *sitter.Node) []analysis.Evidence {
	imp, method, ok := importedContractCall(m, call)
	if !ok || method != "" {
		return nil
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	switch imp.module {
	case "method-override", "express-fileupload":
		if args.NamedChildCount() != 0 {
			return nil
		}
	case "express-session":
		if args.NamedChildCount() != 1 || args.NamedChild(0).Kind() != "object" || !literalContractOptions(m, args.NamedChild(0), 0, true) {
			return nil
		}
	default:
		return nil
	}
	return []analysis.Evidence{m.evidence("middleware_adapter_binding", imp.declaration), m.evidence("middleware_adapter_call", call)}
}

func inputPredicateEvidence(m *sourceModule, call *sitter.Node) []analysis.Evidence {
	imp, method, ok := importedContractCall(m, call)
	if !ok || imp.module != "validator" || method != "isEmail" {
		return nil
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 {
		return nil
	}
	return []analysis.Evidence{m.evidence("input_predicate_binding", imp.declaration), m.evidence("input_predicate_call", call)}
}

func (s *moduleSet) expressContractFacts(use *analysis.CandidateUse) {
	seen := map[string]bool{}
	for _, e := range use.Context {
		fact := ""
		if e.Kind == "input_predicate_call" {
			fact = "A verified immutable validator.isEmail(value) call is a string/email predicate on that argument only (non-string inputs can throw). It does not transform another request field or remove query operators from a sibling password/selector value. A successful predicate must not lend validation or protection to another field."
		}
		if e.Kind == "middleware_adapter_call" {
			fact = "Verified default method-override()/express-fileupload() or literal-data express-session options are transport/session adapters, not per-field database validators. Default method override changes request method, default upload handling concerns multipart bodies, and session handling supplies session/cookie state. They do not impose a scalar schema on fields of an already parsed JSON body. Custom callbacks, stores, dynamic options, mutated imports and unknown middleware are not covered by this contract."
		}
		if fact != "" && !seen[fact] {
			use.Completeness.ModelFacts = append(use.Completeness.ModelFacts, fact)
			seen[fact] = true
		}
	}
}
