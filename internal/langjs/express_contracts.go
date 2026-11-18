package langjs

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
	return m.bindingWrites().contractStable(name, allowed)
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
			fact = "validator_is_email"
		}
		if e.Kind == "middleware_adapter_call" {
			fact = "express_transport_adapters"
		}
		if fact != "" && !seen[fact] {
			use.Completeness.ModelFacts = append(use.Completeness.ModelFacts, fact)
			seen[fact] = true
		}
	}
}
