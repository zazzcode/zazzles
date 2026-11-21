package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// nativeHashHex accepts a single immutable native createHash/update/digest chain.
// It models only the returned alphabet, never password strength or sibling values.
func nativeHashHex(m *sourceModule, n *sitter.Node) (*sitter.Node, []analysis.Evidence) {
	update, digestArgs := chainedMethod(m, n, "digest")
	if update == nil || digestArgs.NamedChildCount() != 1 {
		return nil, nil
	}
	if encoding, ok := stringLiteral(digestArgs.NamedChild(0), m.src); !ok || encoding != "hex" {
		return nil, nil
	}
	create, updateArgs := chainedMethod(m, update, "update")
	if create == nil || updateArgs.NamedChildCount() < 1 || updateArgs.NamedChildCount() > 2 {
		return nil, nil
	}
	if updateArgs.NamedChildCount() == 2 {
		encoding, ok := stringLiteral(updateArgs.NamedChild(1), m.src)
		if !ok || encoding != "utf8" {
			return nil, nil
		}
	}
	imp, method, ok := importedContractCall(m, create)
	if !ok || (imp.module != "crypto" && imp.module != "node:crypto") || method != "createHash" {
		return nil, nil
	}
	args := create.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 {
		return nil, nil
	}
	algorithm, ok := stringLiteral(args.NamedChild(0), m.src)
	if !ok {
		return nil, nil
	}
	switch algorithm {
	case "md5", "sha1", "sha256", "sha384", "sha512":
	default:
		return nil, nil
	}
	return updateArgs.NamedChild(0), []analysis.Evidence{m.evidence("native_hash_binding", imp.declaration), m.evidence("native_hash_hex", n)}
}

func chainedMethod(m *sourceModule, n *sitter.Node, method string) (*sitter.Node, *sitter.Node) {
	if n == nil || n.Kind() != "call_expression" {
		return nil, nil
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" {
		return nil, nil
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || obj.Kind() != "call_expression" || prop == nil || prop.Utf8Text(m.src) != method {
		return nil, nil
	}
	return obj, args
}

// Inner chain calls share the verified outer expression's contract, but calls
// inside the input operand still require independent helper evidence.
func nativeHashChainCall(m *sourceModule, call *sitter.Node) bool {
	n := call
	for depth := 0; depth < 3; depth++ {
		if input, _ := nativeHashHex(m, n); input != nil {
			return true
		}
		p := n.Parent()
		if p == nil || p.Kind() != "member_expression" {
			return false
		}
		obj := p.ChildByFieldName("object")
		if obj == nil || obj.StartByte() != n.StartByte() || obj.EndByte() != n.EndByte() {
			return false
		}
		n = p.Parent()
		if n == nil || n.Kind() != "call_expression" {
			return false
		}
	}
	return false
}
