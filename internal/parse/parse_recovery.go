package parse

import (
	"regexp"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// typedTaggedTemplate matches a type-argument list directly before a tagged
// template (`fn<T>`...“), which the pinned TypeScript grammar does not accept.
var typedTaggedTemplate = regexp.MustCompile("([\\w$\\]\\)])(<(?:[^<>`=]|<[^<>`]*>)*>)(\\s*`)")

// htmlEntity matches a complete character reference after an ampersand.
var htmlEntity = regexp.MustCompile(`^&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);`)

// parseRecovered parses src and, only when the tree has errors, retries on a
// byte-for-byte equal-length copy that blanks two grammar limitations: a bare
// `&` inside an error region (JSX text or attribute strings such as
// "Terms & Conditions") and type arguments on a tagged template. Every span and
// evidence text still comes from the original source; the copy only steers the
// grammar. The retry is kept only when it removes every syntax error.
func parseRecovered(parser *sitter.Parser, src []byte) (*sitter.Tree, []string) {
	tree := parser.Parse(src, nil)
	if tree == nil || !tree.RootNode().HasError() {
		return tree, nil
	}
	copySrc := append([]byte{}, src...)
	var steps []string
	if locs := typedTaggedTemplate.FindAllSubmatchIndex(copySrc, -1); len(locs) > 0 {
		for _, loc := range locs {
			for i := loc[4]; i < loc[5]; i++ {
				if copySrc[i] != '\n' {
					copySrc[i] = ' '
				}
			}
		}
		steps = append(steps, "tagged_template_type_arguments")
	}
	for attempt := 0; attempt < 4; attempt++ {
		candidate := parser.Parse(copySrc, nil)
		if candidate == nil {
			break
		}
		if !candidate.RootNode().HasError() {
			tree.Close()
			return candidate, steps
		}
		changed := false
		var visit func(n *sitter.Node)
		visit = func(n *sitter.Node) {
			if n.IsError() || n.IsMissing() {
				start, end := int(n.StartByte()), int(n.EndByte())
				// Widen a missing-node or zero-width error to its parent's text.
				if end <= start && n.Parent() != nil {
					start, end = int(n.Parent().StartByte()), int(n.Parent().EndByte())
				}
				for i := start; i < end && i < len(copySrc); i++ {
					if blankAmpersand(copySrc, i) {
						copySrc[i] = ' '
						changed = true
					}
				}
			}
			for i := uint(0); i < n.ChildCount(); i++ {
				if c := n.Child(i); c.HasError() || c.IsError() || c.IsMissing() {
					visit(c)
				}
			}
		}
		visit(candidate.RootNode())
		candidate.Close()
		if !changed {
			break
		}
		if len(steps) == 0 || steps[len(steps)-1] != "jsx_ampersand" {
			steps = append(steps, "jsx_ampersand")
		}
	}
	return tree, nil
}

// blankAmpersand reports a lone `&` that is neither a logical operator nor a
// complete character reference.
func blankAmpersand(src []byte, i int) bool {
	if src[i] != '&' {
		return false
	}
	if (i > 0 && src[i-1] == '&') || (i+1 < len(src) && (src[i+1] == '&' || src[i+1] == '=')) {
		return false
	}
	return !htmlEntity.Match(src[i:])
}

// typedAwaitCalls finds `await f<T>(...)`, which the pinned grammar parses as
// `(await f)<T>(...)`. It returns the await keyword spans and the start byte of
// each awaited callee.
func typedAwaitCalls(root *sitter.Node) (blanks [][2]uint, callees []uint) {
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "call_expression" && n.ChildByFieldName("type_arguments") != nil {
			if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "await_expression" && fn.ChildCount() > 1 && fn.NamedChildCount() == 1 {
				kw := fn.Child(0)
				if kw.Kind() == "await" {
					blanks = append(blanks, [2]uint{kw.StartByte(), kw.EndByte()})
					callees = append(callees, fn.NamedChild(0).StartByte())
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(root)
	return blanks, callees
}

// reparseTypedAwaits re-parses src with the misattached await keywords blanked
// so the generic call parses as one call. The blanked calls are returned so the
// flow can still apply await semantics to them.
func reparseTypedAwaits(parser *sitter.Parser, tree *sitter.Tree, src []byte) (*sitter.Tree, map[uint]bool) {
	blanks, callees := typedAwaitCalls(tree.RootNode())
	if len(blanks) == 0 {
		return tree, nil
	}
	copySrc := append([]byte{}, src...)
	for _, b := range blanks {
		for i := b[0]; i < b[1]; i++ {
			copySrc[i] = ' '
		}
	}
	candidate := parser.Parse(copySrc, nil)
	if candidate == nil || candidate.RootNode().HasError() {
		if candidate != nil {
			candidate.Close()
		}
		return tree, nil
	}
	tree.Close()
	awaited := map[uint]bool{}
	for _, c := range callees {
		awaited[c] = true
	}
	return candidate, awaited
}
