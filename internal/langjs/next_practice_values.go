package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// practiceConst resolves only prior immutable lexical bindings. Parameters and
// later declarations stop the search rather than exposing an outer namesake.
func practiceConst(m *sourceModule, at *sitter.Node) *sitter.Node {
	if at == nil || at.Kind() != "identifier" && at.Kind() != "shorthand_property_identifier" {
		return nil
	}
	name := at.Utf8Text(m.src)
	for p := at.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "statement_block" || p.Kind() == "program" {
			for i := uint(0); i < p.NamedChildCount(); i++ {
				statement := p.NamedChild(i)
				if statement.Kind() == "export_statement" {
					statement = statement.ChildByFieldName("declaration")
				}
				if statement == nil || statement.Kind() != "lexical_declaration" && statement.Kind() != "variable_declaration" {
					continue
				}
				for j := uint(0); j < statement.NamedChildCount(); j++ {
					d := statement.NamedChild(j)
					id := d.ChildByFieldName("name")
					if id == nil || id.Utf8Text(m.src) != name {
						continue
					}
					v := d.ChildByFieldName("value")
					if v == nil || v.EndByte() >= at.StartByte() || !strings.HasPrefix(statement.Utf8Text(m.src), "const ") {
						return nil
					}
					if m.guardLang().AssignedBetween(m.tree.RootNode(), v.EndByte(), uint(len(m.src)), []string{name}) {
						return nil
					}
					return v
				}
			}
		}
		if isFunction(p) || p.Kind() == "function_declaration" {
			for _, param := range nextParams(p, m.src) {
				if param.name == name {
					return nil
				}
			}
		}
	}
	return nil
}

func practiceUnwrap(n *sitter.Node) *sitter.Node {
	n = unwrapTS(n)
	for n != nil && (n.Kind() == "await_expression" || n.Kind() == "parenthesized_expression") && n.NamedChildCount() == 1 {
		n = unwrapTS(n.NamedChild(0))
	}
	return n
}

// practiceLiteral folds only immutable local aliases, with an explicit cycle bound.
func practiceLiteral(m *sourceModule, n *sitter.Node, depth int) *sitter.Node {
	n = practiceUnwrap(n)
	if n == nil || depth > 6 {
		return nil
	}
	if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
		return practiceLiteral(m, practiceConst(m, n), depth+1)
	}
	return n
}

func practiceCookieOptions(ps *practiceSet, m *sourceModule, call, args *sitter.Node) {
	var options *sitter.Node
	if args.NamedChildCount() >= 3 {
		options = args.NamedChild(2)
	} else if args.NamedChildCount() == 1 {
		options = args.NamedChild(0)
	}
	flags := practiceOptionValues(m, options, 0, options)
	var missing, unknown []string
	for _, key := range []string{"httpOnly", "secure", "sameSite"} {
		v, known := flags[key]
		if !known {
			unknown = append(unknown, key)
			continue
		}
		if v == nil || v.Utf8Text(m.src) == "false" || v.Utf8Text(m.src) == "undefined" {
			missing = append(missing, key)
			continue
		}
		text := v.Utf8Text(m.src)
		if key == "secure" && strings.Contains(text, "NODE_ENV") {
			missing = append(missing, key)
			continue
		}
		valid := text == "true"
		if key == "sameSite" {
			value, ok := stringLiteral(v, m.src)
			valid = valid || ok && (value == "strict" || value == "lax" || value == "none")
		}
		if !valid {
			unknown = append(unknown, key)
		}
	}
	if len(missing) > 0 {
		ps.add("NX-BP-11", "Cookie security options", "observed", "cookie write omits or conditionally disables "+strings.Join(missing, ", "), "", m.evidence("cookie_write", call))
	}
	if len(unknown) > 0 {
		ps.add("NX-BP-11", "Unresolved cookie security options", "review", "cookie option composition does not establish "+strings.Join(unknown, ", "), "", m.evidence("cookie_write", call))
	}
}

// A present nil value means absent; a missing map key means unresolved. Each
// spread replaces the preceding knowledge because JavaScript applies it last.
func practiceOptionValues(m *sourceModule, n *sitter.Node, depth int, use *sitter.Node) map[string]*sitter.Node {
	if depth > 6 {
		return map[string]*sitter.Node{}
	}
	if n == nil {
		return map[string]*sitter.Node{"httpOnly": nil, "secure": nil, "sameSite": nil}
	}
	if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
		if !practiceObjectUnescaped(m, n, use) {
			return map[string]*sitter.Node{}
		}
		v := practiceConst(m, n)
		if v == nil {
			return map[string]*sitter.Node{}
		}
		return practiceOptionValues(m, v, depth+1, use)
	}
	n = practiceUnwrap(n)
	if n == nil || n.Kind() != "object" {
		return map[string]*sitter.Node{}
	}
	out := map[string]*sitter.Node{"httpOnly": nil, "secure": nil, "sameSite": nil}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		p := n.NamedChild(i)
		if p.Kind() == "spread_element" && p.NamedChildCount() == 1 {
			spread := practiceOptionValues(m, p.NamedChild(0), depth+1, use)
			for _, key := range []string{"httpOnly", "secure", "sameSite"} {
				if v, ok := spread[key]; ok {
					if v != nil {
						out[key] = v
					}
				} else {
					delete(out, key)
				}
			}
			continue
		}
		key := p.ChildByFieldName("key")
		v := p.ChildByFieldName("value")
		name := ""
		if key != nil {
			name = key.Utf8Text(m.src)
			if quoted, ok := stringLiteral(key, m.src); ok {
				name = quoted
			}
		}
		if p.Kind() == "shorthand_property_identifier" {
			name = p.Utf8Text(m.src)
			v = p
		}
		if key != nil && key.Kind() == "computed_property_name" {
			out = map[string]*sitter.Node{}
			continue
		}
		if name == "httpOnly" || name == "secure" || name == "sameSite" {
			out[name] = practiceLiteral(m, v, 0)
			if v != nil && out[name] == nil {
				delete(out, name)
			}
		}
	}
	return out
}

// Escaping an options object through an alias or unrelated call could mutate
// it. Such composition stays unresolved rather than inheriting stale defaults.
func practiceObjectUnescaped(m *sourceModule, ref, use *sitter.Node) bool {
	names := map[string]bool{ref.Utf8Text(m.src): true}
	for round := 0; round < 6; round++ {
		walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "variable_declarator" {
				return
			}
			v, id := n.ChildByFieldName("value"), n.ChildByFieldName("name")
			if v != nil && id != nil && v.Kind() == "identifier" && names[v.Utf8Text(m.src)] && id.Kind() == "identifier" {
				names[id.Utf8Text(m.src)] = true
			}
		})
	}
	safe := true
	walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" || n.Kind() == "update_expression" || n.Kind() == "unary_expression" && strings.HasPrefix(n.Utf8Text(m.src), "delete ") {
			target := n.ChildByFieldName("left")
			if target == nil {
				target = n.ChildByFieldName("argument")
			}
			if target != nil {
				for name := range names {
					t := target.Utf8Text(m.src)
					if t == name || strings.HasPrefix(t, name+".") || strings.HasPrefix(t, name+"[") {
						safe = false
					}
				}
			}
		}
		if n.Kind() != "call_expression" {
			return
		}
		args := n.ChildByFieldName("arguments")
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "member_expression" {
			obj := fn.ChildByFieldName("object")
			if obj != nil && names[obj.Utf8Text(m.src)] {
				safe = false
			}
		}
		if args == nil {
			return
		}
		for i := uint(0); i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			if arg.Kind() == "identifier" && names[arg.Utf8Text(m.src)] && (use == nil || arg.StartByte() < use.StartByte() || arg.EndByte() > use.EndByte()) {
				safe = false
			}
		}
	})
	return safe
}
