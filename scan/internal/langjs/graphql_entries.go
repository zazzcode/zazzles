package langjs

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func graphqlObject(m *sourceModule, n *sitter.Node) *sitter.Node {
	if n != nil && (n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier") {
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) || graphqlPropertyWrite(m, name) || graphqlBindingEscapes(m, name) {
			return nil
		}
		n = browserLocalValue(m, n)
	}
	if n != nil && n.Kind() == "object" {
		return n
	}
	return nil
}
func graphqlPropertyWrite(m *sourceModule, name string) bool {
	bad := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression", "update_expression":
			left := n.ChildByFieldName("left")
			if left == nil {
				left = n.ChildByFieldName("argument")
			}
			if left != nil {
				text := left.Utf8Text(m.src)
				if strings.HasPrefix(text, name+".") || strings.HasPrefix(text, name+"[") {
					bad = true
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return bad
}
func graphqlLiteralObject(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	seen := map[string]bool{}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "comment" {
			continue
		}
		if c.Kind() != "pair" && c.Kind() != "shorthand_property_identifier" && c.Kind() != "method_definition" {
			return false
		}
		key := c.ChildByFieldName("key")
		if c.Kind() == "method_definition" {
			key = c.ChildByFieldName("name")
			text := c.Utf8Text(src)
			if strings.HasPrefix(text, "get ") || strings.HasPrefix(text, "set ") {
				return false
			}
		}
		name := graphqlPropertyName(c, src)
		if !graphqlName(name) || seen[name] {
			return false
		}
		seen[name] = true
		if key != nil && key.Kind() == "computed_property_name" {
			return false
		}
	}
	return true
}

func (s *moduleSet) graphqlEntries(out *analysis.AnalysisReport, m *sourceModule) {
	var visit func(*sitter.Node)
	visit = func(call *sitter.Node) {
		if call.Kind() == "new_expression" {
			ctor := call.ChildByFieldName("constructor")
			if ctor != nil && ctor.Kind() == "identifier" {
				name := ctor.Utf8Text(m.src)
				imp, ok := m.imports[name]
				if ok && imp.module == "@apollo/server" && imp.name == "ApolloServer" {
					if graphqlShadowed(call, name, m.src) || bindingReassigned(m, name) {
						out.Gaps = append(out.Gaps, analysis.Gap{Kind: "graphql_constructor_unresolved", Detail: "Apollo constructor is shadowed or mutated", At: parse.Span(m.file, call)})
					} else {
						s.graphqlServer(out, m, call)
					}
				}
			}
		}
		for i := uint(0); i < call.NamedChildCount(); i++ {
			visit(call.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
}
func (s *moduleSet) graphqlServer(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node) {
	limitation := "GraphQL discovery assumes the Apollo Server 4 named-constructor API with literal SDL/resolver maps; installed framework versions, loaders, transport exposure and parent-result execution are not verified"
	found := false
	for _, text := range out.Limitations {
		found = found || text == limitation
	}
	if !found {
		out.Limitations = append(out.Limitations, limitation)
	}
	registration := m.evidence("entry_registration", call)
	instance := "apollo:" + parse.SnapshotID("registration", registration, m.file, "schema-instance")
	gap := func(kind, detail string) analysis.Gap {
		return analysis.Gap{Kind: kind, Detail: detail, At: registration.Span}
	}
	args := call.ChildByFieldName("arguments")
	var config *sitter.Node
	if args != nil && args.NamedChildCount() == 1 {
		config = graphqlObject(m, args.NamedChild(0))
	}
	var defs, resolvers *sitter.Node
	if config != nil {
		defs = graphqlProperty(config, "typeDefs", m.src)
		resolvers = graphqlObject(m, graphqlProperty(config, "resolvers", m.src))
	}
	fields, gaps := s.graphqlSchema(m, defs)
	if config != nil {
		for i := uint(0); i < config.NamedChildCount(); i++ {
			p := config.NamedChild(i)
			if p.Kind() == "comment" {
				continue
			}
			name := graphqlPropertyName(p, m.src)
			if name != "typeDefs" && name != "resolvers" {
				gaps = append(gaps, gap("graphql_config_unresolved", "Additional Apollo options/overrides are outside the supported constructor subset"))
			}
		}
	}
	gaps = append(gaps, graphqlResolverMapGaps(m, resolvers, fields, registration)...)

	if config == nil || !graphqlLiteralObject(config, m.src) {
		gaps = append(gaps, gap("graphql_config_unresolved", "Apollo options require an immutable literal object"))
	}
	if resolvers == nil || !graphqlLiteralObject(resolvers, m.src) {
		gaps = append(gaps, gap("graphql_resolvers_unresolved", "Resolver map requires an immutable literal object without runtime composition"))
	}
	if len(fields) == 0 {
		out.Gaps = append(out.Gaps, gaps...)
		return
	}
	for i, field := range fields {
		if i >= 128 || s.graphqlRecords+s.grpcRecords+5 > 10000 {
			out.Gaps = append(out.Gaps, gap("graphql_registration_limit", fmt.Sprintf("128 fields/site or 10000 derived records/scan reached; %d SDL fields unexpanded", len(fields)-i)))
			break
		}
		s.graphqlRecords += 5
		s.graphqlFieldEntry(out, m, call, registration, instance, field, resolvers, gaps)
	}
}
func (s *moduleSet) graphqlFieldEntry(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node, registration analysis.Evidence, instance string, field graphqlField, resolvers *sitter.Node, gaps []analysis.Gap) {
	gap := func(kind, detail string) analysis.Gap {
		return analysis.Gap{Kind: kind, Detail: detail, At: registration.Span}
	}
	localGaps := append([]analysis.Gap{}, gaps...)
	var target *sitter.Node
	if resolvers != nil {
		obj := graphqlObject(m, graphqlProperty(resolvers, field.typ, m.src))
		if obj != nil && graphqlLiteralObject(obj, m.src) {
			target = graphqlProperty(obj, field.name, m.src)
		} else if graphqlProperty(resolvers, field.typ, m.src) != nil {
			localGaps = append(localGaps, gap("graphql_resolver_map_unresolved", "Type resolver map uses unsupported composition"))
		}
	}
	operation := "field"
	if field.typ == "Query" {
		operation = "query"
	}
	if field.typ == "Mutation" {
		operation = "mutation"
	}
	if field.typ == "Subscription" {
		localGaps = append(localGaps, gap("graphql_subscription_unsupported", "Subscription execution is outside the supported subset"))
	}
	entry := analysis.EntryPoint{ID: parse.SnapshotID("entry", field.evidence, instance, field.typ+"."+field.name), Kind: "graphql", Name: field.typ + "." + field.name, InstanceID: instance, Location: registration, GraphQL: &analysis.GraphQLEntryMetadata{Type: field.typ, Field: field.name, Operation: operation}}
	hm, fn := s.graphqlResolver(m, target)
	if target == nil {
		localGaps = append(localGaps, gap("graphql_default_resolver_unresolved", "Default field/parent-result resolution is not modeled"))
	} else if fn == nil {
		localGaps = append(localGaps, gap("graphql_resolver_unresolved", "Resolver is not an immutable inline/local/imported named function; wrappers are unsupported"))
	}
	var handler *analysis.Evidence
	var inputs []analysis.InputBinding
	if fn != nil && len(localGaps) == 0 {
		var more []analysis.Gap
		inputs, more = graphqlInputs(hm, fn)
		localGaps = append(localGaps, more...)
		if len(more) == 0 {
			e := hm.evidence("handler", fn.ChildByFieldName("body"))
			handler = &e
		}
	}
	// Object fields have independent args. No schema edge proves a parent value transfer.
	if operation == "field" {
		localGaps = append(localGaps, gap("graphql_parent_result_unresolved", "Parent-result transitions across schema fields are not modeled"))
	}
	entry.Gaps = localGaps
	ctx := parse.RegisterInvocation(out, entry, handler, "graphql_resolver", inputs, localGaps)
	reg := &out.Registrations[len(out.Registrations)-1]
	reg.Framework = "apollo"
	reg.DerivedFrom = []analysis.Evidence{field.evidence, m.evidence("framework_binding", m.imports[call.ChildByFieldName("constructor").Utf8Text(m.src)].declaration)}
	if handler != nil {
		s.graphqlFlow(out, hm, fn, entry, ctx, field, *handler)
	}
}

func (s *moduleSet) graphqlResolver(m *sourceModule, n *sitter.Node) (*sourceModule, *sitter.Node) {
	if n == nil {
		return nil, nil
	}
	if isFunction(n) || n.Kind() == "method_definition" {
		return m, n
	}
	if n.Kind() != "identifier" && n.Kind() != "shorthand_property_identifier" {
		return nil, nil
	}
	name := n.Utf8Text(m.src)
	if bindingReassigned(m, name) {
		return nil, nil
	}
	if local := browserLocalValue(m, n); local != nil {
		if isFunction(local) || local.Kind() == "function_declaration" {
			return m, local
		}
		return nil, nil
	}
	if imp, ok := m.imports[name]; ok && strings.HasPrefix(imp.module, ".") && !graphqlShadowed(n, name, m.src) {
		hm, fn := s.resolve(m, name)
		if hm != nil && fn != nil && !bindingReassigned(hm, imp.name) && (isFunction(fn) || fn.Kind() == "function_declaration") && !hm.tree.RootNode().HasError() {
			return hm, fn
		}
	}
	return nil, nil
}

func graphqlProperty(n *sitter.Node, name string, src []byte) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		p := n.NamedChild(i)
		key := p.ChildByFieldName("key")
		if p.Kind() == "method_definition" {
			key = p.ChildByFieldName("name")
		}
		if key != nil {
			k := key.Utf8Text(src)
			if lit, ok := stringLiteral(key, src); ok {
				k = lit
			}
			if k == name {
				if p.Kind() == "method_definition" {
					return p
				}
				return p.ChildByFieldName("value")
			}
		}
		if p.Kind() == "shorthand_property_identifier" && p.Utf8Text(src) == name {
			return p
		}
	}
	return nil
}
func graphqlShadowed(n *sitter.Node, name string, src []byte) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if param := p.ChildByFieldName("parameter"); param != nil && param.Kind() == "identifier" && param.Utf8Text(src) == name {
			return true
		}
	}
	return shadowed(n, name, src)
}

// A source object passed to an arbitrary call or aliased outside the literal
// constructor maps no longer has an established immutable runtime shape.
func graphqlBindingEscapes(m *sourceModule, name string) bool {
	escaped := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			p := n.Parent()
			if p != nil {
				switch p.Kind() {
				case "arguments":
					parent := p.Parent()
					if parent == nil || parent.Kind() != "new_expression" {
						escaped = true
					} else {
						ctor := parent.ChildByFieldName("constructor")
						if ctor == nil {
							escaped = true
						} else {
							imp := m.imports[ctor.Utf8Text(m.src)]
							if imp.module != "@apollo/server" || imp.name != "ApolloServer" {
								escaped = true
							}
						}
					}
				case "variable_declarator":
					if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == n.StartByte() {
						escaped = true
					}
				case "assignment_expression", "return_statement", "spread_element":
					escaped = true
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount() && !escaped; i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return escaped
}

func graphqlPropertyName(n *sitter.Node, src []byte) string {
	key := n.ChildByFieldName("key")
	if n.Kind() == "method_definition" {
		key = n.ChildByFieldName("name")
	}
	if key != nil {
		if literal, ok := stringLiteral(key, src); ok {
			return literal
		}
		return key.Utf8Text(src)
	}
	if n.Kind() == "shorthand_property_identifier" {
		return n.Utf8Text(src)
	}
	return ""
}

func graphqlResolverMapGaps(m *sourceModule, resolvers *sitter.Node, fields []graphqlField, registration analysis.Evidence) []analysis.Gap {
	var gaps []analysis.Gap
	gap := func(kind, detail string) analysis.Gap {
		return analysis.Gap{Kind: kind, Detail: detail, At: registration.Span}
	}
	if resolvers != nil {
		types := map[string]bool{}
		coordinates := map[string]bool{}
		for _, field := range fields {
			types[field.typ] = true
			coordinates[field.typ+"."+field.name] = true
		}
		for i := uint(0); i < resolvers.NamedChildCount(); i++ {
			p := resolvers.NamedChild(i)
			if p.Kind() == "comment" {
				continue
			}
			typ := graphqlPropertyName(p, m.src)
			if obj := graphqlObject(m, graphqlProperty(resolvers, typ, m.src)); obj != nil {
				for j := uint(0); j < obj.NamedChildCount(); j++ {
					member := obj.NamedChild(j)
					if member.Kind() == "comment" {
						continue
					}
					if !coordinates[typ+"."+graphqlPropertyName(member, m.src)] {
						gaps = append(gaps, gap("graphql_resolver_map_unresolved", "Resolver hooks or fields absent from literal SDL are not modeled"))
					}
				}
			}
			if !types[graphqlPropertyName(p, m.src)] {
				gaps = append(gaps, gap("graphql_resolvers_unresolved", "Custom scalar or non-object resolver execution is not modeled"))
			}
		}
	}

	return gaps
}
