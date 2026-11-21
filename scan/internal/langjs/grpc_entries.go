package langjs

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func grpcAPI(m *sourceModule, n *sitter.Node, module, method string) bool {
	if n == nil {
		return false
	}
	root := n
	name := method
	if n.Kind() == "member_expression" {
		root = n.ChildByFieldName("object")
		prop := n.ChildByFieldName("property")
		if prop == nil || prop.Utf8Text(m.src) != method {
			return false
		}
		name = "*"
	}
	if root == nil || root.Kind() != "identifier" {
		return false
	}
	id := root.Utf8Text(m.src)
	imp, ok := m.imports[id]
	return ok && imp.module == module && (imp.name == name || name == "*" && imp.name == "default") && !graphqlShadowed(n, id, m.src) && !bindingReassigned(m, id) && !graphqlPropertyWrite(m, id)
}
func grpcLocal(m *sourceModule, n *sitter.Node) *sitter.Node {
	if n != nil && n.Kind() == "identifier" {
		name := n.Utf8Text(m.src)
		if graphqlShadowed(n, name, m.src) || bindingReassigned(m, name) || grpcBindingEscapes(m, name, map[string]bool{}) {
			return nil
		}
		return topVariable(m, name)
	}
	return n
}

// Resolve only immutable top-level descriptor aliases and member projections.
func grpcDescriptor(m *sourceModule, n *sitter.Node, depth int) (*sitter.Node, []string, bool) {
	if depth >= 16 {
		return nil, nil, true
	}
	if n == nil {
		return nil, nil, false
	}
	if n.Kind() == "identifier" {
		v := grpcLocal(m, n)
		if v == n {
			return nil, nil, false
		}
		return grpcDescriptor(m, v, depth+1)
	}
	if n.Kind() == "member_expression" {
		base, parts, limited := grpcDescriptor(m, n.ChildByFieldName("object"), depth+1)
		prop := n.ChildByFieldName("property")
		if base == nil || prop == nil {
			return nil, nil, limited
		}
		return base, append(parts, prop.Utf8Text(m.src)), false
	}
	if n.Kind() == "call_expression" && grpcAPI(m, n.ChildByFieldName("function"), "@grpc/grpc-js", "loadPackageDefinition") {
		return n, nil, false
	}
	return nil, nil, false
}
func (s *moduleSet) grpcEntries(out *analysis.AnalysisReport, m *sourceModule) {
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		prop := fn.ChildByFieldName("property")
		if prop == nil || prop.Utf8Text(m.src) != "addService" {
			return
		}
		receiver := fn.ChildByFieldName("object")
		ctor := grpcLocal(m, receiver)
		if ctor == nil || ctor.Kind() != "new_expression" || !grpcAPI(m, ctor.ChildByFieldName("constructor"), "@grpc/grpc-js", "Server") {
			out.Gaps = append(out.Gaps, analysis.Gap{Kind: "grpc_receiver_unresolved", Detail: "addService receiver lacks an immutable verified grpc-js Server construction", At: parse.Span(m.file, call)})
			return
		}
		s.grpcService(out, m, call, ctor)
	})
}
func (s *moduleSet) grpcService(out *analysis.AnalysisReport, m *sourceModule, call, ctor *sitter.Node) {
	registration := m.evidence("entry_registration", call)
	gap := func(kind, detail string) analysis.Gap {
		return analysis.Gap{Kind: kind, Detail: detail, At: registration.Span}
	}
	var gaps []analysis.Gap
	instance := "grpc:" + parse.SnapshotID("registration", m.evidence("grpc_server", ctor), m.file, "server")
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 2 {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_unresolved", "addService requires a descriptor and literal handler map"))
		return
	}
	chain, parts, limited := grpcDescriptor(m, args.NamedChild(0), 0)
	if limited {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_limit", "16 descriptor alias/member expansion steps reached; remaining chain unexpanded"))
		return
	}
	if chain == nil || len(parts) < 2 || parts[len(parts)-1] != "service" {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_unresolved", "Missing verified loadPackageDefinition service chain; dynamic/generated descriptors unsupported"))
		return
	}
	defs := chain.ChildByFieldName("arguments")
	var load *sitter.Node
	if defs != nil && defs.NamedChildCount() == 1 {
		load = grpcLocal(m, defs.NamedChild(0))
	}
	if load == nil || load.Kind() != "call_expression" || !grpcAPI(m, load.ChildByFieldName("function"), "@grpc/proto-loader", "loadSync") {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_unresolved", "Descriptor requires verified proto-loader loadSync"))
		return
	}
	loadArgs := load.ChildByFieldName("arguments")
	if loadArgs == nil || loadArgs.NamedChildCount() < 1 || loadArgs.NamedChildCount() > 2 {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_unresolved", "loadSync requires one literal local path and optional literal options"))
		return
	}
	path, ok := stringLiteral(loadArgs.NamedChild(0), m.src)
	if !ok {
		out.Gaps = append(out.Gaps, gap("grpc_descriptor_unresolved", "Dynamic proto path unsupported"))
		return
	}
	keepCase := false
	if loadArgs.NamedChildCount() == 2 {
		opts := grpcObject(m, loadArgs.NamedChild(1))
		if opts == nil || !graphqlLiteralObject(opts, m.src) {
			gaps = append(gaps, gap("grpc_loader_options_unresolved", "Dynamic loader options/include paths unsupported"))
		} else {
			for i := uint(0); i < opts.NamedChildCount(); i++ {
				p := opts.NamedChild(i)
				if p.Kind() == "comment" {
					continue
				}
				key := graphqlPropertyName(p, m.src)
				v := p.ChildByFieldName("value")
				if key == "keepCase" && v != nil && (v.Kind() == "true" || v.Kind() == "false") {
					keepCase = v.Kind() == "true"
				} else {
					gaps = append(gaps, gap("grpc_loader_options_unresolved", "Loader options beyond literal keepCase (including includeDirs) are unsupported"))
				}
			}
		}
	}
	ca := ctor.ChildByFieldName("arguments")
	if ca != nil && ca.NamedChildCount() != 0 {
		gaps = append(gaps, gap("grpc_interceptor_unresolved", "Server options/interceptors are outside the supported subset"))
	}
	result := s.grpcProto(path, registration.Span)
	gaps = append(gaps, result.gaps...)
	for _, name := range sortedImportNames(m) {
		imp := m.imports[name]
		if (imp.module == "@grpc/grpc-js" || imp.module == "@grpc/proto-loader") && grpcBindingEscapes(m, name, map[string]bool{}) {
			gaps = append(gaps, gap("grpc_framework_unresolved", "Framework binding escapes the verified source API subset"))
		}
	}
	impl := grpcObject(m, args.NamedChild(1))
	if impl == nil || !graphqlLiteralObject(impl, m.src) {
		gaps = append(gaps, gap("grpc_implementation_unresolved", "Implementation must be an immutable literal map"))
		impl = nil
	}
	service := strings.Join(parts[:len(parts)-1], ".")
	var methods []grpcMethod
	for _, method := range result.methods {
		full := method.service
		if method.pkg != "" {
			full = method.pkg + "." + full
		}
		if full == service {
			methods = append(methods, method)
		}
	}
	if len(methods) == 0 {
		out.Gaps = append(out.Gaps, gaps...)
		out.Gaps = append(out.Gaps, gap("grpc_service_unresolved", "Selected service is absent from supported proto declarations"))
		return
	}
	validKeys := map[string]bool{}
	for _, method := range methods {
		validKeys[method.name] = true
		alias := grpcCamel(method.name)
		if alias != "" {
			validKeys[alias] = true
		}
	}
	if impl != nil {
		for i := uint(0); i < impl.NamedChildCount(); i++ {
			p := impl.NamedChild(i)
			if p.Kind() != "comment" && !validKeys[graphqlPropertyName(p, m.src)] {
				gaps = append(gaps, gap("grpc_method_mismatch", "Implementation key is absent from the selected proto service"))
			}
		}
	}
	limitation := "gRPC discovery assumes grpc-js 1.x/proto-loader 0.8 source-visible unary APIs and process cwd equal to selected root; installed versions, generated stubs, imports/include paths, streaming and interceptors are not verified"
	found := false
	for _, v := range out.Limitations {
		found = found || v == limitation
	}
	if !found {
		out.Limitations = append(out.Limitations, limitation)
	}
	for i, method := range methods {
		if i >= 128 || s.grpcRecords+s.graphqlRecords+5 > 10000 {
			out.Gaps = append(out.Gaps, gap("grpc_registration_limit", fmt.Sprintf("128 methods/site or 10000 records/scan reached; %d methods unexpanded", len(methods)-i)))
			break
		}
		s.grpcRecords += 5
		s.grpcMethodEntry(out, m, registration, instance, method, impl, keepCase, gaps, []analysis.Evidence{m.evidence("grpc_server", ctor.Parent()), m.evidence("grpc_package_definition", chain.Parent()), m.evidence("grpc_proto_loader", load.Parent()), m.evidence("grpc_service_descriptor", args.NamedChild(0))})
	}
}

// Match ordinary lower/UpperCamel names and snake_case. Acronym fallback is left
// unresolved rather than approximating lodash.camelcase's word segmentation.
func grpcCamel(name string) string {
	var out []rune
	upper := false
	priorUpper := false
	for i, c := range name {
		if c == '_' {
			upper = true
			continue
		}
		isUpper := unicode.IsUpper(c)
		if priorUpper && isUpper {
			return ""
		}
		if i == 0 {
			c = unicode.ToLower(c)
		}
		if upper {
			c = unicode.ToUpper(c)
			upper = false
		}
		out = append(out, c)
		priorUpper = isUpper
	}
	return string(out)
}
func (s *moduleSet) grpcMethodEntry(out *analysis.AnalysisReport, m *sourceModule, registration analysis.Evidence, instance string, method grpcMethod, impl *sitter.Node, keepCase bool, gaps []analysis.Gap, derived []analysis.Evidence) {
	local := append([]analysis.Gap{}, gaps...)
	if !keepCase {
		seen := map[string]bool{}
		for _, field := range method.fields {
			name := grpcFieldName(field)
			if seen[name] {
				local = append(local, analysis.Gap{Kind: "grpc_message_unresolved", Detail: "Default loader field-name conversion collides; request shape unresolved", At: method.evidence.Span})
			}
			seen[name] = true
		}
	}
	gap := func(kind, detail string) {
		local = append(local, analysis.Gap{Kind: kind, Detail: detail, At: registration.Span})
	}
	var target *sitter.Node
	if impl != nil {
		target = graphqlProperty(impl, method.name, m.src)
		if target == nil {
			if alias := grpcCamel(method.name); alias != "" {
				target = graphqlProperty(impl, alias, m.src)
			}
		}
	}
	if method.clientStream || method.serverStream {
		gap("grpc_streaming_unsupported", "Streaming RPC is inventoried; event/value flow is not modeled")
	}
	hm, fn := s.graphqlResolver(m, target)
	if target == nil {
		gap("grpc_handler_unresolved", "No literal implementation for this method; generated/default handlers are unsupported")
	} else if fn == nil {
		gap("grpc_handler_unresolved", "Handler wrappers/dynamic or missing implementations are unsupported")
	}
	var handler *analysis.Evidence
	var inputs []analysis.InputBinding
	if fn != nil && len(local) == 0 {
		var more []analysis.Gap
		inputs, more = grpcInputs(hm, fn)
		local = append(local, more...)
		if len(more) == 0 {
			e := hm.evidence("handler", fn.ChildByFieldName("body"))
			handler = &e
		}
	}
	name := method.service + "/" + method.name
	if method.pkg != "" {
		name = method.pkg + "." + name
	}
	entry := analysis.EntryPoint{ID: parse.SnapshotID("entry", method.evidence, instance, parse.SnapshotID("registration", registration, instance, name)), Kind: "grpc", Name: name, InstanceID: instance, Location: registration, GRPC: &analysis.GRPCEntryMetadata{Package: method.pkg, Service: method.service, Method: method.name, ClientStreaming: method.clientStream, ServerStreaming: method.serverStream}, Gaps: local}
	ctx := parse.RegisterInvocation(out, entry, handler, "grpc_handler", inputs, local)
	reg := &out.Registrations[len(out.Registrations)-1]
	reg.Framework = "grpc-js"
	derived = append(append([]analysis.Evidence{}, method.messages...), derived...)
	reg.DerivedFrom = append([]analysis.Evidence{method.evidence}, derived...)
	for _, n := range []string{"@grpc/grpc-js", "@grpc/proto-loader"} {
		for _, key := range sortedImportNames(m) {
			imp := m.imports[key]
			if imp.module == n {
				reg.DerivedFrom = append(reg.DerivedFrom, m.evidence("framework_binding", imp.declaration))
			}
		}
	}
	if target != nil {
		reg.DerivedFrom = append(reg.DerivedFrom, m.evidence("grpc_implementation", target))
	}
	if handler != nil {
		s.grpcFlow(out, hm, fn, entry, ctx, method, keepCase, *handler)
	}
}

func sortedImportNames(m *sourceModule) []string {
	keys := make([]string, 0, len(m.imports))
	for key := range m.imports {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Aliases and member projections retain the same mutable object identity. A
// descriptor/server passed to an unknown call cannot retain a verified shape.
func grpcBindingEscapes(m *sourceModule, name string, seen map[string]bool) bool {
	if seen[name] || len(seen) >= 16 {
		return true
	}
	seen[name] = true
	defer delete(seen, name)
	if graphqlPropertyWrite(m, name) {
		return true
	}
	bad := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if bad {
			return
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			top := n
			for top.Parent() != nil && (top.Parent().Kind() == "member_expression" || top.Parent().Kind() == "subscript_expression") && top.Parent().ChildByFieldName("object") != nil && top.Parent().ChildByFieldName("object").StartByte() == top.StartByte() {
				top = top.Parent()
			}
			if p := top.Parent(); p != nil {
				switch p.Kind() {
				case "call_expression":
					// Calling an unknown member can mutate a source-visible server/descriptor.
					// Imported namespaces keep their library binding unless it is written or escapes.
					if fn := p.ChildByFieldName("function"); fn != nil && fn.StartByte() == top.StartByte() {
						imp := m.imports[name]
						trusted := imp.module == "@grpc/grpc-js" || imp.module == "@grpc/proto-loader"
						method := ""
						if prop := top.ChildByFieldName("property"); prop != nil {
							method = prop.Utf8Text(m.src)
						}
						if !trusted {
							switch method {
							case "addService", "bindAsync", "start", "forceShutdown", "tryShutdown":
								trusted = grpcVerifiedServiceCall(m, p)
							}
						}
						if !trusted {
							bad = true
						}
					}
				case "arguments":
					call := p.Parent()
					fn := call.ChildByFieldName("function")
					allowed := grpcAPI(m, fn, "@grpc/grpc-js", "loadPackageDefinition")
					if fn != nil && fn.Kind() == "member_expression" {
						prop := fn.ChildByFieldName("property")
						allowed = allowed || prop != nil && prop.Utf8Text(m.src) == "addService" && grpcVerifiedServiceCall(m, call)
					}
					if !allowed {
						bad = true
					}
				case "variable_declarator":
					if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == top.StartByte() {
						alias := p.ChildByFieldName("name")
						if alias == nil || alias.Kind() != "identifier" || grpcBindingEscapes(m, alias.Utf8Text(m.src), seen) {
							bad = true
						}
					}
				case "assignment_expression", "return_statement", "spread_element":
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

func grpcObject(m *sourceModule, n *sitter.Node) *sitter.Node {
	n = grpcLocal(m, n)
	if n != nil && n.Kind() == "object" {
		return n
	}
	return nil
}

func grpcVerifiedServiceCall(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" {
		return false
	}
	name := obj.Utf8Text(m.src)
	if graphqlShadowed(call, name, m.src) || bindingReassigned(m, name) || graphqlPropertyWrite(m, name) {
		return false
	}
	ctor := topVariable(m, name)
	return ctor != nil && ctor.Kind() == "new_expression" && grpcAPI(m, ctor.ChildByFieldName("constructor"), "@grpc/grpc-js", "Server")
}
