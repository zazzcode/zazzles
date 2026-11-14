package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

// nodeHTTPContext is adapter output consumed by common source/flow assembly.
// No adapter chooses a database contract or a vulnerability status.
type nodeHTTPContext struct {
	pathOnly              bool
	pathIndex             int
	entry                 analysis.EntryPoint
	registration, handler *sourceModule
	call, body            *sitter.Node
	request, receiver     string
	stages                []analysis.InputStage
	controls              []analysis.Evidence
	gaps                  []analysis.Gap
}

func (s *moduleSet) rememberNodeHTTP(e analysis.EntryPoint, m, hm *sourceModule, call, body *sitter.Node, req, receiver string, context []analysis.Evidence) {
	if e.HTTP == nil {
		return
	}
	if s.nodeHTTP == nil {
		s.nodeHTTP = map[string]*nodeHTTPContext{}
	}
	c := &nodeHTTPContext{entry: e, registration: m, handler: hm, call: call, body: body, request: req, receiver: receiver}
	if e.HTTP.Framework != "express" {
		c.controls, c.gaps, c.stages = s.nodeHTTPControls(m, call, receiver, e.HTTP.Framework)
	}
	s.nodeHTTP[e.ID] = c
}
func nodeReceiver(m *sourceModule, name string) (string, []analysis.Evidence) {
	if m.receivers[name] {
		return "express", nil
	}
	if !contractBindingStable(m, name) {
		return "", nil
	}
	v := topVariable(m, name)
	if v == nil {
		return "", nil
	}
	if v.Kind() == "await_expression" && v.NamedChildCount() == 1 {
		v = v.NamedChild(0)
	}
	if v.Kind() != "call_expression" {
		return "", nil
	}
	fn := v.ChildByFieldName("function")
	if fn == nil {
		return "", nil
	}
	var imp importBinding
	method := ""
	if fn.Kind() == "identifier" {
		imp = m.imports[fn.Utf8Text(m.src)]
		if !contractBindingStable(m, fn.Utf8Text(m.src)) {
			return "", nil
		}
	} else if fn.Kind() == "member_expression" {
		obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || p == nil || obj.Kind() != "identifier" || !contractBindingStable(m, obj.Utf8Text(m.src)) {
			return "", nil
		}
		imp = m.imports[obj.Utf8Text(m.src)]
		method = p.Utf8Text(m.src)
	} else if fn.Kind() == "call_expression" {
		if path, member, ok := requireBinding(m, fn); ok && member == "*" {
			imp = importBinding{module: path, name: "*", declaration: fn}
		}
	}
	framework := ""
	if imp.module == "fastify" && (method == "" || method == "fastify") && (imp.name == "default" || imp.name == "*" || imp.name == "fastify") {
		framework = "fastify"
	}
	if (imp.module == "@hapi/hapi" || imp.module == "hapi") && ((method == "server" && (imp.name == "default" || imp.name == "*")) || (method == "" && imp.name == "server")) {
		framework = "hapi"
	}
	if framework == "" || imp.declaration == nil {
		return "", nil
	}
	return framework, []analysis.Evidence{m.evidence("framework_binding", imp.declaration), m.evidence("framework_instance", v)}
}
func (s *moduleSet) nodeFrameworkEntries(out *analysis.AnalysisReport, m *sourceModule) {
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" {
			return
		}
		receiver := obj.Utf8Text(m.src)
		framework, binding := nodeReceiver(m, receiver)
		if framework == "" || framework == "express" || shadowed(call, receiver, m.src) {
			return
		}
		args := call.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() == 0 {
			return
		}
		method := prop.Utf8Text(m.src)
		var config, h, pathNode, methodNode *sitter.Node
		if method == "route" {
			config = args.NamedChild(0)
			if _, valid := jsOptions(m, config); config.Kind() != "object" || !valid {
				out.Gaps = append(out.Gaps, analysis.Gap{Kind: "node_route_unresolved", Detail: "route options are not a literal object", At: spanOf(m.file, call)})
				return
			}
			h = property(config, "handler", m.src)
			pathNode = property(config, "path", m.src)
			if framework == "fastify" {
				if url := property(config, "url", m.src); url != nil {
					if pathNode != nil {
						a, okA := stringLiteral(pathNode, m.src)
						b, okB := stringLiteral(url, m.src)
						if !okA || !okB || a != b {
							out.Gaps = append(out.Gaps, analysis.Gap{Kind: "node_route_unresolved", Detail: "conflicting path/url options", At: spanOf(m.file, call)})
							return
						}
					}
					pathNode = url
				}
			}
			methodNode = property(config, "method", m.src)
		} else if framework == "fastify" && httpMethod(method) != "" && args.NamedChildCount() >= 2 {
			pathNode = args.NamedChild(0)
			h = args.NamedChild(args.NamedChildCount() - 1)
		} else {
			return
		}
		path, ok := stringLiteral(pathNode, m.src)
		methods := []string{httpMethod(method)}
		if methodNode != nil {
			methods = nodeMethods(methodNode, m.src)
		}
		if !ok || h == nil || len(methods) == 0 || methods[0] == "" || !directNodeRegistration(call) {
			out.Gaps = append(out.Gaps, analysis.Gap{Kind: "node_route_unresolved", Detail: "route needs literal method/path and a handler", At: spanOf(m.file, call)})
			return
		}
		for _, verb := range methods {
			r := analysis.Route{ID: m.file + ":" + receiver + ":" + verb + ":" + path, Method: verb, PathPattern: path, Framework: framework, Registration: spanOf(m.file, call)}
			s.analyzeHTTPHandler(out, m, m, r, call, receiver, binding, path, "", nil, h)
		}
	})
}
func httpMethod(s string) string {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
		return strings.ToUpper(s)
	}
	return ""
}
func nodeMethods(n *sitter.Node, src []byte) []string {
	if t, ok := stringLiteral(n, src); ok {
		if m := httpMethod(t); m != "" {
			return []string{m}
		}
	}
	if n != nil && n.Kind() == "array" {
		out := []string{}
		seen := map[string]bool{}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			m := nodeMethods(n.NamedChild(i), src)
			if len(m) != 1 {
				return nil
			}
			if !seen[m[0]] {
				out = append(out, m[0])
				seen[m[0]] = true
			}
		}
		return out
	}
	return nil
}

func directNodeRegistration(n *sitter.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) {
			return false
		}
		switch p.Kind() {
		case "function_declaration", "generator_function_declaration", "generator_function", "method_definition", "if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "try_statement":
			return false
		}
	}
	return true
}
