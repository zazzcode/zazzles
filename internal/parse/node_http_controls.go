package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"sort"
)

// nodeHTTPControls supplies application code/configuration to the judge. It
// never reimplements schema validation or assumes a schema is protective.
func (s *moduleSet) nodeHTTPControls(m *sourceModule, site *sitter.Node, receiver, framework string) ([]analysis.Evidence, []analysis.Gap, []analysis.InputStage) {
	out := []analysis.Evidence{}
	stages := []analysis.InputStage{}
	currentStage, currentScope := "unknown", "route"
	gaps := []analysis.Gap{}
	addGap := func(n *sitter.Node, detail string) {
		gaps = append(gaps, analysis.Gap{Kind: "http_hook_unresolved", Detail: detail, At: spanOf(m.file, n)})
	}
	var hook func(*sitter.Node)
	hook = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "array" {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				hook(n.NamedChild(i))
			}
			return
		}
		hm, body, _, missing := s.handler(m, n)
		if body == nil || len(missing) > 0 {
			addGap(n, "hook/validator body is not independently resolved")
			return
		}
		e := hm.evidence("http_hook", body)
		out = append(out, e)
		stages = append(stages, analysis.InputStage{Name: currentStage, Order: nodeStageOrder(currentStage), Scope: currentScope, Evidence: e})
		seen := map[string]bool{}
		s.includeHelpers(hm, body, &out, seen, 0)
		gaps = append(gaps, s.nodeControlHelperGaps(hm, body, parameterNames(body.Parent(), hm.src), 0)...)
	}
	var config func(*sitter.Node)
	config = func(n *sitter.Node) {
		if n == nil {
			return
		}
		out = append(out, m.evidence("http_options", n))
		props, ok := jsOptions(m, n)
		if n.Kind() != "object" || !ok {
			addGap(n, "dynamic/computed route configuration")
			return
		}
		keys := make([]string, 0, len(props))
		for key := range props {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			v := props[key]
			switch key {
			case "method", "url", "path", "handler", "schema", "validate", "routes", "onRequest", "preParsing", "preValidation", "preHandler", "ext", "pre", "validatorCompiler", "attachValidation", "logLevel", "bodyLimit", "exposeHeadRoute", "port", "host", "logger":
			default:
				addGap(v, "configuration option is outside the supported acquisition boundary: "+key)
			}
		}
		for _, key := range []string{"onRequest", "preParsing", "preValidation", "preHandler"} {
			if v := props[key]; v != nil {
				currentStage = key
				hook(v)
			}
		}
		if v := props["routes"]; v != nil {
			config(v)
		}
		for _, key := range []string{"schema", "validate"} {
			if v := props[key]; v != nil {
				e := m.evidence("http_schema", v)
				out = append(out, e)
				stages = append(stages, analysis.InputStage{Name: "validation", Order: 40, Scope: currentScope, Evidence: e})
				more, missing := s.schemaContext(m, v, 0)
				out = append(out, more...)
				gaps = append(gaps, missing...)
			}
		}
		for _, key := range []string{"ext", "pre", "validatorCompiler", "attachValidation"} {
			if v := props[key]; v != nil {
				out = append(out, m.evidence("http_configuration", v))
				addGap(v, "custom lifecycle/validation override is outside the supported boundary")
			}
		}
	}
	// Capture instance defaults as well as route-local configuration.
	if instance := topVariable(m, receiver); instance != nil {
		if args := instance.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 0 {
			currentScope = "instance"
			config(args.NamedChild(0))
			currentScope = "route"
		}
	}
	fn := site.ChildByFieldName("function")
	prop := fn.ChildByFieldName("property")
	args := site.ChildByFieldName("arguments")
	if prop.Utf8Text(m.src) == "route" {
		opts := args.NamedChild(0)
		if framework == "hapi" {
			if v := property(opts, "options", m.src); v != nil {
				config(v)
			}
		} else {
			config(opts)
		}
	} else if args.NamedChildCount() > 2 {
		config(args.NamedChild(1))
	}
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || p == nil || obj.Utf8Text(m.src) != receiver {
			return
		}
		a := call.ChildByFieldName("arguments")
		if a == nil {
			return
		}
		switch p.Utf8Text(m.src) {
		case "addHook", "ext", "register", "plugin", "setValidatorCompiler", "setSchemaController", "addContentTypeParser", "decorateRequest":
		default:
			return
		}
		if call.StartByte() > site.StartByte() {
			addGap(call, "late lifecycle registration applicability is not modeled")
		}
		if !directNodeRegistration(call) {
			addGap(call, "conditional/deferred lifecycle applicability is not modeled")
			return
		}
		currentScope = "instance"
		switch p.Utf8Text(m.src) {
		case "addHook":
			out = append(out, m.evidence("http_hook_registration", call))
			if a.NamedChildCount() != 2 {
				addGap(call, "dynamic hook registration")
				return
			}
			name, ok := stringLiteral(a.NamedChild(0), m.src)
			if !ok {
				addGap(call, "dynamic lifecycle stage")
				return
			}
			switch name {
			case "onRequest", "preParsing", "preValidation", "preHandler":
				currentStage = name
				hook(a.NamedChild(1))
			default:
				addGap(call, "lifecycle stage is outside the supported boundary")
			}
		case "ext", "register", "plugin", "setValidatorCompiler", "setSchemaController", "addContentTypeParser", "decorateRequest":
			out = append(out, m.evidence("http_configuration", call))
			addGap(call, "plugin, extension, parser or custom validation scope is not modeled")
		}
	})
	sort.SliceStable(stages, func(i, j int) bool {
		a, b := stages[i], stages[j]
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		if a.Scope != b.Scope {
			return a.Scope == "instance"
		}
		return false // preserve registration/array order, not handler declaration offsets
	})
	return out, gaps, stages
}

// nativeHTTPChain is shared by query/command assembly; framework-specific
// registration syntax has already been lowered into this context.
func (s *moduleSet) nativeHTTPChain(c *nodeHTTPContext) ([]analysis.Evidence, []analysis.Gap) {
	context := []analysis.Evidence{c.registration.evidence("route_registration", c.call), c.handler.evidence("invoked_callable", c.body), c.registration.evidence("framework_binding", topVariable(c.registration, c.receiver))}
	context = append(context, c.controls...)
	gaps := append([]analysis.Gap{}, c.gaps...)
	gaps = append(gaps, s.inputHelperGaps(c.handler, c.body, c.request, s.contextFields)...)
	seen := map[string]bool{}
	s.includeHelpers(c.handler, c.body, &context, seen, 0)
	return context, gaps
}

func nodeStageOrder(name string) int {
	switch name {
	case "onRequest":
		return 10
	case "preParsing":
		return 20
	case "preValidation":
		return 30
	case "validation":
		return 40
	case "preHandler":
		return 50
	}
	return 0
}
