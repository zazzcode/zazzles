package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type value struct {
	pathArchive        string
	pathArchiveBinding *analysis.Evidence
	pathObjectClosed   bool
	grpcInput          *grpcInput
	grpcTransfers      []analysis.Evidence
	graphqlArgs        *analysis.Evidence
	graphqlTransfers   []analysis.Evidence
	domNode            bool
	jqueryNode         bool
	urlParams          bool
	trustedContext     string
	apiPath, apiMethod string
	// responseField is the JSON path read from an API response ("data[].id"); "*" when ambiguous.
	responseField string
	model         string
	read          *analysis.Evidence
	fields        map[string]value
	templateFile  string
	outputHTML    bool
	outputContext string
	deps          []analysis.Dependency
	gaps          []analysis.Gap
	// web is the web-request-v1 object kind this value is (searchParams,
	// headers, formData, ...); "" for ordinary values.
	web string
}
type flow struct {
	// web is the web-request acquisition context of a Next.js entry; nil elsewhere.
	web          *webState
	constants    registrationSeeds
	client       *clientContext
	response     string
	responseType string
	registration *sourceModule
	module       *sourceModule
	set          *moduleSet
	entry        analysis.EntryPoint
	invocation   analysis.InvocationContext
	request      string
	env          map[string]value
	context      []analysis.Evidence
	gaps         []analysis.Gap
	uses         []analysis.CandidateUse
	returns      []value
	work         int
	depth        int
	helpers      *helperExpansion
	facts        *inputFacts
	// parts maps destructured request-parameter names (query, body, ...) to their container.
	parts map[string]string
	// setterValue, inside a model attribute setter, receives what the setter stores.
	setterValue *value
	// heapWrites records unmodeled heap/property writes whose expression value is
	// discarded. A conditional join keeps them as gaps for later code.
	heapWrites []analysis.Gap
	// conditions, when set, collects the modeled conditionals of a helper body so
	// the helper keeps its precision policy for tests that may guard content.
	conditions *[]modeledCondition
}

// modeledCondition is one conditional the flow modeled precisely: its test and
// whether an arm left the statement.
type modeledCondition struct {
	test  *sitter.Node
	exits bool
}

func (f *flow) gap(kind, detail string, n *sitter.Node) analysis.Gap {
	g := analysis.Gap{Kind: kind, Detail: detail}
	if n != nil {
		g.At = spanOf(f.module.file, n)
	}
	return g
}

// statements returns true when every path through body leaves by return or throw.
func (f *flow) statements(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	if body.Kind() != "statement_block" && body.Kind() != "program" {
		// An expression-bodied function returns that expression. The route handler's
		// own implicit return is recorded and then ignored by the caller.
		f.returns = append(f.returns, f.transfer(f.eval(body), "return_value", body))
		return true
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		if f.statement(body.NamedChild(i)) {
			return true
		}
	}
	return false
}

func (f *flow) statement(n *sitter.Node) bool {
	switch n.Kind() {
	case "statement_block":
		return f.block(n)
	case "if_statement":
		if yes, known := f.registrationCondition(n.ChildByFieldName("condition")); known {
			f.context = append(f.context, f.module.evidence("conditional_test", n.ChildByFieldName("condition")))
			if yes {
				return f.statement(n.ChildByFieldName("consequence"))
			}
			if alt := n.ChildByFieldName("alternative"); alt != nil && alt.NamedChildCount() > 0 {
				return f.statement(alt.NamedChild(alt.NamedChildCount() - 1))
			}
			return false
		}
		return f.conditional(n)
	case "lexical_declaration", "variable_declaration":
		for j := uint(0); j < n.NamedChildCount(); j++ {
			d := n.NamedChild(j)
			name := d.ChildByFieldName("name")
			if name == nil {
				continue
			}
			if f.reactState(d, name) {
				continue
			}
			v := f.eval(d.ChildByFieldName("value"))
			if name.Kind() == "identifier" {
				f.env[name.Utf8Text(f.module.src)] = f.transfer(v, "assignment", d)
				if name.Utf8Text(f.module.src) == f.request {
					f.request = ""
				}
				if name.Utf8Text(f.module.src) == f.response {
					f.response = ""
				}
			} else {
				if name.Kind() == "object_pattern" {
					for k := uint(0); k < name.NamedChildCount(); k++ {
						binding := name.NamedChild(k)
						if f.web != nil && v.web != "" {
							if local, prop, key := patternBinding(binding, f.module.src); local != "" {
								if wv, ok := f.webProjection(v, prop, key); ok {
									f.env[local] = wv
									continue
								}
							}
						}
						if binding.Kind() == "shorthand_property_identifier_pattern" {
							f.env[binding.Utf8Text(f.module.src)] = f.transfer(v, "field_projection", binding)
						} else {
							f.gaps = append(f.gaps, f.gap("unsupported_binding", "destructuring alias/default not modeled", binding))
						}
					}
				} else {
					f.gaps = append(f.gaps, f.gap("unsupported_binding", "binding not modeled", d))
				}
			}
		}
	case "return_statement":
		var v value
		if n.NamedChildCount() > 0 {
			v = f.eval(n.NamedChild(0))
		}
		f.returns = append(f.returns, f.transfer(v, "return_value", n))
		return true
	case "expression_statement", "throw_statement":
		if n.NamedChildCount() > 0 {
			f.eval(n.NamedChild(0))
		}
		// The shared guard engine treats the Node global process.exit as an exit too.
		return n.Kind() == "throw_statement" || (n.NamedChildCount() == 1 && (f.module.nodeProcessExit(n.NamedChild(0)) || nextNavigationExit(f.module, n.NamedChild(0))))
	case "function_declaration", "comment", "empty_statement":
	case "for_in_statement":
		if f.pathArchiveForOf(n) {
			return false
		}
		if !f.clientForOf(n) {
			f.branches(n)
		}
	default:
		f.branches(n)
	}
	return false
}

// heapWrite returns the gap for an unmodeled heap write and records it for
// conditional joins, where the discarded expression value would otherwise lose it.
func (f *flow) heapWrite(detail string, n *sitter.Node) analysis.Gap {
	g := f.gap("unsupported_write", detail, n)
	f.heapWrites = append(f.heapWrites, g)
	return g
}

// block runs a nested statement block. let/const/class bindings it declares are
// block scoped: after the block, a shadowed outer binding is restored and a new
// one is removed, so it cannot leak into a sibling branch or later code.
func (f *flow) block(n *sitter.Node) bool {
	names := blockDeclarations(n, f.module.src)
	if len(names) == 0 {
		return f.statements(n)
	}
	type saved struct {
		v     value
		bound bool
	}
	prior := map[string]saved{}
	for _, name := range names {
		v, ok := f.env[name]
		prior[name] = saved{v, ok}
	}
	request, response := f.request, f.response
	exits := f.statements(n)
	for _, name := range names {
		if p := prior[name]; p.bound {
			f.env[name] = p.v
		} else {
			delete(f.env, name)
		}
		if name == request && request != "" {
			f.request = request
		}
		if name == response && response != "" {
			f.response = response
		}
	}
	return exits
}

// blockDeclarations lists the names a block's own let/const/class declarations bind.
func blockDeclarations(n *sitter.Node, src []byte) []string {
	var names []string
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	var pattern func(*sitter.Node)
	pattern = func(p *sitter.Node) {
		if p == nil {
			return
		}
		switch p.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			add(p.Utf8Text(src))
			return
		case "pair_pattern":
			pattern(p.ChildByFieldName("value"))
			return
		case "assignment_pattern":
			pattern(p.ChildByFieldName("left"))
			return
		}
		for i := uint(0); i < p.NamedChildCount(); i++ {
			pattern(p.NamedChild(i))
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "lexical_declaration":
			for j := uint(0); j < c.NamedChildCount(); j++ {
				if d := c.NamedChild(j); d.Kind() == "variable_declarator" {
					pattern(d.ChildByFieldName("name"))
				}
			}
		case "class_declaration":
			if name := c.ChildByFieldName("name"); name != nil {
				add(name.Utf8Text(src))
			}
		}
	}
	return names
}

// branches explores the bodies of a statement the flow does not model precisely.
// Each body that can fall through contributes its exit environment; an if without
// else, and every other construct, also keeps the path that skips all bodies.
// This is a may-depend relationship, not a proven witness.
func (f *flow) branches(n *sitter.Node) {
	// Preserve branch evidence without claiming a resolved control-flow path.
	f.gaps = append(f.gaps, f.gap("unsupported_control_flow", "statement not traversed: "+n.Kind(), n))
	f.context = append(f.context, f.module.evidence("control_statement", n))
	if condition := n.ChildByFieldName("condition"); condition != nil {
		f.noteWeakCondition(condition)
		f.eval(condition)
	}
	type exit struct {
		env               map[string]value
		branch            *analysis.Evidence
		request, response string
	}
	saved := copyValues(f.env)
	request, response := f.request, f.response
	var exits []exit
	runs := 0
	baseContext := append([]analysis.Evidence{}, f.context...)
	var added []analysis.Evidence
	run := func(body *sitter.Node, branch *analysis.Evidence) {
		runs++
		f.env = copyValues(saved)
		// Each body starts from the request/response identifiers and the context
		// before the statement; one body's path controls never reach another.
		f.request, f.response = request, response
		f.context = append([]analysis.Evidence{}, baseContext...)
		defer func() { added = append(added, f.context[len(baseContext):]...) }()
		if !f.statement(body) {
			exits = append(exits, exit{f.env, branch, f.request, f.response})
		}
	}
	complete := false
	if n.Kind() == "if_statement" {
		condition := n.ChildByFieldName("condition")
		if body := n.ChildByFieldName("consequence"); body != nil {
			e := f.module.evidence("branch_consequence", condition)
			run(body, &e)
		}
		if alternative := n.ChildByFieldName("alternative"); alternative != nil {
			complete = true
			e := f.module.evidence("branch_alternative", condition)
			for j := uint(0); j < alternative.NamedChildCount(); j++ {
				if c := alternative.NamedChild(j); c.Kind() != "comment" {
					run(c, &e)
				}
			}
		}
	} else {
		switch n.Kind() {
		case "switch_statement":
			// Case/default bodies are field-named "body" (possibly several); they are
			// never statement_block children of the switch itself.
			if body := n.ChildByFieldName("body"); body != nil {
				for j := uint(0); j < body.NamedChildCount(); j++ {
					c := body.NamedChild(j)
					if c.Kind() != "switch_case" && c.Kind() != "switch_default" {
						continue
					}
					if value := c.ChildByFieldName("value"); value != nil {
						f.eval(value)
					}
					for k := uint(0); k < c.ChildCount(); k++ {
						child := c.Child(k)
						if !child.IsNamed() || c.FieldNameForChild(uint32(k)) != "body" {
							continue
						}
						run(child, nil)
					}
				}
			}
		case "labeled_statement", "while_statement", "for_statement", "do_statement", "for_in_statement":
			// Brace-less loop/label bodies are expression_statement (or other
			// non-block) under the "body" field; the generic walk below misses them.
			if body := n.ChildByFieldName("body"); body != nil {
				run(body, nil)
			}
		default:
			for j := uint(0); j < n.NamedChildCount(); j++ {
				c := n.NamedChild(j)
				switch c.Kind() {
				case "statement_block":
					run(c, nil)
				case "else_clause", "catch_clause", "finally_clause":
					if body := c.ChildByFieldName("body"); body != nil {
						run(body, nil)
					} else if c.NamedChildCount() > 0 {
						run(c.NamedChild(c.NamedChildCount()-1), nil)
					}
				}
			}
		}
	}
	if bodies := len(exits); bodies < runs {
		f.gaps = append(f.gaps, f.gap("branch_exit", "a branch returns or throws; its condition may guard later code", n))
	}
	if !complete {
		exits = append(exits, exit{saved, nil, request, response})
	}
	// A body may run zero times or only partly: later code keeps the binding
	// evidence the bodies found, never a path control recorded inside one.
	f.context = joinArmContext(baseContext, added, nil)
	// An identifier still bound on some continuing path keeps its role there; a
	// path that rebinds it is a may-change, not a removal of the feasible source.
	f.request, f.response = "", ""
	rebound := false
	for _, e := range exits {
		if e.request == request {
			f.request = request
		}
		if e.response == response {
			f.response = response
		}
		rebound = rebound || e.request != request || e.response != response
	}
	if len(exits) == 0 {
		f.request, f.response = request, response
	}
	if rebound {
		f.gaps = append(f.gaps, f.gap("unknown_control_effect", "request or response identifier may be rebound on a path", n))
	}
	merged := map[string]value{}
	keys := map[string]bool{}
	for _, e := range exits {
		for key := range e.env {
			keys[key] = true
		}
	}
	for key := range keys {
		// A dependency present on every exit is not specific to one branch. Others
		// keep the branch condition as a precondition of that path.
		count := map[string]int{}
		for _, e := range exits {
			seen := map[string]bool{}
			for _, d := range e.env[key].deps {
				if k := dependencyKey(d); !seen[k] {
					seen[k] = true
					count[k]++
				}
			}
		}
		var v value
		for _, e := range exits {
			branch := e.env[key]
			if e.branch != nil {
				branch = tagBranch(branch, *e.branch, func(d analysis.Dependency) bool { return count[dependencyKey(d)] < len(exits) }, 0)
			}
			v = combine(v, branch)
		}
		if len(exits) > 0 && exits[0].env[key].graphqlArgs != nil {
			marker := exits[0].env[key].graphqlArgs
			unchanged := true
			for _, e := range exits {
				unchanged = unchanged && e.env[key].graphqlArgs == marker
			}
			if unchanged {
				v.graphqlArgs = marker
				v.graphqlTransfers = append([]analysis.Evidence{}, exits[0].env[key].graphqlTransfers...)
			}
		}
		if len(exits) > 0 && exits[0].env[key].grpcInput != nil {
			marker := exits[0].env[key].grpcInput
			unchanged := true
			for _, e := range exits {
				unchanged = unchanged && e.env[key].grpcInput == marker
			}
			if unchanged {
				v.grpcInput = marker
				v.grpcTransfers = append([]analysis.Evidence{}, exits[0].env[key].grpcTransfers...)
			}
		}
		v.gaps = append(v.gaps, f.gap("unknown_control_effect", "value may change across unsupported control flow", n))
		merged[key] = v
	}
	if len(exits) == 0 {
		// Every explored body leaves; keep the prior bindings for any later statements.
		merged = saved
	}
	f.env = merged
}

func (f *flow) eval(n *sitter.Node) value {
	if n == nil {
		return value{}
	}
	f.work++
	if f.work > 10000 {
		gap := f.gap("work_limit", "handler expression work limit reached", n)
		if f.work == 10001 {
			f.gaps = append(f.gaps, gap)
		}
		return value{gaps: []analysis.Gap{gap}}
	}
	src := f.module.src
	if v, ok := f.graphqlInputValue(n); ok {
		return v
	}
	if f.client != nil {
		if v, ok := f.clientValue(n); ok {
			return v
		}
		if v, ok := f.clientJSX(n); ok {
			return v
		}
	}
	if v, ok := f.pathArchiveValue(n); ok {
		return v
	}
	if f.web != nil {
		if v, ok := f.webValue(n); ok {
			return v
		}
		if v, ok := f.serverJSX(n); ok {
			return v
		}
	}
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier":
		if v, ok := f.env[n.Utf8Text(src)]; ok {
			return v
		}
		if f.parts[n.Utf8Text(src)] != "" && f.nodeFieldAvailable(n) {
			source := f.module.evidence("input_source", n)
			f.rememberInput(source)
			return value{deps: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{}}}}
		}
		return value{gaps: []analysis.Gap{f.gap("unknown_value", "unresolved local value: "+n.Utf8Text(src), n)}}
	case "member_expression", "subscript_expression":
		partField := f.partField(n)
		if (partField != nil || isRequestField(n, src, f.request) || f.hapiPayload(n)) && f.nodeFieldAvailable(n) {
			sourceNode := n
			if partField != nil {
				sourceNode = partField
			} else if field := requestFieldNode(n, src, f.request); field != nil {
				sourceNode = field
			}
			source := f.module.evidence("input_source", sourceNode)
			f.rememberInput(source)
			v := value{deps: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{}}}}
			// A length read directly on the field is a derived fact, not its content.
			if obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property"); n.Kind() == "member_expression" && obj != nil && prop != nil &&
				prop.Utf8Text(src) == "length" && obj.StartByte() == sourceNode.StartByte() && obj.EndByte() == sourceNode.EndByte() {
				return f.transfer(v, "property_read", n)
			}
			return v
		}
		if v, ok := f.storedProperty(n); ok {
			return v
		}
		obj := n.ChildByFieldName("object")
		base := f.eval(obj)
		if v, ok := f.grpcProjection(n, base); ok {
			return v
		}
		v := base
		segment := "[]"
		if n.Kind() == "member_expression" {
			if prop := n.ChildByFieldName("property"); prop != nil {
				segment = prop.Utf8Text(src)
			}
		} else {
			v = combine(v, f.eval(n.ChildByFieldName("index")))
		}
		if base.apiPath != "" && base.responseField != "*" {
			v.responseField = joinField(base.responseField, segment)
		}
		v.deps = fieldDeps(v.deps, segment)
		return f.transfer(v, "property_read", n)
	case "assignment_expression":
		left := n.ChildByFieldName("left")
		v := f.transfer(f.eval(n.ChildByFieldName("right")), "assignment", n)
		if f.client != nil && f.clientAssignment(n, left, v) {
			return v
		}
		if left != nil && left.Kind() == "identifier" {
			f.env[left.Utf8Text(src)] = v
			if left.Utf8Text(src) == f.request {
				f.request = ""
			}
			if left.Utf8Text(src) == f.response {
				f.response = ""
			}
		} else if !f.assignLocalField(left, v) {
			f.assignStoredField(left, v)
			v.gaps = append(v.gaps, f.heapWrite("heap/property assignment is not modeled", n))
		}
		return v
	case "augmented_assignment_expression":
		// a += b keeps a's prior dependencies and adds b's (string building).
		left := n.ChildByFieldName("left")
		prior := value{}
		if left != nil && left.Kind() == "identifier" {
			prior = f.env[left.Utf8Text(src)]
		} else if left != nil {
			prior = f.eval(left)
		}
		v := f.transfer(combine(prior, f.eval(n.ChildByFieldName("right"))), "assignment", n)
		if f.client != nil && f.clientAssignment(n, left, v) {
			return v
		}
		if left != nil && left.Kind() == "identifier" {
			if _, known := f.env[left.Utf8Text(src)]; known {
				f.env[left.Utf8Text(src)] = v
			}
		} else if left != nil {
			v.gaps = append(v.gaps, f.heapWrite("heap/property assignment is not modeled", n))
		}
		return v
	case "update_expression":
		v := f.transfer(f.children(n), "expression", n)
		if arg := n.ChildByFieldName("argument"); arg != nil && arg.Kind() != "identifier" {
			v.gaps = append(v.gaps, f.heapWrite("heap/property update is not modeled", n))
		}
		return v
	case "unary_expression":
		v := f.transfer(f.children(n), "expression", n)
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(src) == "delete" {
			v.gaps = append(v.gaps, f.heapWrite("heap/property delete is not modeled", n))
		}
		return v
	case "object":
		v := value{fields: map[string]value{}, pathObjectClosed: true}
		var spread value
		for i := uint(0); i < n.NamedChildCount(); i++ {
			p := n.NamedChild(i)
			key, child := p.ChildByFieldName("key"), p.ChildByFieldName("value")
			if key != nil && child != nil {
				field := f.eval(p)
				v = combine(v, field)
				v.model, v.read = "", nil
				v.fields[key.Utf8Text(src)] = field
				f.noteTrustedField(key.Utf8Text(src), field)
			} else if p.Kind() == "shorthand_property_identifier" {
				field := f.eval(p)
				v = combine(v, field)
				v.fields[p.Utf8Text(src)] = field
			} else if p.Kind() == "spread_element" && p.NamedChildCount() == 1 {
				spread = f.eval(p.NamedChild(0))
				v.pathObjectClosed = v.pathObjectClosed && spread.pathObjectClosed
				v = combine(v, spread)
			}
		}
		// A spread row keeps its columns readable beside the listed overrides.
		v.model, v.read = spread.model, spread.read
		return v
	case "template_string":
		return f.templateString(n)
	case "new_expression":
		if f.client != nil {
			if v, ok := f.clientConstructor(n); ok {
				return v
			}
		}
		if v, ok := f.xssConstructor(n); ok {
			return v
		}
		return f.transfer(f.children(n), "expression", n)
	case "call_expression":
		if f.module.awaitedCalls[n.StartByte()] {
			return f.awaited(n, f.call(n))
		}
		return f.call(n)
	case "binary_expression":
		// Same as any expression; a comparison against a credential-named property is destination evidence.
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		l, r := f.eval(left), f.eval(right)
		f.noteCredentialComparison(n, left, l, right, r)
		return f.transfer(combine(l, r), "expression", n)
	case "pair":
		// Same transfer as any expression; a credential-named property records where the value goes.
		v := f.children(n)
		f.noteCredentialDestination(n, v)
		return f.transfer(v, "expression", n)
	case "arrow_function", "function_expression", "function":
		if f.client != nil && f.client.react {
			f.reactCallback(n, nil)
			return value{}
		}
		f.enterQueryCallback(n)
		return value{gaps: []analysis.Gap{f.gap("unsupported_callback", "callback/closure body not traversed", n)}}
	case "number", "string", "true", "false", "null", "undefined", "property_identifier", "type_identifier", "comment", "string_fragment", "escape_sequence":
		return value{}
	case "ternary_expression":
		if yes, known := f.registrationCondition(n.ChildByFieldName("condition")); known {
			f.context = append(f.context, f.module.evidence("conditional_test", n.ChildByFieldName("condition")))
			branch := "alternative"
			if yes {
				branch = "consequence"
			}
			return f.transfer(f.eval(n.ChildByFieldName(branch)), "conditional_value", n)
		}
		a := f.eval(n.ChildByFieldName("consequence"))
		b := f.eval(n.ChildByFieldName("alternative"))
		v := combine(a, b)
		v.gaps = append(v.gaps, f.gap("conditional_merge", "branch feasibility is not modeled", n))
		return f.transfer(v, "conditional_value", n)
	case "await_expression":
		return f.awaited(n, f.children(n))
	default:
		return f.transfer(f.children(n), "expression", n)
	}
}

func isRequestField(n *sitter.Node, src []byte, req string) bool {
	if n.Kind() != "member_expression" && n.Kind() != "subscript_expression" {
		return false
	}
	obj := n.ChildByFieldName("object")
	prop := n.ChildByFieldName("property")
	if obj != nil && prop != nil && obj.Kind() == "identifier" && obj.Utf8Text(src) == req {
		switch prop.Utf8Text(src) {
		case "body", "query", "params", "headers", "cookies", "payload",
			"path", "url", "originalUrl", "baseUrl", "file", "files":
			return true
		}
	}
	base := n
	for base != nil && (base.Kind() == "member_expression" || base.Kind() == "subscript_expression") {
		obj := base.ChildByFieldName("object")
		if obj != nil && obj.Kind() == "member_expression" {
			root := obj.ChildByFieldName("object")
			prop := obj.ChildByFieldName("property")
			if root != nil && prop != nil && root.Kind() == "identifier" && root.Utf8Text(src) == req {
				switch prop.Utf8Text(src) {
				case "body", "query", "params", "headers", "cookies", "payload",
					"path", "url", "originalUrl", "baseUrl", "file", "files":
					return true
				}
			}
		}
		base = obj
	}
	return false
}

func (f *flow) children(n *sitter.Node) value {
	v := value{}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		v = combine(v, f.eval(n.NamedChild(i)))
	}
	return v
}

func (f *flow) transfer(v value, kind string, n *sitter.Node) value {
	out := v
	if v.grpcInput != nil {
		out.grpcTransfers = append(append([]analysis.Evidence{}, v.grpcTransfers...), f.module.evidence(kind, n))
		if len(out.grpcTransfers) > 64 {
			out.grpcTransfers = out.grpcTransfers[:64]
			out.gaps = append(out.gaps, f.gap("transfer_limit", "gRPC object exceeds 64 transfer steps", n))
		}
	}
	if v.graphqlArgs != nil {
		out.graphqlTransfers = append(append([]analysis.Evidence{}, v.graphqlTransfers...), f.module.evidence(kind, n))
		if len(out.graphqlTransfers) > 64 {
			out.graphqlTransfers = out.graphqlTransfers[:64]
			out.gaps = append(out.gaps, f.gap("transfer_limit", "GraphQL object exceeds 64 transfer steps", n))
		}
	}
	out.deps = nil
	out.gaps = append([]analysis.Gap{}, out.gaps...)
	for _, d := range v.deps {
		if len(d.Transfers) >= 64 {
			out.gaps = append(out.gaps, f.gap("transfer_limit", "dependency exceeds 64 transfer steps", n))
			out.deps = append(out.deps, d)
			continue
		}
		d.Transfers = append(append([]analysis.Evidence{}, d.Transfers...), f.module.evidence(kind, n))
		out.deps = append(out.deps, d)
	}
	return out
}

func combine(a, b value) value {
	if a.pathArchive == "" {
		a.pathArchive = b.pathArchive
	}
	if a.pathArchiveBinding == nil {
		a.pathArchiveBinding = b.pathArchiveBinding
	}
	if a.model == "" {
		a.model, a.read = b.model, b.read
	}
	if a.fields == nil && b.fields != nil {
		a.fields = b.fields
	}
	if a.templateFile == "" {
		a.templateFile = b.templateFile
	}
	a.outputHTML = a.outputHTML || b.outputHTML
	a.domNode = a.domNode || b.domNode
	a.jqueryNode = a.jqueryNode || b.jqueryNode
	a.urlParams = a.urlParams || b.urlParams
	if a.trustedContext == "" {
		a.trustedContext = b.trustedContext
	}
	if a.apiPath == "" {
		a.apiPath, a.apiMethod, a.responseField = b.apiPath, b.apiMethod, b.responseField
	} else if b.apiPath != "" && (b.apiPath != a.apiPath || b.responseField != a.responseField) {
		a.responseField = "*"
	}
	if a.outputContext == "" {
		a.outputContext = b.outputContext
	}
	// A web object kind survives only an accumulation from an empty value.
	switch {
	case a.web == b.web:
	case a.web == "" && len(a.deps) == 0:
		a.web = b.web
	case b.web == "" && len(b.deps) == 0:
	default:
		a.web = ""
	}
	// An identical source path reached twice (for example an unchanged value on
	// two merged branches) is one path; distinct transfer sequences stay separate.
	deps := append([]analysis.Dependency{}, a.deps...)
	seen := map[string]bool{}
	for _, d := range deps {
		seen[dependencyKey(d)] = true
	}
	for _, d := range b.deps {
		if k := dependencyKey(d); !seen[k] {
			seen[k] = true
			deps = append(deps, d)
		}
	}
	a.deps = deps
	a.gaps = append(append([]analysis.Gap{}, a.gaps...), b.gaps...)
	if len(a.deps) > 64 {
		a.deps = a.deps[:64]
		a.gaps = append(a.gaps, analysis.Gap{Kind: "dependency_limit", Detail: "more than 64 dependencies; remaining paths unexamined", At: a.deps[0].Source.Span})
	}
	if len(a.gaps) > 64 {
		a.gaps = uniqueGaps(a.gaps)
	}
	if len(a.gaps) > 64 {
		a.gaps = append(a.gaps[:63], analysis.Gap{Kind: "gap_limit", Detail: "additional uncertainty reasons omitted", At: a.gaps[0].At})
	}
	return a
}

// call adds the storage and token facts of a call to its ordinary value flow.
func (f *flow) call(n *sitter.Node) value {
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if f.setterValue != nil && fn != nil && args != nil && fn.Utf8Text(f.module.src) == "this.setDataValue" && args.NamedChildCount() == 2 {
		*f.setterValue = combine(*f.setterValue, f.eval(args.NamedChild(1)))
		return value{}
	}
	v := f.evalCall(n)
	if fn == nil || args == nil || f.client != nil {
		return v
	}
	f.noteTokenSigning(fn, args)
	f.sqlWrite(n, fn, args)
	if model, read, ok := f.sqlRead(n, fn, args); ok {
		v.model, v.read = model, read
	}
	return v
}

func (f *flow) evalCall(n *sitter.Node) value {
	if v, ok := f.pathImmediate(n); ok {
		return v
	}
	fn := n.ChildByFieldName("function")
	args := n.ChildByFieldName("arguments")
	if fn == nil {
		return value{}
	}
	name := fn.Utf8Text(f.module.src)
	if input, evidence := nativeHashHex(f.module, n); input != nil {
		v := f.eval(input)
		for _, e := range evidence {
			f.context = append(f.context, e)
			if e.Kind == "native_hash_hex" {
				v = f.transfer(v, e.Kind, n)
			}
		}
		return v
	}
	if f.client != nil {
		if v, handled := f.reactCall(n, fn, args); handled {
			return v
		}
		if v, handled := f.clientCall(n, fn, args); handled {
			return v
		}
	}
	// Recording a filesystem candidate is additive and precedes the template-file
	// read model, which otherwise consumes fs.readFile calls whole.
	if f.client == nil {
		f.pathCall(n, fn, args)
	}
	if modeled, handled := f.templateCall(n, fn, args); handled {
		return modeled
	}
	// An outer chained call must still visit its receiver, including a query call.
	// Its result is kept so a.b().c() still depends on what a.b() depended on.
	var chained value
	if fn.Kind() == "member_expression" {
		obj := fn.ChildByFieldName("object")
		if obj != nil && (obj.Kind() == "call_expression" || obj.Kind() == "new_expression") {
			chained = f.eval(obj)
		}
	}
	modelValue, modelCall := f.modelCallValue(n, fn, chained)
	var values []value
	var mapped *value
	if args != nil {
		for i := uint(0); i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			if isFunction(arg) && modelCall {
				result := f.modelCallback(arg, modelValue, name)
				if strings.HasSuffix(name, ".map") {
					mapped = &result
				}
				values = append(values, value{})
			} else if isFunction(arg) && f.client == nil && (continuationCall(fn, f.module.src) || f.respondsInCallback(arg)) {
				f.enterContinuation(arg)
				values = append(values, value{})
			} else {
				values = append(values, f.eval(arg))
			}
		}
	}
	if mapped != nil {
		return f.transfer(*mapped, "collection_map", n)
	}
	if f.responseCall(n, fn, args, values) {
		return value{}
	}
	if f.nextJSONResponse(n, fn, values) {
		return value{gaps: []analysis.Gap{f.gap("unknown_call_result", "response object is not modeled", n)}}
	}
	// Recording a process candidate is additive: the call is then handled exactly as
	// before, so existing candidates, gaps and identities are unchanged.
	f.commandCall(n, fn, args)
	if modelCall {
		f.recordStorageWrite(n, fn, args, values, modelValue)
	}
	// A verified logger is an emission sink, not a validator of its arguments.
	if binding, ok := f.logSink(n, fn); ok {
		f.recordLogSink(n, binding, values)
		return value{gaps: []analysis.Gap{f.gap("unknown_call_result", "logger return value is not modeled", n)}}
	}
	kind := queryKind(name, args, f.module.src, values)
	if kind == "" && modelCall && strings.HasPrefix(modelValue.model, "mongoose:") && requestDeps(values) {
		if prop := fn.ChildByFieldName("property"); prop != nil {
			switch prop.Utf8Text(f.module.src) {
			case "find", "findOne", "findById", "update", "updateOne", "deleteOne":
				kind = "nosql_query_candidate"
			}
		}
	}
	if kind == "" && f.set != nil && len(values) > 0 {
		if _, _, ok := f.set.prismaFilterCall(f.module, n); ok && f.set.unvalidatedBody(values[0].fields["where"]) {
			kind = "nosql_query_candidate"
		}
	}
	if kind == "" && collectionWrite(name) && requestDeps(values) && f.set != nil {
		probe := analysis.CandidateUse{Sink: f.module.evidence("nosql_query_candidate", n)}
		if len(f.set.collectionBinding(probe)) > 0 {
			kind = "nosql_query_candidate"
		}
	}
	if kind == "" && f.client == nil && len(values) > 0 && len(values[0].deps) > 0 {
		// Only request data in the SQL text slot is a claim; a bound values array is not.
		if _, ok := sqlJSCall(f.module, fn); ok {
			kind = "sql_query_candidate"
		} else if f.set != nil {
			if _, _, _, ok := f.set.sqlLibraryCall(f.module, n); ok {
				kind = "sql_query_candidate"
			}
		}
	}
	var outbound *analysis.OutboundFacts
	var outboundBinding []analysis.Evidence
	op, contract, binding, dest, verified := f.outboundOperation(n, fn, args)
	// Name-shaped clients (fetch/axios/http/https.*) stay outbound observations even when
	// the binding is shadowed; never treat every unrelated `.get` / `.request` as outbound.
	isNamedClient := name == "fetch" || name == "axios" || strings.HasPrefix(name, "axios.") ||
		strings.HasPrefix(name, "http.") || strings.HasPrefix(name, "https.")
	if verified || isNamedClient {
		kind = "outbound_http_candidate"
		var destNode *sitter.Node
		destValue := value{}
		if args != nil && args.NamedChildCount() > 0 && len(values) > 0 {
			destNode, destValue = args.NamedChild(0), values[0]
			if dest > 0 && dest < len(values) {
				destNode, destValue = args.NamedChild(uint(dest)), values[dest]
			}
		}
		if verified && (strings.HasPrefix(op, "http.") || strings.HasPrefix(op, "https.")) && destNode != nil && destNode.Kind() == "object" {
			destValue = f.httpOptionsDestination(destNode, destValue)
		}
		outbound = &analysis.OutboundFacts{DestinationOrigin: f.destinationOrigin(n, destNode, destValue)}
		internalPath := false
		if verified && outbound.DestinationOrigin == analysis.DestinationRequest && f.web != nil && f.fixedOriginRequestPath(destNode) {
			// A fixed (constant or configured) origin with a request-derived path is
			// a request into the app's own or a fixed service: a path observation
			// (request_path_in_internal_url), never forgery of an attacker-chosen host.
			internalPath = true
			g := f.gap("request_path_in_internal_url", "a request-derived value is inserted into the path of a fixed-origin server request; ../ or %2F may redirect it to another internal endpoint", destNode)
			for i := range values {
				if i == dest || (dest <= 0 && i == 0) {
					values[i].gaps = append(append([]analysis.Gap{}, values[i].gaps...), g)
				}
			}
		}
		if verified && outbound.DestinationOrigin == analysis.DestinationRequest && !internalPath {
			// A verified client with a request-derived destination is an SSRF claim
			// over that operand only; other arguments are data, not destination control.
			kind = "ssrf_candidate"
			outbound.Operation, outbound.ContractID = op, contract
			outboundBinding = binding
			values = []value{destValue}
		}
	}
	if kind != "" {
		v := value{}
		for i, a := range values {
			if kind == "sql_query_candidate" {
				a.deps = append([]analysis.Dependency{}, a.deps...)
				slot := "sql_options"
				if i == 0 {
					slot = "sql_text"
					if sequelizeFinderName(name) {
						// A finder's where object holds bound values, not SQL text.
						slot = "finder_value"
					}
				}
				for j := range a.deps {
					a.deps[j].SinkSlot = slot
				}
			}
			if kind == "ssrf_candidate" {
				a.deps = append([]analysis.Dependency{}, a.deps...)
				for j := range a.deps {
					a.deps[j].SinkSlot = analysis.OutboundSlotDestination
				}
			}
			v = combine(v, a)
		}
		if len(v.deps) > 0 || len(v.gaps) > 0 || kind == "outbound_http_candidate" {
			gaps := append(append([]analysis.Gap{}, f.gaps...), v.gaps...)
			gaps = append(gaps, f.structureGaps(kind, args, values, n)...)
			if kind != "ssrf_candidate" {
				gaps = append(gaps, f.gap("sink_binding_unverified", "candidate API shape; library binding/argument roles require review", n))
			}
			if kind == "outbound_http_candidate" || kind == "ssrf_candidate" {
				gaps = append(gaps, f.gap("external_response_unresolved", "remote response and asynchronous continuation are not modeled", n))
			}
			context := append([]analysis.Evidence{}, f.context...)
			use := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, n.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: v.deps, Context: context, Gaps: gaps, Assessment: analysis.Assessment{Status: "not_run"}}
			if kind == "ssrf_candidate" {
				use.Context = append(use.Context, outboundBinding...)
				for i := range v.deps {
					outbound.Paths = append(outbound.Paths, analysis.CommandPath{Dependency: i, Operand: analysis.OutboundSlotDestination})
				}
			}
			if outbound != nil {
				use.Outbound = outbound
			}
			f.uses = append(f.uses, use)
		}
		// Response values are new external sources, never aliases of request arguments.
		if modelCall {
			return modelValue
		}
		return value{gaps: []analysis.Gap{f.gap("unknown_call_result", "sink/transport return value is not modeled", n)}}
	}
	if modelCall {
		return modelValue
	}
	if v, ok := f.validationHelperCall(n, values); ok {
		return v
	}
	ret, entered, precise := f.enterHelper(n, name, values)
	if entered && precise {
		return ret
	}
	// A helper that contains the sink is not a validator of its arguments.
	if !entered {
		if f.entry.Kind == "graphql" || f.entry.Kind == "grpc" {
			for _, v := range values {
				if len(v.deps) > 0 && !nativeStringOperation(f.module, n) {
					origin := "resolver-derived"
					if f.entry.Kind == "grpc" {
						origin = "gRPC request-derived"
					}
					f.gaps = append(f.gaps, f.gap("input_helper_unresolved", "Unresolved call receives a "+origin+" value before this operation: "+name, n))
				}
				if v.grpcInput != nil {
					f.gaps = append(f.gaps, f.gap("grpc_argument_escape", "Call/request object reaches unresolved call: "+name, n))
				}
				if v.graphqlArgs != nil {
					f.gaps = append(f.gaps, f.gap("graphql_argument_escape", "Argument object reaches an unresolved call: "+name, n))
				}
			}
		}
		f.noteInputTouch(values, name)
	}
	v := value{}
	for _, a := range values {
		v = combine(v, a)
	}
	// Method results may depend on their receiver (for example input.trim()).
	if fn.Kind() == "member_expression" {
		obj := fn.ChildByFieldName("object")
		if obj != nil && obj.Kind() != "call_expression" {
			v = combine(v, f.eval(obj))
		} else if obj != nil {
			v = combine(v, chained)
		}
	}
	if len(v.deps) > 0 {
		v.gaps = append(v.gaps, f.gap("unknown_transfer", "call may transform or discard its arguments: "+name, n))
		// enterHelper already recorded the definition when the body was analyzed.
		if !entered {
			if hm, helper := f.set.resolve(f.module, name); hm != nil && helper != nil && !shadowed(n, name, f.module.src) {
				f.context = append(f.context, hm.evidence("helper_definition", helper))
			}
		}
	}
	if len(v.deps) == 0 {
		v.gaps = append(v.gaps, f.gap("unknown_call_result", "call result is not modeled: "+name, n))
	}
	return f.transfer(v, "call_argument_dependency", n)
}

// tagBranch appends a branch condition to the selected dependencies of a value
// and of its nested fields, so a field read later keeps the same precondition.
func tagBranch(v value, branch analysis.Evidence, selected func(analysis.Dependency) bool, depth int) value {
	v.deps = append([]analysis.Dependency{}, v.deps...)
	for i, d := range v.deps {
		if selected(d) {
			d.Transfers = append(append([]analysis.Evidence{}, d.Transfers...), branch)
			v.deps[i] = d
		}
	}
	if len(v.fields) > 0 && depth < 8 {
		fields := map[string]value{}
		for k, field := range v.fields {
			fields[k] = tagBranch(field, branch, selected, depth+1)
		}
		v.fields = fields
	}
	return v
}

func dependencyKey(d analysis.Dependency) string {
	var b strings.Builder
	key := func(e analysis.Evidence) {
		fmt.Fprintf(&b, "%s:%s:%d:%d;", e.Kind, e.Span.File, e.Span.StartByte, e.Span.EndByte)
	}
	b.WriteString(d.StorageKey + "|" + d.SinkSlot + "|" + d.OutputContext + "|" + d.ResponseField + "|")
	key(d.Source)
	for _, e := range d.Transfers {
		key(e)
	}
	return b.String()
}

func copyValues(in map[string]value) map[string]value {
	out := map[string]value{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func joinField(base, segment string) string {
	switch {
	case base == "":
		return segment
	case segment == "[]":
		return base + "[]"
	}
	return base + "." + segment
}

// assignLocalField records a write such as result.data[0] = v into the fields of
// a local object value. Model instances keep their storage semantics instead.
func (f *flow) assignLocalField(left *sitter.Node, v value) bool {
	var path []string
	n := left
	for n != nil && (n.Kind() == "member_expression" || n.Kind() == "subscript_expression") {
		segment := "[]"
		if n.Kind() == "member_expression" {
			prop := n.ChildByFieldName("property")
			if prop == nil {
				return false
			}
			segment = prop.Utf8Text(f.module.src)
		}
		path = append([]string{segment}, path...)
		n = n.ChildByFieldName("object")
	}
	if n == nil || n.Kind() != "identifier" || len(path) == 0 {
		return false
	}
	name := n.Utf8Text(f.module.src)
	base, ok := f.env[name]
	if !ok || base.model != "" || base.domNode || f.client != nil {
		return false
	}
	f.env[name] = withField(base, path, v)
	return true
}

func withField(base value, path []string, v value) value {
	fields := map[string]value{}
	for k, old := range base.fields {
		fields[k] = old
	}
	child := v
	if len(path) > 1 {
		child = withField(fields[path[0]], path[1:], v)
	}
	fields[path[0]] = child
	out := combine(base, v)
	out.fields = fields
	return out
}

// fieldValue resolves a JSON path (as produced by joinField) in a value's fields.
func fieldValue(v value, path string) (value, bool) {
	if path == "" {
		return v, true
	}
	for _, segment := range strings.Split(strings.ReplaceAll(path, "[]", ".[]"), ".") {
		if segment == "" {
			continue
		}
		next, ok := v.fields[segment]
		if !ok {
			return value{}, false
		}
		v = next
	}
	return v, true
}

func continuationCall(fn *sitter.Node, src []byte) bool {
	if fn.Kind() != "member_expression" {
		return false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	switch prop.Utf8Text(src) {
	case "then", "catch", "finally":
		return true
	}
	return false
}

// enterContinuation follows a promise continuation with the handler's request,
// response and closure bindings. Its parameters are external results, not request
// data; scheduling and rejection ordering remain unmodeled.
func (f *flow) enterContinuation(fn *sitter.Node) {
	if f.depth >= 3 {
		f.gaps = append(f.gaps, f.gap("unsupported_callback", "promise continuation depth limit reached", fn))
		return
	}
	child := *f
	child.env = copyValues(f.env)
	child.context = append(append([]analysis.Evidence{}, f.context...), f.module.evidence("async_continuation", fn))
	child.gaps = append(append([]analysis.Gap{}, f.gaps...), f.gap("async_continuation", "promise continuation traversed; scheduling and rejection paths are not modeled", fn))
	child.uses, child.returns = nil, nil
	child.depth = f.depth + 1
	if params, ok := functionParameters(fn, f.module.src); ok {
		for _, p := range params {
			child.env[p.name] = value{gaps: []analysis.Gap{{Kind: "async_result_unresolved", Detail: "continuation argument is an external result: " + p.name, At: spanOf(f.module.file, p.node)}}}
			if p.name == child.request {
				child.request = ""
			}
			if p.name == child.response {
				child.response = ""
			}
		}
	}
	child.statements(fn.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	for _, g := range child.gaps[len(f.gaps)+1:] {
		switch g.Kind {
		case "work_limit", "helper_call_limit", "recursive_helper":
			f.gaps = append(f.gaps, g)
		}
	}
	f.work = child.work
}

// patternBinding returns the local name, property and key node of one object
// pattern entry: `{ id }` or `{ id: orderId }`.
func patternBinding(b *sitter.Node, src []byte) (local, prop string, key *sitter.Node) {
	switch b.Kind() {
	case "shorthand_property_identifier_pattern":
		return b.Utf8Text(src), b.Utf8Text(src), b
	case "pair_pattern":
		k, v := b.ChildByFieldName("key"), b.ChildByFieldName("value")
		if k != nil && v != nil && v.Kind() == "identifier" {
			return v.Utf8Text(src), k.Utf8Text(src), k
		}
	}
	return "", "", nil
}

// awaited applies await semantics to the value of an awaited expression n (an
// await_expression, or a generic call whose await keyword was blanked).
func (f *flow) awaited(n *sitter.Node, v value) value {
	if f.client != nil && v.apiPath != "" {
		// A verified client HTTP call resolves to its response data.
		return f.transfer(v, "await_response", n)
	}
	inner := n
	if n.Kind() == "await_expression" && n.NamedChildCount() == 1 {
		inner = unwrapTS(n.NamedChild(0))
	}
	if f.web != nil && inner.Kind() == "call_expression" && f.webAwaitable(inner) {
		return f.transfer(v, "await_request_read", n)
	}
	v.gaps = append(v.gaps, f.gap("async_response_unresolved", "await response/continuation semantics not modeled", n))
	return f.transfer(v, "await", n)
}

// fixedOriginRequestPath reports a template URL `${base}/path/${x}` whose leading
// substitution is request-independent: a dependency-free local, a no-argument
// call or a process.env read. Request data then sits only in the path or query.
func (f *flow) fixedOriginRequestPath(n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil || n.Kind() != "template_string" || n.NamedChildCount() < 2 {
		return false
	}
	first, second := n.NamedChild(0), n.NamedChild(1)
	if first.Kind() == "string_fragment" {
		// A literal scheme and host: `https://api.example.com/x/${id}`.
		text := first.Utf8Text(f.module.src)
		i := strings.Index(text, "://")
		return i > 0 && strings.Contains(text[i+3:], "/")
	}
	if first.Kind() != "template_substitution" || first.NamedChildCount() != 1 || second.Kind() != "string_fragment" || !strings.HasPrefix(second.Utf8Text(f.module.src), "/") {
		return false
	}
	base := unwrapTS(first.NamedChild(0))
	switch base.Kind() {
	case "identifier":
		v, ok := f.env[base.Utf8Text(f.module.src)]
		return ok && len(v.deps) == 0
	case "call_expression":
		args := base.ChildByFieldName("arguments")
		return args != nil && args.NamedChildCount() == 0
	case "member_expression":
		return f.environmentRead(n, base)
	}
	return false
}
