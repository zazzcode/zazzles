package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type value struct {
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
}
type flow struct {
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
		return f.statements(n)
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
		f.branches(n)
	case "lexical_declaration", "variable_declaration":
		for j := uint(0); j < n.NamedChildCount(); j++ {
			d := n.NamedChild(j)
			name := d.ChildByFieldName("name")
			if name == nil {
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
		return n.Kind() == "throw_statement"
	case "function_declaration", "comment", "empty_statement":
	case "for_in_statement":
		if !f.clientForOf(n) {
			f.branches(n)
		}
	default:
		f.branches(n)
	}
	return false
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
		env    map[string]value
		branch *analysis.Evidence
	}
	saved := copyValues(f.env)
	var exits []exit
	runs := 0
	run := func(body *sitter.Node, branch *analysis.Evidence) {
		runs++
		f.env = copyValues(saved)
		if !f.statement(body) {
			exits = append(exits, exit{f.env, branch})
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
	if bodies := len(exits); bodies < runs {
		f.gaps = append(f.gaps, f.gap("branch_exit", "a branch returns or throws; its condition may guard later code", n))
	}
	if !complete {
		exits = append(exits, exit{saved, nil})
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
			v.gaps = append(v.gaps, f.gap("unsupported_write", "heap/property assignment is not modeled", n))
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
			v.gaps = append(v.gaps, f.gap("unsupported_write", "heap/property assignment is not modeled", n))
		}
		return v
	case "object":
		v := value{fields: map[string]value{}}
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
		v := f.children(n)
		v.gaps = append(v.gaps, f.gap("async_response_unresolved", "await response/continuation semantics not modeled", n))
		return f.transfer(v, "await", n)
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
		case "body", "query", "params", "headers", "cookies":
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
				case "body", "query", "params", "headers", "cookies":
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
		if v, handled := f.clientCall(n, fn, args); handled {
			return v
		}
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
		}
	}
	if name == "fetch" || name == "axios" || strings.HasPrefix(name, "axios.") {
		kind = "outbound_http_candidate"
	}
	if kind != "" {
		v := value{}
		for i, a := range values {
			if kind == "sql_query_candidate" {
				a.deps = append([]analysis.Dependency{}, a.deps...)
				slot := "sql_options"
				if i == 0 {
					slot = "sql_text"
				}
				for j := range a.deps {
					a.deps[j].SinkSlot = slot
				}
			}
			v = combine(v, a)
		}
		if len(v.deps) > 0 || len(v.gaps) > 0 || kind == "outbound_http_candidate" {
			gaps := append(append([]analysis.Gap{}, f.gaps...), v.gaps...)
			gaps = append(gaps, f.structureGaps(kind, args, values, n)...)
			gaps = append(gaps, f.gap("sink_binding_unverified", "candidate API shape; library binding/argument roles require review", n))
			if kind == "outbound_http_candidate" {
				gaps = append(gaps, f.gap("external_response_unresolved", "remote response and asynchronous continuation are not modeled", n))
			}
			context := append([]analysis.Evidence{}, f.context...)
			f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, n.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: v.deps, Context: context, Gaps: gaps, Assessment: analysis.Assessment{Status: "not_run"}})
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
