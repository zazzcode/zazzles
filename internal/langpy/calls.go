package langpy

import (
	"fmt"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

func (f *pythonFlow) call(n *sitter.Node) pythonValue {
	m := f.module
	fn := n.ChildByFieldName("function")
	name := pyText(m, fn)
	q := f.qualified(name)
	if q == "flask.render_template" {
		f.renderTemplate(n)
		return pythonValue{rendered: true}
	}
	nodes, values, all := f.callArguments(n)
	f.interpreterOperation(n, fn, nodes, values)
	if v, ok := f.regexMatch(n, q, nodes, values); ok {
		return v
	}
	if v, ok := f.regexGroup(n, fn, nodes); ok {
		return v
	}

	object := pyField(fn, "object")
	method := pyText(m, pyField(fn, "attribute"))
	var receiver pythonValue
	if object != nil {
		receiver = f.eval(object)
	}
	// Recording a filesystem candidate is additive and precedes framework call
	// models, which can consume a call such as send_from_directory whole.
	f.pathCall(n, fn, receiver, object, method)
	f.uploadCall(n, fn, object, receiver, method, nodes, values)
	if v, ok := f.frameworkCall(n, q, nodes, values, all); ok {
		return v
	}
	// Recording a process candidate is additive: the call is then handled exactly as
	// before, so existing candidates, gaps and identities are unchanged.
	f.commandCall(n, fn)

	if receiver.binding == "db_connection" && method == "cursor" {
		return pythonValue{binding: "db_cursor", driver: receiver.driver, evidence: append(receiver.evidence, m.evidence("sink_binding", n))}
	}
	connectionExecution := receiver.binding == "db_connection" && (receiver.driver == "sqlite3" || receiver.driver == "psycopg")
	operation := method == "execute" || method == "executemany" || (method == "executescript" && receiver.driver == "sqlite3")
	if (connectionExecution || receiver.binding == "db_cursor") && operation {
		result := f.sql(n, object, values, receiver)
		result.binding = "db_cursor"
		return result
	}
	if receiver.binding == "db_cursor" && (method == "fetchone" || method == "fetchall") {
		v := receiver
		v.binding = "db_row"
		v.evidence = append(v.evidence, m.evidence("storage_read", n))
		return v
	}
	if method == "get_template" && len(values) == 1 {
		if v, ok := f.jinjaFileTemplate(object, nodes[0]); ok {
			return v
		}
	}
	if receiver.binding == "jinja_file" && method == "render" {
		f.renderJinjaFile(n, receiver)
		return pythonValue{rendered: true}
	}
	if method == "append" && len(values) == 1 && f.route.route.Framework == "wsgi" && len(values[0].deps) > 0 && f.wsgiHTML() && f.wsgiDispatchBranch(n) {
		f.recordXSS(m.evidence("html_response", n), values[0], "html_text", nil)
	}
	if v, ok := f.containerWrite(n, object, method, receiver, values); ok {
		return v
	}
	if receiver.binding == "jinja_template" && method == "render" {
		arguments := all
		// Escaping affects substituted variables, never text compiled as template source.
		if receiver.constant {
			arguments = pyProtect(arguments, receiver.templateEscape)
		}
		v := pyCombine(receiver, arguments)
		v = pyTransfer(v, m.evidence("template_render", n))
		v.binding = ""
		return v
	}
	if receiver.binding == "flask_request" && (method == "get_param" || method == "get_param_as_bool") && len(nodes) > 0 {
		key, _ := pyLiteral(m, nodes[0])
		v := f.source(n, "query", key)
		if method == "get_param_as_bool" {
			v = pyProtect(v, "non_content")
		}
		return v
	}
	if callable := receiver.methods[method]; callable != nil && object != nil && object.Kind() == "identifier" {
		// self.<method>(...) in a class-based handler resolves to the registered class's method.
		return f.boundHelper(n, callable, append([]pythonValue{{}}, values...))
	}
	if q == "threading.Thread" {
		return f.threadValue(n)
	}
	if method == "start" && receiver.thread != nil {
		t := receiver.thread
		v := f.boundHelper(n, t.callable, t.args)
		_ = v
		return pythonValue{}
	}
	if method == "get" && len(values) > 0 {
		key, _ := pyLiteral(m, nodes[0])
		if len(receiver.deps) > 0 || receiver.fields != nil {
			v := f.projectValue(receiver, key, n)
			if len(values) > 1 {
				v = pyCombine(v, values[1])
			}
			return v
		}
	}
	if f.outbound(q) {
		return f.outboundCall(n, q, fn, values)
	}

	if f.logger(q, name, receiver, method, n) {
		for _, v := range values {
			all = pyCombine(all, f.logValue(n, v))
		}
		f.log(n, all)
		return pythonValue{}
	}
	if (name == "len" || name == "bool") && f.builtin(name) {
		return pyTransfer(pyProtect(all, "non_content"), m.evidence("non_content", n))
	}
	if (name == "int" || name == "float") && f.builtin(name) {
		return pyTransfer(pyProtect(all, "numeric"), m.evidence("numeric_conversion", n))
	}
	if name == "str" && f.builtin(name) {
		return pyTransfer(all, m.evidence("string_conversion", n))
	}
	if method == "format" || method == "join" {

		v := pyCombine(receiver, all)
		v.built = true
		return pyTransfer(v, m.evidence("string_construction", n))
	}
	if method == "strip" || method == "lower" || method == "upper" || method == "split" {
		return pyTransfer(pyCombine(receiver, all), m.evidence("string_transform", n))
	}
	if method == "getLogger" && strings.HasPrefix(q, "logging.") {
		return pythonValue{binding: "logger", evidence: []analysis.Evidence{m.evidence("logger_binding", n)}}
	}
	if v, ok := f.env[name]; ok && v.callable != nil {
		return f.boundHelper(n, v.callable, values)
	}
	if v, ok := f.env[name]; ok && f.route.dispatch != nil && len(v.deps) > 0 && len(v.methods) == 0 && !strings.Contains(name, ".") {
		// A callable selected by request path from a finite registry: this context
		// is one registry item, so the call resolves to that item's callable.
		bound := *f.route.dispatch
		bound.evidence = append(append([]analysis.Evidence{}, bound.evidence...), m.evidence("registry_dispatch", n))
		return f.boundHelper(n, &bound, values)
	}
	if target, key := f.set.resolve(m, name, 0); target != nil && target.funcs[key] != nil {
		// Local assignments/parameters override helper declarations and imported helpers.
		if _, shadow := f.env[strings.Split(name, ".")[0]]; !shadow && !f.set.staticInvalid[m.file+":"+strings.Split(name, ".")[0]] && !f.set.staticInvalid[target.file+":"+key] {
			if callable := f.staticCallable(n); callable != nil {
				return pythonValue{callable: callable}
			}
			return f.helper(n, target, target.funcs[key], values)
		}
	}
	if v, ok := f.finiteCall(n, name, q, values, all); ok {
		return v
	}

	v := pyCombine(receiver, all)
	if len(v.deps) > 0 {
		// parse_qs decodes a query string and keeps its content: no effect on protection.
		if q != "urllib.parse.parse_qs" {
			v = pyProtect(v, "unknown")
		}
		v = pyTransfer(v, m.evidence("call_argument_dependency", n))
		v.gaps = append(v.gaps, f.gap("python_call_unresolved", "unmodeled return/content effect: "+name, n))
		if f.route.generated {
			f.gaps = append(f.gaps, f.gap("python_dispatch_unresolved", "Request-dependent call lacks a supported callable: "+name, n))
		}
	}
	if pyPathObjectNames[q] {
		// A pathlib object keeps the value's dependencies; the receiver of a later
		// read or write method carries the effective path.
		v.binding = "pathlib_path"
	}
	if strings.HasPrefix(q, "tarfile.") && pyArchiveOpens[q] != "" {
		// Opened TarFile carries archive provenance into extractall.
		v.binding = "tarfile_archive"
	}
	return v
}
func (f *pythonFlow) builtin(name string) bool {
	_, local := f.env[name]
	return !local && f.module.vars[name] == nil && f.module.funcs[name] == nil && f.module.imports[name].node == nil
}
func (f *pythonFlow) helper(call *sitter.Node, m *pythonModule, fn *sitter.Node, values []pythonValue) pythonValue {
	return f.boundHelper(call, &pythonBoundCallable{module: m, fn: fn}, values)
}
func (f *pythonFlow) boundHelper(call *sitter.Node, callable *pythonBoundCallable, values []pythonValue) pythonValue {
	m, fn := callable.module, callable.fn
	f.context = append(f.context, callable.evidence...)
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if f.depth >= 3 || *f.work >= 24 || f.stack[key] {

		if f.closedSummaryCall(call, callable, values) {
			return pythonValue{}
		}
		if v, ok := f.applyWitness(call, callable, values); ok {
			return v
		}

		v := pythonValue{}
		for _, a := range values {
			v = pyCombine(v, a)
		}
		v = pyProtect(v, "unknown")
		v.gaps = append(v.gaps, f.gap("work_limit", "Python helper expansion depth/cycle/work limit", call))
		return v
	}
	*f.work++
	f.stack[key] = true
	defer delete(f.stack, key)
	return f.helperFrame(call, callable, values, nil)
}

func (f *pythonFlow) helperFrame(call *sitter.Node, callable *pythonBoundCallable, values []pythonValue, plan *pythonWitnessPlan) pythonValue {
	m, fn := callable.module, callable.fn
	f.context = append(f.context, m.evidence("helper_definition", fn), f.module.evidence("call_binding", call))
	usesBefore := len(f.report.Uses)
	h := f.clone()
	h.module = m
	h.selectionActive = f.selectionActive || f.selectorMatches(callable, values)
	h.depth++
	h.env = map[string]pythonValue{}
	for k, v := range callable.closure {
		h.env[k] = v
	}
	h.imports = map[string]pythonImport{}
	h.context = append(h.context, m.evidence("helper_definition", fn), f.module.evidence("call_binding", call))
	params := fn.ChildByFieldName("parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if strings.Contains(p.Kind(), "splat") || strings.Contains(pyText(m, p), "*") {
			v := pythonValue{unknown: true, gaps: []analysis.Gap{{Kind: "python_parameter_unresolved", Detail: "variadic helper binding is not modeled", At: parse.Span(m.file, p)}}}
			for _, arg := range values {
				v = pyCombine(v, arg)
			}
			return pyTransfer(pyProtect(v, "unknown"), f.module.evidence("call_argument_dependency", call))
		}
	}
	pos := 0
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		name := p
		if p.Kind() != "identifier" {
			name = p.ChildByFieldName("name")
			if name == nil && p.Kind() == "typed_parameter" && p.NamedChildCount() > 0 {
				name = p.NamedChild(0)
			}
		}
		if name == nil {
			h.gaps = append(h.gaps, analysis.Gap{Kind: "python_parameter_unresolved", Detail: "unsupported helper parameter", At: parse.Span(m.file, p)})
			continue
		}
		v := pythonValue{}
		if pos < len(values) {
			v = pyTransfer(values[pos], m.evidence("argument_to_parameter", p))
		} else if keyword := pyKeywordIn(f.module, call, pyText(m, name)); keyword != nil {
			v = pyTransfer(f.eval(keyword), m.evidence("argument_to_parameter", p))
		} else {
			v = h.eval(p.ChildByFieldName("value"))
		}
		h.env[pyText(m, name)] = v
		pos++
	}
	if plan == nil {
		h.block(fn.ChildByFieldName("body"))
	} else {
		h.witnessValues = map[uintptr]pythonValue{}
		for _, op := range plan.ops {
			v := h.witnessExpression(op.expr)
			if op.returned {
				h.returns = pyCombine(h.returns, v)
				break
			}
			if op.expr != nil {
				h.markGuard(op.expr.node, v)
			}
		}
	}
	f.mergeGuards(h)
	f.context = pythonMergeEvidence(f.context, h.context)
	h.returns.gaps = append(h.returns.gaps, h.gaps...)
	if pythonSummaryShadow != nil {
		pythonSummaryShadow(f, call, callable, values, h.returns, len(f.report.Uses)-usesBefore)
	}
	return pyTransfer(h.returns, f.module.evidence("helper_return", call))
}
func (f *pythonFlow) outbound(q string) bool {
	for _, p := range []string{"requests.", "httpx."} {
		if strings.HasPrefix(q, p) {
			switch strings.TrimPrefix(q, p) {
			case "get", "post", "put", "patch", "delete", "head", "request":
				return true
			}
		}
	}
	return q == "urllib.request.urlopen"
}
func (f *pythonFlow) logger(q, name string, v pythonValue, method string, n *sitter.Node) bool {
	if name == "print" && f.builtin("print") {
		return true
	}
	if strings.HasPrefix(q, "logging.") || v.binding == "logger" {
		switch method {
		case "debug", "info", "warning", "warn", "error", "exception", "critical", "log":
			return true
		}
		switch strings.TrimPrefix(q, "logging.") {
		case "debug", "info", "warning", "error", "exception", "critical", "log":
			return true
		}
	}
	return false
}
func (f *pythonFlow) log(n *sitter.Node, v pythonValue) {
	var claims []analysis.Gap
	for _, d := range v.deps {
		class, hint := parse.LogDataClass(d.container, d.key)
		if d.container == "session" {
			class = "container"
		}
		if class == "" {
			continue
		}
		kind, detail := "log_sensitive_field_hint", hint+" field hint: "+d.key
		switch {
		case d.protection == "non_content":
			kind, detail = "log_non_content_only", "only a derived non-content fact is emitted"
		case d.protection == "unknown":
			kind, detail = "log_transform_unresolved", "unmodeled content transformation"
		case class == "protocol_credential":
			kind, detail = "log_protocol_credential", "HTTP credential content is emitted"
		case class == "container":
			kind, detail = "log_request_container", "whole request/session container may include sensitive data"
		}
		claims = append(claims, f.gap(kind, detail, n))
		if d.dep.Source.Kind == "literal_sensitive_source" {
			claims = append(claims, f.gap("log_literal_sensitivity_unresolved", "Email syntax alone does not establish that a constant address is private or identifies a person", n))
		}
	}
	if len(claims) == 0 {
		return
	}
	u := f.addUse("log_sink_candidate", n, v)
	u.Context = append(u.Context, f.module.evidence("logger_binding", n.ChildByFieldName("function")))
	u.Gaps = append(u.Gaps, claims...)
	u.Gaps = append(u.Gaps, f.gap("log_destination_unresolved", "logger handlers/formatters/retention not modeled", n))
}

func (f *pythonFlow) callArguments(n *sitter.Node) ([]*sitter.Node, []pythonValue, pythonValue) {
	nodes := pyArgs(n)
	values := make([]pythonValue, len(nodes))
	var all pythonValue
	for i, a := range nodes {
		values[i] = f.eval(a)
		all = pyCombine(all, values[i])
	}
	args := n.ChildByFieldName("arguments")
	if args != nil {
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if a.Kind() == "keyword_argument" {
				all = pyCombine(all, f.eval(a.ChildByFieldName("value")))
			}
		}
	}
	return nodes, values, all
}

// pythonRegexFlags maps re flag names to the classifier's flag letters.
var pythonRegexFlags = map[string]string{"re.I": "i", "re.IGNORECASE": "i", "re.X": "x", "re.VERBOSE": "x", "re.A": "a", "re.ASCII": "a",
	"re.S": "s", "re.DOTALL": "s", "re.M": "m", "re.MULTILINE": "m"}

// regexMatch models re.match/fullmatch/search(<literal>, subject[, flags]):
// the match object holds substrings of the subject, so it keeps the
// subject's paths with a regex_match transfer.
func (f *pythonFlow) regexMatch(n *sitter.Node, q string, nodes []*sitter.Node, values []pythonValue) (pythonValue, bool) {
	if q != "re.match" && q != "re.fullmatch" && q != "re.search" {
		return pythonValue{}, false
	}
	if len(nodes) < 2 || len(nodes) > 3 || nodes[0].Kind() != "string" || nodes[1].Kind() == "keyword_argument" {
		return pythonValue{}, false
	}
	m := f.module
	pattern, ok := analysispacks.PythonStringLiteral(pyText(m, nodes[0]))
	if !ok {
		return pythonValue{}, false
	}
	flags := ""
	if len(nodes) == 3 {
		text := pyText(m, nodes[2])
		if nodes[2].Kind() == "keyword_argument" {
			key := pyText(m, nodes[2].ChildByFieldName("name"))
			if key != "flags" {
				return pythonValue{}, false
			}
			text = pyText(m, nodes[2].ChildByFieldName("value"))
		}
		for _, part := range strings.Split(text, "|") {
			letter, known := pythonRegexFlags[strings.TrimSpace(part)]
			if !known {
				return pythonValue{}, false
			}
			flags += letter
		}
	}
	v := pyTransfer(values[1], m.evidence("regex_match", n))
	v.literal, v.constant, v.fields, v.finite = "", false, nil, nil
	v.regex = &pythonRegex{pattern: pattern, flags: flags, text: pyText(m, nodes[0]), call: m.evidence("regex_match", n)}
	return v, true
}

// regexGroup models m.group(n) on a literal regex match object: group n of
// the subject, recorded as a regex_capture transform on each path.
func (f *pythonFlow) regexGroup(n, fn *sitter.Node, nodes []*sitter.Node) (pythonValue, bool) {
	m := f.module
	object := pyField(fn, "object")
	if fn.Kind() != "attribute" || object == nil || object.Kind() != "identifier" || pyText(m, pyField(fn, "attribute")) != "group" || len(nodes) != 1 || nodes[0].Kind() != "integer" {
		return pythonValue{}, false
	}
	match, ok := f.env[pyText(m, object)]
	if !ok || match.regex == nil {
		return pythonValue{}, false
	}
	group, err := strconv.Atoi(pyText(m, nodes[0]))
	if err != nil || group < 1 {
		return pythonValue{}, false
	}
	re := match.regex
	sub, ok := analysispacks.CaptureSubPattern(re.pattern, group)
	if !ok {
		return pythonValue{}, false
	}
	class := analysispacks.ClassifyCapture(sub, analysispacks.FlavorPython, re.flags)
	v := pyTransfer(match, m.evidence("regex_capture", n))
	v.regex = nil
	v.deps = append([]pythonDep{}, v.deps...)
	for i := range v.deps {
		d := &v.deps[i]
		d.dep.Transforms = append(append([]analysis.ValueTransform{}, d.dep.Transforms...), analysis.ValueTransform{Kind: "regex_capture", At: parse.Span(m.file, n),
			Flavor: analysispacks.FlavorPython, Pattern: re.pattern, Flags: re.flags, Group: group, SubPattern: sub, Class: class.Class, Alphabet: class.Alphabet,
			Regex: re.text, Tests: []string{re.call.Text, pyText(m, object)}})
	}
	return v, true
}

// regexMatchTest reports a condition that only tests the presence of a
// literal regex match object: the regex test itself.
func (f *pythonFlow) regexMatchTest(text string) bool {
	for name, v := range f.env {
		if v.regex != nil && parse.MentionsAny(text, []string{name}) && parse.PresenceOnlyCondition(text, []string{name}) {
			return true
		}
	}
	return false
}
