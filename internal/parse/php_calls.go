package parse

import (
	"fmt"
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// builtin reports whether a called name is the unshadowed builtin. A locally
// defined function with the same name never carries a builtin contract.
// Variables live in a separate namespace from functions, so a same-named
// variable (`$file = ...; file($file)`) never shadows a builtin; variable
// function calls (`$fn()`) carry a `$` callee and match no builtin name.
func (f *phpFlow) builtin(name string) bool {
	_, local := f.module.funcs[name]
	return !local
}

// callName returns the callee text of any call shape.
func (f *phpFlow) callName(n *sitter.Node) string {
	return phpText(f.module, phpCallee(n))
}

func (f *phpFlow) call(n *sitter.Node) phpValue {
	nodes := phpArgs(n)
	values := make([]phpValue, len(nodes))
	var all phpValue
	for i, a := range nodes {
		values[i] = f.eval(a)
		all = phpCombine(all, values[i])
	}
	name := f.callName(n)
	if n.Kind() == "member_call_expression" {
		return f.methodCall(n, nodes, values)
	}
	if n.Kind() == "scoped_call_expression" {
		// Static calls resolve like namespaced builtins; only class-method
		// helpers are modeled, via the class method table.
		return f.staticCall(n, nodes, values)
	}
	qname := strings.TrimPrefix(name, "\\")
	if qname == "" {
		return all
	}

	// Procedural SQL operations.
	switch qname {
	case "mysqli_connect":
		if f.builtin("mysqli_connect") {
			return phpValue{binding: "db_connection", driver: "mysqli", evidence: []analysis.Evidence{f.module.evidence("sink_binding", n)}}
		}
	case "mysqli_query", "mysqli_real_query", "mysqli_multi_query":
		if f.builtin("mysqli_query") && len(values) >= 2 {
			return f.sql(n, nodes, values, values[0], values[1], qname)
		}
		if f.builtin("mysqli_query") && len(values) == 1 {
			return f.sql(n, nodes, values, phpValue{}, values[0], qname)
		}
	case "mysqli_prepare":
		if f.builtin("mysqli_prepare") && len(values) >= 2 {
			return f.sqlPrepare(n, nodes, values, values[0], values[1], "mysqli", "")
		}
	case "mysqli_real_escape_string":
		if f.builtin("mysqli_real_escape_string") && len(values) >= 2 {
			// A value transform recorded as evidence, never a protection verdict.
			v := phpTransfer(values[1], f.module.evidence("escape_transform", n))
			v = phpProtect(v, "escaped_routine")
			return v
		}
	case "mysqli_fetch_assoc", "mysqli_fetch_array", "mysqli_fetch_row", "mysqli_fetch_object":
		if f.builtin(qname) && len(values) >= 1 {
			return f.sqlFetch(n, values[0])
		}
	}

	// Command operations.
	if phpCommandOps[qname] != "" && f.builtin(qname) {
		return f.commandUse(n, qname, []string{"shell_command"}, values, nodes)
	}

	// Escape and validation transforms.
	switch qname {
	case "htmlspecialchars", "htmlentities":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpProtect(values[0], "encoded")
			v.escapes = append(v.escapes, f.module.evidence("escape_transform", n))
			flags := ""
			if len(nodes) > 1 {
				flags = phpText(f.module, nodes[1])
			}
			v.gaps = append(v.gaps, f.gap("php_escape_flags", "escape function "+qname+" flags: "+flags, n))
			return v
		}
	case "explode":
		if f.builtin(qname) && len(values) >= 2 {
			// Every element is a substring of the subject: same sources,
			// same protection, no literal identity.
			v := phpTransfer(values[1], f.module.evidence("string_split", n))
			v.literals, v.constant, v.fields = nil, false, nil
			return v
		}
	case "define":
		if f.builtin(qname) && len(nodes) >= 2 {
			if name, ok := phpStringLiteral(f.module, nodes[0]); ok {
				if text, ok := phpSQLText(values[1]); ok {
					f.defineConstant(name, text)
				}
			}
			return phpValue{}
		}
	case "dirname":
		if f.builtin(qname) && len(values) == 1 {
			if text, ok := phpSQLText(values[0]); ok {
				return phpValue{literals: []phpLiteral{{text: path.Dir(text)}}, constant: true, evidence: []analysis.Evidence{f.module.evidence("path_transform", n)}}
			}
		}
	case "urlencode", "rawurlencode":
		if f.builtin(qname) && len(values) >= 1 {
			// Output holds only [A-Za-z0-9_.~+-] and %XX: no HTML-significant
			// characters and no URL scheme. phpXSSProtection scopes the
			// guarantee to output contexts; other families keep it raw.
			v := phpTransfer(phpProtect(values[0], "url_encoded"), f.module.evidence("url_encode_transform", n))
			v.escapes = append(v.escapes, f.module.evidence("url_encode_transform", n))
			return v
		}
	case "strip_tags":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpProtect(values[0], "sanitized")
			v.escapes = append(v.escapes, f.module.evidence("sanitize_transform", n))
			return v
		}
	case "intval", "floatval", "doubleval":
		if f.builtin(qname) && len(values) >= 1 {
			return phpTransfer(phpProtect(values[0], "numeric"), f.module.evidence("numeric_conversion", n))
		}
	case "is_numeric", "ctype_digit", "isset", "empty", "is_int", "is_string", "is_array":
		return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
	case "escapeshellarg", "escapeshellcmd":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpProtect(values[0], "shell_quoted")
			v.escapes = append(v.escapes, f.module.evidence("shell_quote", n))
			return v
		}
	case "basename":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpProtect(values[0], "component")
			v.escapes = append(v.escapes, f.module.evidence("path_transform", n))
			return v
		}
	case "realpath":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpProtect(values[0], "resolved")
			v.escapes = append(v.escapes, f.module.evidence("path_transform", n))
			return v
		}
	case "md5", "sha1", "hash", "password_hash", "crc32", "hash_hmac":
		return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
	case "strtoupper", "strtolower", "trim", "ltrim", "rtrim", "ucfirst", "ucwords", "strrev", "sprintf", "number_format", "nl2br", "stripslashes", "strip_whitespace":
		if f.builtin(qname) && len(values) >= 1 {
			v := phpTransfer(phpCombine(values[0], phpProtect(sliceFrom(values, 1), "unknown")), f.module.evidence("string_transform", n))
			return v
		}
	case "str_replace", "str_ireplace":
		if f.builtin(qname) && len(values) >= 3 {
			// A finite literal deny-list that leaves a shell metacharacter
			// intact cannot protect a shell string; for every other sink the
			// removal's effect stays unknown.
			protection := "unknown"
			if removed, ok := f.literalRemovals(nodes[0], nodes[1]); ok && phpShellMetaSurvives(removed) {
				protection = phpShellDenylist
			}
			v := phpTransfer(phpDenylistProtect(values[2], protection), f.module.evidence("string_transform", n))
			v = phpCombine(v, phpProtect(phpCombine(values[0], values[1]), "unknown"))
			v.literals, v.constant = nil, false
			return v
		}
	case "preg_replace", "preg_match", "stristr", "stripos", "strpos", "strstr", "substr":
		if f.builtin(qname) {
			// Replacement/removal transforms keep content with unknown effect.
			v := phpTransfer(phpProtect(all, "unknown"), f.module.evidence("string_transform", n))
			return v
		}
	case "count", "sizeof", "strlen", "in_array", "array_key_exists", "array_search":
		return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
	case "file_get_contents":
		if len(values) >= 1 {
			if text, ok := phpStringLiteral(f.module, nodes[0]); ok && text == "php://input" {
				return f.source(n, "INPUT", "http.body", "")
			}
			f.pathUse(n, "file_get_contents", nodes, values, "php-filesystem-v1", "read")
			// The returned content derives from the file the path selects:
			// path control is content control for downstream sinks (eval,
			// render). Keep the path's dependency paths with a read transfer
			// and drop literal identity — the content is not the path text.
			v := phpTransfer(values[0], f.module.evidence("file_read", n))
			v.literals = nil
			v.constant = false
			if len(v.deps) == 0 {
				v.unknown = true
			}
			return v
		}
	case "fopen", "readfile", "file", "file_put_contents", "unlink":
		if f.builtin(qname) && len(values) >= 1 {
			role := "read"
			switch qname {
			case "file_put_contents", "unlink":
				role = "write"
			}
			f.pathUse(n, qname, nodes, values, "php-filesystem-v1", role)
			return phpValue{unknown: true}
		}
	case "move_uploaded_file":
		if f.builtin(qname) && len(values) >= 2 {
			f.pathUse(n, qname, nodes, values, "php-upload-move-v1", "write")
			return phpValue{unknown: true}
		}
	case "is_uploaded_file", "is_file", "file_exists", "is_dir":
		return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
	case "eval":
		// eval parses as a function_call_expression in this grammar.
		if f.builtin("eval") && len(values) >= 1 {
			f.codeUse(n, "eval", values[0], nodes[0])
			return phpValue{}
		}
	case "assert":
		if f.builtin("assert") && len(values) >= 1 {
			if _, isString := phpStringLiteral(f.module, nodes[0]); isString || nodes[0].Kind() == "encapsed_string" || nodes[0].Kind() == "binary_expression" {
				v := values[0]
				v.gaps = append(v.gaps, f.gap("php_assert_string", "string assert evaluates its argument as code before PHP 8", n))
				f.codeUse(n, "assert", v, nodes[0])
				return phpValue{}
			}
			return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
		}
	case "create_function":
		if f.builtin(qname) && len(values) >= 2 {
			v := phpCombine(values[0], values[1])
			f.codeUse(n, "create_function", v, n)
			return phpValue{}
		}
	case "header":
		if f.builtin("header") && len(values) >= 1 {
			f.headerUse(n, nodes[0], values[0])
			return phpValue{}
		}
	case "die", "exit":
		return phpValue{}
	case "print":
		if len(values) >= 1 {
			f.render(n, values[0])
			return phpValue{}
		}
	}

	// User-defined helper in this module (or a same-set module by name).
	if fn := f.helperFunction(qname); fn != nil {
		return f.boundHelper(n, &phpBoundCallable{module: f.module, fn: fn}, values)
	}
	// A same-named helper in any other module resolves only when unique.
	if target := f.uniqueFunction(qname); target != nil {
		return f.boundHelper(n, target, values)
	}

	// Keep the fallback's dependency/protection/evidence shape. The table closes
	// only the missing content effect; it does not turn a transform into protection.
	if effect, ok := analysispacks.PHPBuiltinContentEffect(qname); ok && f.phpBuiltinEffectName(qname) && len(values) >= effect.MinArgs && len(values) <= effect.MaxArgs && len(all.deps) > 0 {
		v := phpContentValue(all)
		if effect.MutatesArgument {
			f.invalidateContentReceiver(nodes[effect.Argument])
		}
		return phpTransfer(v, f.module.evidence("call_argument_dependency", n))
	}

	if len(all.deps) > 0 {
		v := phpProtect(all, "unknown")
		v = phpTransfer(v, f.module.evidence("call_argument_dependency", n))
		v.gaps = append(v.gaps, f.gap("php_call_unresolved", "unmodeled return/content effect: "+qname, n))
		return v
	}
	return all
}

func (f *phpFlow) helperFunction(name string) *sitter.Node {
	if fn, ok := f.module.funcs[name]; ok {
		return fn
	}
	return nil
}

func (f *phpFlow) uniqueFunction(name string) *phpBoundCallable {
	var found *phpBoundCallable
	for _, file := range f.set.files {
		m := f.set.modules[file]
		if m == nil || m.file == f.module.file {
			continue
		}
		if fn, ok := m.funcs[name]; ok {
			if found != nil {
				return nil // ambiguous across modules: stay unresolved
			}
			found = &phpBoundCallable{module: m, fn: fn}
		}
	}
	return found
}

// methodCall models OO operations: SQL engines, upload handling and helpers.
func (f *phpFlow) methodCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue) phpValue {
	m := f.module
	fn := phpField(n, "name")
	method := ""
	if fn != nil {
		method = phpText(m, fn)
	}
	obj := phpField(n, "object")
	if obj == nil {
		return sliceFrom(values, 0)
	}
	receiver := f.eval(obj)
	name := ""
	if obj.Kind() == "variable_name" {
		name = phpVarName(m, obj)
	}
	if len(values) == 0 && receiver.binding == "db_connection" {
		switch method {
		case "query", "real_query", "multi_query", "exec", "prepare":
			// A SQL operation without a SQL operand has no claim.
			return phpValue{}
		}
	}

	switch {
	case receiver.binding == "db_connection" && receiver.driver == "mysqli" && (method == "query" || method == "real_query" || method == "multi_query"):
		return f.sql(n, nodes, values, receiver, values[0], "mysqli")
	case receiver.binding == "db_connection" && receiver.driver == "mysqli" && method == "prepare":
		return f.sqlPrepare(n, nodes, values, receiver, values[0], "mysqli", "")
	case receiver.binding == "db_connection" && receiver.driver == "pdo" && (method == "query" || method == "exec"):
		return f.sql(n, nodes, values, receiver, values[0], "pdo")
	case receiver.binding == "db_connection" && receiver.driver == "pdo" && method == "prepare":
		return f.sqlPrepare(n, nodes, values, receiver, values[0], "pdo", "")
	case receiver.binding == "db_connection" && receiver.driver == "sqlite3" && (method == "query" || method == "exec"):
		return f.sql(n, nodes, values, receiver, values[0], "sqlite3")
	case receiver.binding == "db_connection" && receiver.driver == "sqlite3" && method == "prepare":
		return f.sqlPrepare(n, nodes, values, receiver, values[0], "sqlite3", "")
	case receiver.binding == "db_statement" && (method == "bindParam" || method == "bindValue"):
		stmt := receiver
		stmt.bindingControls = append(stmt.bindingControls, m.evidence("parameter_binding", n))
		// bindParam(name, &var)/bindValue(name, var): argument 1 is the bound
		// value operand; it rides the statement to execute().
		if len(values) > 1 {
			stmt.sqlParams = append(append([]phpValue{}, receiver.sqlParams...), values[1])
		}
		if name != "" {
			f.env[name] = stmt
			f.markDirty(name)
		}
		return phpValue{}
	case receiver.binding == "db_statement" && method == "execute":
		executed := f.sqlExecPrepared(n, receiver)
		executed.evidence = append(executed.evidence, m.evidence("statement_execute", n))
		if name != "" {
			f.env[name] = executed
			f.markDirty(name)
		}
		return executed
	case receiver.binding == "db_statement" || receiver.binding == "db_connection":
		switch method {
		case "fetch", "fetchAll", "fetchAssoc", "fetchArray", "fetchObject", "fetchColumn", "fetchassoc", "fetcharray":
			return f.sqlFetch(n, receiver)
		}
	case receiver.binding == "db_result":
		if method == "fetchArray" || method == "fetchassoc" || method == "fetchAssoc" || method == "fetch" {
			return f.sqlFetch(n, receiver)
		}
	}

	// Method on a class defined in this module: bounded helper expansion.
	if cls := f.classOf(name); cls != nil {
		if method := findClassMethod(m, cls, method); method != nil {
			self := receiver
			return f.boundHelper(n, &phpBoundCallable{module: f.module, fn: method, object: &self}, values)
		}
	}
	// mysqli procedural-style object kept in a global (DVWA stores the
	// connection in $GLOBALS["___mysqli_ston"]) resolves member queries too.
	if len(values) > 0 {
		v := sliceFrom(values, 0)
		if len(v.deps) > 0 {
			v = phpTransfer(phpProtect(v, "unknown"), m.evidence("call_argument_dependency", n))
			v.gaps = append(v.gaps, f.gap("php_call_unresolved", "unmodeled method effect: "+method, n))
			return v
		}
		return v
	}
	return phpValue{}
}

// staticCall resolves ClassName::method() through the class method table.
func (f *phpFlow) staticCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue) phpValue {
	m := f.module
	fn := phpField(n, "name")
	if fn == nil {
		return sliceFrom(values, 0)
	}
	method := phpText(m, fn)
	clsName := phpText(m, phpField(n, "class"))
	if cls := m.classes[strings.TrimPrefix(clsName, "\\")]; cls != nil {
		if methodNode := findClassMethod(m, cls, method); methodNode != nil {
			return f.boundHelper(n, &phpBoundCallable{module: f.module, fn: methodNode}, values)
		}
	}
	return sliceFrom(values, 0)
}

func findClassMethod(m *phpModule, class *sitter.Node, name string) *sitter.Node {
	if class == nil {
		return nil
	}
	body := phpField(class, "body")
	if body == nil {
		return nil
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		c := body.NamedChild(i)
		if c.Kind() == "method_declaration" && phpText(m, phpField(c, "name")) == name {
			return c
		}
	}
	return nil
}

func (f *phpFlow) classOf(varName string) *sitter.Node {
	if varName == "" {
		return nil
	}
	// Track classes by object creation: a `new C` assignment binds the class.
	if v, ok := f.env[varName]; ok && v.binding == "php_class" && len(v.evidence) > 0 {
		return f.module.classes[v.class]
	}
	return nil
}

// objectCreation binds `new mysqli(...)`, `new PDO(...)`, `new SQLite3(...)`
// and plain classes.
func (f *phpFlow) objectCreation(n *sitter.Node) phpValue {
	m := f.module
	// The class name may carry no field; fall back to the leading name child.
	clsNode := phpField(n, "class")
	if clsNode == nil {
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "name" {
				clsNode = c
				break
			}
		}
	}
	cls := phpText(m, clsNode)
	cls = strings.TrimPrefix(cls, "\\")
	switch cls {
	case "mysqli":
		return phpValue{binding: "db_connection", driver: "mysqli", evidence: []analysis.Evidence{m.evidence("sink_binding", n)}}
	case "PDO":
		return phpValue{binding: "db_connection", driver: "pdo", evidence: []analysis.Evidence{m.evidence("sink_binding", n)}}
	case "SQLite3":
		return phpValue{binding: "db_connection", driver: "sqlite3", evidence: []analysis.Evidence{m.evidence("sink_binding", n)}}
	case "mysqli_stmt":
		return phpValue{binding: "db_statement", driver: "mysqli", evidence: []analysis.Evidence{m.evidence("sink_binding", n)}}
	}
	if m.classes[cls] != nil {
		return phpValue{binding: "php_class", class: cls, evidence: []analysis.Evidence{m.evidence("object_creation", n)}}
	}
	f.evalChildren(n)
	return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("object_creation", n)}}
}

// Helper expansion bounds: one level deeper than Python's depth 3 and a
// larger per-entry call budget, because plain-PHP page assembly chains more
// helpers than a Flask handler (DVWA: page echo -> locale -> session grab).
const (
	phpHelperDepthLimit = 4
	phpHelperWorkLimit  = 256
)

// boundHelper expands a user function call with bounded work (the Python
// depth bound; DVWA page assembly chains more helpers than a Flask handler,
// so the call budget is phpHelperWorkLimit per entry).
func (f *phpFlow) boundHelper(call *sitter.Node, callable *phpBoundCallable, values []phpValue) phpValue {
	m, fn := callable.module, callable.fn
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if f.depth >= phpHelperDepthLimit || *f.work >= phpHelperWorkLimit || f.stack[key] {
		if f.closedSummaryCall(call, callable, values) {
			return phpValue{}
		}
		v := phpValue{}
		for _, a := range values {
			v = phpCombine(v, a)
		}
		v = phpProtect(v, "unknown")
		v.gaps = append(v.gaps, f.gap("work_limit", "PHP helper expansion depth/cycle/work limit", call))
		return v
	}
	*f.work++
	f.stack[key] = true
	defer delete(f.stack, key)
	f.context = append(f.context, m.evidence("helper_definition", fn), f.module.evidence("call_binding", call))
	usesBefore := len(f.report.Uses)
	h := f.clone()
	h.module = m
	h.depth++
	h.env = map[string]phpValue{}
	h.globals = map[string]phpValue{}
	if callable.object != nil {
		h.env["this"] = *callable.object
	}
	params := phpField(fn, "parameters")
	pos := 0
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() != "simple_parameter" {
			h.gaps = append(h.gaps, analysis.Gap{Kind: "php_parameter_unresolved", Detail: "unsupported helper parameter", At: spanOf(m.file, p)})
			pos++
			continue
		}
		v := phpValue{}
		if pos < len(values) {
			v = phpTransfer(values[pos], m.evidence("argument_to_parameter", p))
		} else if def := phpField(p, "default_value"); def != nil {
			v = h.eval(def)
		}
		h.env[phpVarName(m, phpField(p, "name"))] = v
		pos++
	}
	// `global $x` statements alias the caller's tracked variables.
	globalNames := map[string]bool{}
	if body := phpField(fn, "body"); body != nil {
		for i := uint(0); i < body.NamedChildCount(); i++ {
			if s := body.NamedChild(i); s.Kind() == "global_declaration" {
				for j := uint(0); j < s.NamedChildCount(); j++ {
					g := phpVarName(m, s.NamedChild(j))
					if g == "" {
						continue
					}
					globalNames[g] = true
					if v, ok := f.env[g]; ok {
						h.env[g] = phpTransfer(v, m.evidence("global_binding", s.NamedChild(j)))
					}
				}
			}
		}
	}
	terminated := h.block(phpField(fn, "body"))
	f.adoptConstants(h.constants)
	f.gaps = phpMergeGaps(f.gaps, h.gaps)
	f.context = phpMergeEvidence(f.context, h.context)
	// A helper's writes to declared globals and to $GLOBALS are visible to the
	// caller (the DVWA connection idiom): propagate them back.
	for g := range globalNames {
		if v, ok := h.env[g]; ok {
			f.env[g] = v
			f.markDirty(g)
		}
	}
	for k, v := range h.globals {
		if f.globals == nil {
			f.globals = map[string]phpValue{}
		}
		f.globals[k] = v
		f.markDirty(phpGlobalsKeyPrefix + k)
	}
	if !terminated {
		h.returns.gaps = append(h.returns.gaps, h.gaps...)
	}
	if phpSummaryShadow != nil {
		phpSummaryShadow(f, call, callable, values, h.returns, len(f.report.Uses)-usesBefore)
	}
	return phpTransfer(h.returns, f.module.evidence("helper_return", call))
}

func firstNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		return n.NamedChild(i)
	}
	return nil
}

func phpOperator(m *phpModule, n *sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && !c.IsNamed() {
			return strings.TrimSpace(c.Utf8Text(m.src))
		}
	}
	return ""
}

// phpCallee resolves the callee node of any call shape for sink evidence.
func phpCallee(n *sitter.Node) *sitter.Node {
	if fn := phpField(n, "function"); fn != nil {
		return fn
	}
	return phpField(n, "name")
}

// phpBuiltinEffectName excludes namespaces and imported function aliases. The
// legacy parser indexes only top-level function names, so inspect declarations
// throughout the source set before assigning a builtin contract.

func (f *phpFlow) phpBuiltinEffectName(name string) bool {
	if strings.ContainsAny(name, "\\\\$") {
		return false
	}
	if f.set.builtinEffects == nil {
		f.set.builtinEffects = map[string]bool{}
		for _, file := range f.set.files {
			m := f.set.modules[file]
			if m == nil {
				continue
			}
			phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
				if n.Kind() == "function_definition" {
					f.set.builtinEffects[strings.ToLower(phpText(m, phpField(n, "name")))] = true
				}
				if n.Kind() == "namespace_definition" || n.Kind() == "namespace_use_declaration" {
					f.set.builtinEffects["module:"+file] = true
				}
			})
		}
	}
	return !f.set.builtinEffects["module:"+f.module.file] && !f.set.builtinEffects[strings.ToLower(name)]
}

// phpContentValue retains provenance while forgetting shape and protection
// that a transform or a reindexed container can no longer justify.
func phpContentValue(v phpValue) phpValue {
	v = phpProtect(v, "unknown")
	return phpValue{deps: v.deps, gaps: v.gaps, evidence: v.evidence, unknown: v.unknown, built: v.built}
}
func (f *phpFlow) invalidateContentReceiver(n *sitter.Node) {
	for n != nil && n.Kind() == "subscript_expression" {
		n, _ = phpSubscriptParts(n)
	}
	if n == nil || n.Kind() != "variable_name" {
		return
	}
	name := phpVarName(f.module, n)
	if v, ok := f.env[name]; ok {
		f.env[name] = phpContentValue(v)
		f.markDirty(name)
	}
}
