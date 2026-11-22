package langphp

import (
	"fmt"
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
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
	return f.callValues(n, nodes, values, all)
}

// callValues shares the native API models with compiled witness recipes; only
// argument evaluation differs between the two callers.
func (f *phpFlow) callValues(n *sitter.Node, nodes []*sitter.Node, values []phpValue, all phpValue) phpValue {
	name := f.callName(n)
	f.deserializationCall(n, nodes, values)
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
	if f.phpLoggingFunction(n, qname, nodes, values) {
		return phpValue{}
	}
	if v, ok := f.symfonyUploadNameCall(n, qname, nodes, values); ok {
		return v
	}

	suppressSymfonyPath := f.symfonyURLBuiltin(n, qname, nodes, values)

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
			at := f.module.evidence("numeric_conversion", n)
			return phpTransfer(phpNumeric(values[0], analysis.CommandValueNumber, at), at)
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
	case "json_decode":
		// Decoding the raw request body is how plain PHP reads a JSON
		// request: the decoded fields are request values (acquisition, not a
		// transform). Any other argument keeps the content-effect contract.
		if f.builtin(qname) && f.phpBuiltinEffectName(qname) && len(values) >= 1 && len(values) <= 4 && phpRequestBody(values[0]) {
			v := phpTransfer(values[0], f.module.evidence("json_body_decode", n))
			v.literals, v.constant, v.fields = nil, false, nil
			return v
		}
	case "preg_match":
		if f.builtin(qname) {
			f.bindRegexMatches(n, nodes, values)
			return phpTransfer(phpProtect(all, "unknown"), f.module.evidence("string_transform", n))
		}
	case "preg_replace", "stristr", "stripos", "strpos", "strstr", "substr":
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
			if !suppressSymfonyPath {
				f.pathUse(n, "file_get_contents", nodes, values, "php-filesystem-v1", "read")
			}
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
			if !suppressSymfonyPath {
				f.pathUse(n, qname, nodes, values, "php-filesystem-v1", role)
			}
			return phpValue{unknown: true}
		}
	case "move_uploaded_file":
		if f.builtin(qname) && len(values) >= 2 {
			f.pathUse(n, qname, nodes, values, "php-upload-move-v1", "write")
			f.uploadUse(n, nodes, values)
			return phpValue{unknown: true}
		}
	case "is_uploaded_file", "is_file", "file_exists", "is_dir":
		return phpTransfer(phpProtect(all, "non_content"), f.module.evidence("non_content", n))
	case "template_from_string", "twig_template_from_string":
		if f.builtin(qname) && len(values) >= 2 {
			f.templateUse(n, qname, values[1], nodes[1])
			return phpValue{unknown: true}
		}
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

// phpRequestBody reports a value that is exactly the raw request body read
// (php://input) with no transform.
func phpRequestBody(v phpValue) bool {
	if len(v.deps) == 0 {
		return false
	}
	for _, d := range v.deps {
		if d.container != "INPUT" || d.protection != "raw" || d.key != "" {
			return false
		}
	}
	return true
}

// bindRegexMatches binds the matches array of preg_match($re, $subject, $m)
// for a literal $re: $m holds substrings of the subject, so its elements keep
// the subject's paths with a regex_match transfer.
func (f *phpFlow) bindRegexMatches(n *sitter.Node, nodes []*sitter.Node, values []phpValue) {
	m := f.module
	if len(nodes) < 3 || len(values) < 2 {
		return
	}
	name := phpVarName(m, nodes[2])
	if name == "" {
		return
	}
	if _, ok := phpStringLiteral(m, nodes[0]); !ok {
		return
	}
	pattern, flags, ok := analysispacks.PHPRegexLiteral(phpText(m, nodes[0]))
	if !ok {
		return
	}
	v := phpTransfer(values[1], m.evidence("regex_match", n))
	v.literals, v.constant, v.fields = nil, false, nil
	v.regex = &phpRegex{pattern: pattern, flags: flags, text: phpText(m, nodes[0]), call: m.evidence("guard", n)}
	f.markDirty(name)
	f.env[name] = v
}

// regexCapture reads group n of a literal preg_match's matches array and
// records the capture as a transform on each path (close-findings-gaps D-4).
func (f *phpFlow) regexCapture(v phpValue, group int, n *sitter.Node) phpValue {
	re := v.regex
	sub, ok := analysispacks.CaptureSubPattern(re.pattern, group)
	out := phpTransfer(v, f.module.evidence("regex_capture", n))
	out.regex = nil
	out.deps = append([]phpDep{}, out.deps...)
	for i := range out.deps {
		d := &out.deps[i]
		if !ok {
			d.protection = "unknown"
			continue
		}
		class := analysispacks.ClassifyCapture(sub, analysispacks.FlavorPCRE, re.flags)
		d.dep.Transforms = append(append([]analysis.ValueTransform{}, d.dep.Transforms...), analysis.ValueTransform{Kind: "regex_capture", At: parse.Span(f.module.file, n),
			Flavor: analysispacks.FlavorPCRE, Pattern: re.pattern, Flags: re.flags, Group: group, SubPattern: sub, Class: class.Class, Alphabet: class.Alphabet, Regex: re.text, Tests: []string{re.call.Text}})
		if d.protection == "raw" || d.protection == "" {
			d.protection, d.regexGuard = phpRegexCapture, re.call
		}
	}
	return out
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
	if v, ok := f.symfonyOperationMethod(n, receiver, method, nodes, values); ok {
		return v
	}
	if v, ok := f.requestCall(n, receiver, method, values); ok {
		return v
	}
	if f.phpLoggingMethod(n, receiver, method, nodes, values) {
		return phpValue{}
	}
	if f.symfonyUploadMove(n, receiver, method, nodes, values) {
		return phpValue{unknown: true}
	}
	if v, ok := f.symfonyRedirectCall(n, receiver, method, nodes, values); ok {
		return v
	}
	if v, ok := f.symfonyControllerCall(n, receiver, method, values); ok {
		return v
	}
	if v, ok := f.doctrineStorageCall(n, receiver, method, values); ok {
		return v
	}
	if v, ok := f.doctrineSQLCall(n, receiver, method, nodes, values); ok {
		return v
	}
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

	// Twig Environment::createTemplate(source) compiles template source
	// (close-findings-gaps D-24); the class is matched by its qualified name.
	if method == "createTemplate" && len(values) >= 1 && receiver.class == "Twig\\Environment" {
		f.templateUse(n, "Twig\\Environment::createTemplate", values[0], nodes[0])
		// The compiled template renders its own source text.
		t := phpTransfer(values[0], m.evidence("template_source_construction", n))
		t.binding, t.literals, t.constant = "twig_template", nil, false
		return t
	}
	if method == "render" && receiver.binding == "twig_template" {
		// Render variables are data under the environment's autoescape
		// setting, which is not established here.
		out := phpCombine(phpTransfer(receiver, m.evidence("template_render", n)), phpProtect(sliceFrom(values, 0), "unknown"))
		out.binding = ""
		return out
	}
	// Method of a tracked object: its class, used traits and in-repository
	// parents (D-9).
	if receiver.classDecl != nil {
		self := receiver
		if v, ok := f.classMethodCall(n, receiver.classDecl, method, &self, values); ok {
			return v
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
	scope := phpField(n, "scope")
	clsName := phpText(m, scope)
	if v, ok := f.symfonyProcessStatic(n, clsName, scope, method, nodes, values); ok {
		return v
	}
	idx := f.set.classIndex()
	var decl *phpClassDecl
	relative := false
	switch strings.ToLower(clsName) {
	case "self", "static":
		decl, relative = f.class, true
	case "parent":
		relative = true
		if f.class != nil {
			decl, _ = idx.parentOf(f.class)
		}
	default:
		if scope != nil {
			decl, _ = idx.resolve(m, clsName, scope.StartByte())
		}
	}
	if decl != nil {
		var object *phpValue
		if this, ok := f.env["this"]; ok && relative {
			self := this
			object = &self
		}
		if v, ok := f.classMethodCall(n, decl, method, object, values); ok {
			return v
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
	if anonymous := phpAnonymousClass(n); anonymous != nil {
		return f.instantiate(n, f.set.classIndex().anonymousClass(m, anonymous))
	}
	// The class name may carry no field; fall back to the leading name child.
	clsNode := phpField(n, "class")
	if clsNode == nil {
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "name" || f.symfony != nil && (c.Kind() == "qualified_name" || c.Kind() == "relative_name") {
				clsNode = c
				break
			}
		}
	}
	cls := phpText(m, clsNode)
	if v, ok := f.symfonyOperationObject(n, clsNode, cls); ok {
		return v
	}
	if v, ok := f.symfonyRedirectCreation(n, clsNode, cls); ok {
		return v
	}
	if v, ok := f.symfonyObjectCreation(n, clsNode, cls); ok {
		return v
	}
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
	if v, ok, reason := f.newObject(n, clsNode, cls); ok {
		f.doctrineTrackObject(v, n)
		return v
	} else if reason != "" && strings.Contains(reason, "more than once") {
		f.evalChildren(n)
		return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("object_creation", n)}, gaps: []analysis.Gap{f.classGap("class "+cls+" is not resolved: "+reason, n)}}
	}
	f.evalChildren(n)
	// An out-of-repository class keeps its qualified name so verified
	// library contracts can match it.
	external := ""
	if clsNode != nil {
		external = f.set.classIndex().qualify(m, cls, clsNode.StartByte())
	}
	return phpValue{unknown: true, class: external, evidence: []analysis.Evidence{m.evidence("object_creation", n)}}
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
		if callable.object != nil {
			// An unexpanded method may write any property.
			callable.object.propsUnknown = true
		}
		if f.closedSummaryCall(call, callable, values) {
			return phpValue{}
		}
		if v, ok := f.applyPHPWitness(call, callable, values); ok {
			return v
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
	h.globals = superglobalState(f.globals)
	h.helperExits = &phpSuperglobalExits{includeDepth: h.include, changed: map[string]bool{}}
	h.class = callable.class
	if callable.object != nil {
		h.env["this"] = *callable.object
	}
	params := phpField(fn, "parameters")
	pos := 0
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() == "property_promotion_parameter" && callable.object != nil {
			// A promoted constructor parameter binds like a simple parameter
			// and writes the property of the same name (D-11).
			v := phpValue{}
			if pos < len(values) {
				v = phpTransfer(values[pos], m.evidence("argument_to_parameter", p))
			} else if def := phpField(p, "default_value"); def != nil {
				v = h.eval(def)
			}
			name := phpVarName(m, phpField(p, "name"))
			h.env[name] = v
			this := h.env["this"]
			props := map[string]phpValue{}
			for k, e := range this.props {
				props[k] = e
			}
			props[name] = phpTransfer(v, m.evidence("property_write", p))
			this.props = props
			h.env["this"] = this
			pos++
			continue
		}
		if p.Kind() != "simple_parameter" {
			h.gaps = append(h.gaps, analysis.Gap{Kind: "php_parameter_unresolved", Detail: "unsupported helper parameter", At: parse.Span(m.file, p)})
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
	h.joinHelperExits(terminated)
	if callable.object != nil {
		if this, ok := h.env["this"]; ok {
			*callable.object = this
		}
	}
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
		// Tracked request elements come back only when the helper changed
		// them; an unchanged copy would mark them dirty at every call.
		if strings.HasPrefix(k, phpSuperglobalPrefix) && !h.dirty[phpGlobalsKeyPrefix+k] {
			continue
		}
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
	if strings.ContainsAny(name, "\\$") {
		return false
	}
	f.set.indexBuiltinEffects()
	return !f.set.builtinEffects["functions:"+f.module.file] && !f.set.builtinEffects[strings.ToLower(name)]
}
func (s *phpSet) indexBuiltinEffects() {
	if s.builtinEffects != nil {
		return
	}
	s.builtinEffects = map[string]bool{}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "function_definition" {
				s.builtinEffects[strings.ToLower(phpText(m, phpField(n, "name")))] = true
			}
			// Summary witnesses refuse namespaced modules ("module:"). An
			// unqualified call in a namespace falls back to the global
			// function unless a function of that name is declared (any
			// declaration excludes the name above) or imported here
			// ("functions:").
			if n.Kind() == "namespace_definition" || n.Kind() == "namespace_use_declaration" {
				s.builtinEffects["module:"+file] = true
			}
			if n.Kind() == "namespace_use_declaration" && strings.HasPrefix(strings.TrimSpace(phpText(m, n)), "use function") {
				s.builtinEffects["functions:"+file] = true
			}
		})
	}
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
