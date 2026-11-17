package parse

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpDep is one dependency path with its current protection class.
type phpDep struct {
	dep                               analysis.Dependency
	protection, container, key, entry string
}

// phpLiteral is one finite literal candidate. More than one candidate means a
// value constrained to a finite alternative set (a security-level switch).
type phpLiteral struct {
	text      string
	condition []analysis.Evidence
}

type phpValue struct {
	deps     []phpDep
	gaps     []analysis.Gap
	literals []phpLiteral
	constant bool
	fields   map[string]phpValue
	// binding labels tracked objects: db_connection, db_statement, db_result.
	binding string
	driver  string
	// table/columns carry SQL read provenance for storage linking.
	table   string
	columns []string
	// sqlText keeps the SQL text value on statements/results so a later
	// execute() re-records construction-time taint.
	sqlText *phpValue
	// sqlParams collects values bound through bindParam/bindValue so execute()
	// records the parameter operands with their binding controls.
	sqlParams []phpValue
	// template keeps the raw source template of an interpolated/concatenated
	// string (variables in place) for SQL table/column attribution.
	template string
	// arrayLiterals keeps the string elements of an array literal whose
	// elements are all plain string literals (membership allowlists).
	arrayLiterals []string
	// escapes records htmlspecialchars/htmlentities transform evidence.
	escapes []analysis.Evidence
	// bindingControls records prepare/bindParam control evidence.
	bindingControls []analysis.Evidence
	evidence        []analysis.Evidence
	built           bool
	unknown         bool
}

type phpBoundCallable struct {
	module *phpModule
	fn     *sitter.Node
	// object receives a verified class receiver for method calls.
	object *phpValue
}

func phpEmpty(v phpValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && len(v.literals) == 0 && v.binding == "" && len(v.evidence) == 0 && len(v.escapes) == 0 && !v.built && !v.unknown && len(v.bindingControls) == 0
}

func phpCombine(a, b phpValue) phpValue {
	if phpEmpty(a) {
		return b
	}
	if phpEmpty(b) {
		return a
	}
	if len(a.literals) == 1 && len(b.literals) == 1 && a.constant && b.constant {
		a.literals = []phpLiteral{{text: a.literals[0].text + b.literals[0].text}}
	} else {
		a.constant = false
		a.literals = nil
	}
	if len(b.deps) > 0 || len(b.literals) > 0 {
		a.binding = ""
		a.table = ""
		a.columns = nil
	}
	a.unknown = a.unknown || b.unknown
	a.deps = phpMergeDeps(a.deps, b.deps)
	if len(a.deps) > 64 {
		a.deps = a.deps[:64]
		a.gaps = append(a.gaps, analysis.Gap{Kind: "dependency_limit", Detail: "PHP value exceeds 64 dependency paths", At: a.deps[0].dep.Source.Span})
	}
	a.gaps = append(append([]analysis.Gap{}, a.gaps...), b.gaps...)
	a.built = a.built || b.built
	a.escapes = append(append([]analysis.Evidence{}, a.escapes...), b.escapes...)
	a.bindingControls = append(append([]analysis.Evidence{}, a.bindingControls...), b.bindingControls...)
	a.evidence = append(append([]analysis.Evidence{}, a.evidence...), b.evidence...)
	if a.fields == nil {
		a.fields = b.fields
	}
	return a
}

func phpMergeDeps(a, b []phpDep) []phpDep {
	out := []phpDep{}
	seen := map[string]bool{}
	for _, d := range append(append([]phpDep{}, a...), b...) {
		key := fmt.Sprintf("%v|%s|%s|%s|%s", d.dep.Source.Span, d.protection, d.container, d.key, d.dep.StorageKey)
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}

func phpTransfer(v phpValue, e analysis.Evidence) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].dep.Transfers = append(append([]analysis.Evidence{}, v.deps[i].dep.Transfers...), e)
		if len(v.deps[i].dep.Transfers) > 48 {
			v.deps[i].dep.Transfers = v.deps[i].dep.Transfers[:48]
			v.gaps = append(v.gaps, analysis.Gap{Kind: "transfer_limit", Detail: "PHP path exceeds 48 transfers", At: e.Span})
		}
	}
	return v
}

func phpProtect(v phpValue, p string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].protection = p
	}
	return v
}

// phpLiteralsOnly reports a value that is exactly a finite literal candidate
// set with no other content.
func phpLiteralsOnly(v phpValue) bool {
	return len(v.deps) == 0 && len(v.literals) > 0 && !v.unknown && len(v.gaps) == 0
}

type phpFlow struct {
	set        *phpSet
	module     *phpModule
	entry      analysis.EntryPoint
	invocation analysis.InvocationContext
	report     *analysis.AnalysisReport
	env        map[string]phpValue
	// globals tracks $GLOBALS['name'] assignments (the DVWA mysqli idiom).
	globals map[string]phpValue
	context []analysis.Evidence
	gaps    []analysis.Gap
	depth   int
	work    *int
	stack   map[string]bool
	include int
	returns phpValue
	// entryModule/entryModuleRoot anchor the invoked_callable evidence of the
	// entry file even while helper expansion switches f.module.
	entryModule     *phpModule
	entryModuleRoot *sitter.Node
	// condition carries selecting-branch evidence tagged onto literal sets.
	condition []analysis.Evidence
	// dirty records the variables this flow wrote since its clone origin, so
	// branch merges join only changed values instead of the whole environment.
	dirty map[string]bool
}

// markDirty records an environment write for branch merge efficiency.
func (f *phpFlow) markDirty(name string) {
	if f.dirty == nil {
		f.dirty = map[string]bool{}
	}
	f.dirty[name] = true
}

func (f *phpFlow) gap(kind, detail string, n *sitter.Node) analysis.Gap {
	return analysis.Gap{Kind: kind, Detail: detail, At: spanOf(f.module.file, n)}
}

func (f *phpFlow) clone() *phpFlow {
	c := *f
	c.env = map[string]phpValue{}
	for k, v := range f.env {
		c.env[k] = v
	}
	c.globals = map[string]phpValue{}
	for k, v := range f.globals {
		c.globals[k] = v
	}
	c.gaps = append([]analysis.Gap{}, f.gaps...)
	c.context = append([]analysis.Evidence{}, f.context...)
	c.returns = phpValue{}
	c.stack = map[string]bool{}
	for k, v := range f.stack {
		c.stack[k] = v
	}
	c.dirty = map[string]bool{}
	return &c
}

func (f *phpFlow) merge(branches ...*phpFlow) {
	keys := map[string]bool{}
	for _, b := range branches {
		f.gaps = phpMergeGaps(f.gaps, b.gaps)
		f.returns = phpJoin(f.returns, b.returns)
		for k := range b.dirty {
			keys[k] = true
		}
	}
	for key := range keys {
		global, isGlobal := strings.CutPrefix(key, phpGlobalsKeyPrefix)
		var v phpValue
		for _, b := range branches {
			scope := b.env
			name := key
			if isGlobal {
				scope, name = b.globals, global
			}
			candidate := phpValue{unknown: true}
			if value, ok := scope[name]; ok {
				candidate = value
			}
			v = phpJoin(v, candidate)
		}
		if isGlobal {
			if f.globals == nil {
				f.globals = map[string]phpValue{}
			}
			f.globals[global] = v
		} else {
			f.env[key] = v
		}
		// The joined value is a write in this flow too: when f is itself a
		// branch clone, its own merge must carry the nested change outward.
		f.markDirty(key)
	}
}

// phpGlobalsKeyPrefix namespaces $GLOBALS['name'] writes in the dirty set.
const phpGlobalsKeyPrefix = "GLOBALS:"

// phpJoin merges branch values: distinct protections on the same source stay
// separate dependency paths; literal candidate sets union with their conditions.
func phpJoin(a, b phpValue) phpValue {
	if phpEmpty(a) {
		return b
	}
	if phpEmpty(b) {
		return a
	}
	out := phpCombine(a, b)
	out.deps = phpMergeDeps(a.deps, b.deps)
	out.literals = append(append([]phpLiteral{}, a.literals...), b.literals...)
	out.constant = false
	if len(a.literals) == 1 && len(b.literals) == 1 && a.literals[0].text == b.literals[0].text {
		out.literals = []phpLiteral{a.literals[0]}
		out.constant = true
	}
	if len(out.literals) > 16 {
		out.literals = out.literals[:16]
	}
	return out
}

func (f *phpFlow) addUse(kind string, n *sitter.Node, v phpValue) *analysis.CandidateUse {
	deps := []analysis.Dependency{}
	for _, d := range v.deps {
		deps = append(deps, d.dep)
	}
	u := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, f.module.file, n.StartByte(), kind), EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: deps, Context: phpDedupeEvidence(f.context), Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}}
	f.report.Uses = append(f.report.Uses, u)
	return &f.report.Uses[len(f.report.Uses)-1]
}

// phpDedupeEvidence drops byte-identical repeated evidence items so helper and
// include expansion does not inflate requests with duplicates.
func phpDedupeEvidence(list []analysis.Evidence) []analysis.Evidence {
	out := make([]analysis.Evidence, 0, len(list))
	seen := map[analysis.Evidence]bool{}
	for _, e := range list {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// block walks statements in order; it returns true when the modeled path
// cannot fall through.
func (f *phpFlow) block(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	var list []*sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		list = append(list, n.NamedChild(i))
	}
	return f.stmts(list)
}

// body walks a control-structure body: a braced or colon block, or the single
// statement of a braceless form (`if ($a) $x = 1;`, `else exit;`).
func (f *phpFlow) body(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "compound_statement", "colon_block":
		return f.block(n)
	}
	return f.stmts([]*sitter.Node{n})
}

// stmts walks a statement list. A conditional include forks the remainder of
// the list per alternative (D-3): each candidate file continues in its own
// flow carrying its selecting condition, so a guard in one alternative never
// protects a sibling.
func (f *phpFlow) stmts(list []*sitter.Node) bool {
	for i, s := range list {
		include := phpIncludeStmt(s)
		if include == nil {
			if f.stmt(s) {
				return true
			}
			continue
		}
		operand := firstNamedChild(include)
		if operand == nil {
			continue
		}
		v := f.eval(operand)
		f.pathUse(include, include.Kind(), []*sitter.Node{operand}, []phpValue{v}, "php-include-v1", "execute")
		targets := f.includeTargets(operand, v)
		if len(targets) == 0 {
			f.gaps = append(f.gaps, f.gap("php_dynamic_include", "include path is not resolvable to a finite literal set", operand))
			continue
		}
		if f.include >= phpIncludeDepthLimit {
			f.gaps = append(f.gaps, f.gap("work_limit", "include composition depth limit", include))
			continue
		}
		if len(targets) == 1 {
			f.inlineInclude(include, targets[0])
			continue
		}
		terminated := true
		for _, t := range targets {
			b := f.clone()
			b.inlineInclude(include, t)
			if !b.stmts(list[i+1:]) {
				terminated = false
			}
			// The alternative's remaining statements ran in b; its gaps
			// belong to this entry even though b's values do not rejoin.
			f.gaps = phpMergeGaps(f.gaps, b.gaps)
		}
		return terminated
	}
	return false
}

// phpIncludeDepthLimit bounds include nesting; the active include chain also
// rejects cycles, which would otherwise recurse without end.
const phpIncludeDepthLimit = 8

// phpIncludeStmt unwraps an include-family statement to its expression.
func phpIncludeStmt(s *sitter.Node) *sitter.Node {
	if s == nil {
		return nil
	}
	if phpIncludeKind(s) {
		return s
	}
	if s.Kind() == "expression_statement" && s.NamedChildCount() == 1 && phpIncludeKind(s.NamedChild(0)) {
		return s.NamedChild(0)
	}
	return nil
}

// inlineInclude walks an included module's top-level scope in this flow. A
// module already on the active include chain is not re-entered: *_once is a
// runtime no-op there, and a plain include would recurse without bound.
func (f *phpFlow) inlineInclude(include *sitter.Node, t phpIncludeTarget) {
	key := "include:" + t.module.file
	if f.stack[key] || t.module == f.entryModule {
		if !strings.HasSuffix(include.Kind(), "_once_expression") {
			f.gaps = append(f.gaps, f.gap("work_limit", "include cycle is not re-entered: "+t.module.file, include))
		}
		return
	}
	if len(t.condition) > 0 {
		f.context = append(f.context, t.condition...)
		f.condition = append(append([]analysis.Evidence{}, f.condition...), t.condition...)
	}
	f.stack[key] = true
	f.include++
	saved := f.module
	f.module = t.module
	f.block(t.module.tree.RootNode())
	f.module = saved
	f.include--
	delete(f.stack, key)
}

func (f *phpFlow) stmt(n *sitter.Node) bool {
	switch n.Kind() {
	case "php_tag", "text_interpolation", "comment":
		return false
	case "expression_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			f.eval(n.NamedChild(i))
		}
		// die(...)/exit(...) parse as calls; as a statement they never fall
		// through, exactly like the exit_statement form.
		return f.terminatingCall(n)
	case "echo_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			v := f.eval(n.NamedChild(i))
			f.render(n.NamedChild(i), v)
		}
	case "return_statement":
		if n.NamedChildCount() > 0 {
			f.returns = phpCombine(f.returns, f.eval(n.NamedChild(0)))
		}
		return true
	case "exit_statement":
		// exit/die never falls through; the path after it is unreachable.
		return true
	case "if_statement":
		return f.conditional(n)
	case "switch_statement":
		return f.switchStatement(n)
	case "while_statement", "for_statement", "do_statement", "foreach_statement":
		return f.loop(n)
	case "function_definition", "class_declaration", "interface_declaration", "trait_declaration", "namespace_definition", "use_declaration", "declare_statement":
		return false
	case "break_statement", "continue_statement":
		// Ends the current case or loop body; loop() and switchStatement()
		// keep the enclosing path alive.
		return true
	case "global_declaration":
		// boundHelper aliases `global $x` names before walking the body.
		return false
	case "try_statement":
		return f.tryStatement(n)
	default:
		f.evalChildren(n)
	}
	return false
}

// branchProtection returns variable protections that hold on the true branch
// of the condition (yes) and on the false branch (no). Only predicates whose
// truth is implied by the branch contribute: `!` flips the branch, `&&`
// implies both operands only when true, `||` implies both negations only when
// false; any other operator implies nothing. A negated predicate such as
// `!in_array($v, [...])` therefore lands in no, which conditional() applies
// only when the rejecting branch terminates.
func (f *phpFlow) branchProtection(n *sitter.Node) (yes, no map[string]string) {
	yes, no = map[string]string{}, map[string]string{}
	f.impliedProtections(n, true, yes)
	f.impliedProtections(n, false, no)
	return yes, no
}

// impliedProtections records into out the protections implied when the
// condition c evaluates to truth.
func (f *phpFlow) impliedProtections(c *sitter.Node, truth bool, out map[string]string) {
	if c == nil {
		return
	}
	m := f.module
	switch c.Kind() {
	case "parenthesized_expression":
		if c.NamedChildCount() == 1 {
			f.impliedProtections(c.NamedChild(0), truth, out)
		}
	case "unary_op_expression":
		if strings.HasPrefix(strings.TrimSpace(phpText(m, c)), "!") && c.NamedChildCount() == 1 {
			f.impliedProtections(c.NamedChild(0), !truth, out)
		}
	case "binary_expression":
		switch strings.ToLower(phpOperator(m, c)) {
		case "&&", "and":
			if truth {
				f.impliedProtections(phpField(c, "left"), true, out)
				f.impliedProtections(phpField(c, "right"), true, out)
			}
		case "||", "or":
			if !truth {
				f.impliedProtections(phpField(c, "left"), false, out)
				f.impliedProtections(phpField(c, "right"), false, out)
			}
		}
	case "function_call_expression":
		if !truth {
			return
		}
		name := phpText(m, phpCallee(c))
		if _, shadow := m.funcs[name]; shadow {
			return
		}
		args := phpArgs(c)
		switch name {
		case "is_numeric", "ctype_digit":
			if len(args) != 1 {
				return
			}
			if v := phpVarName(m, args[0]); v != "" {
				out[v] = "numeric"
			}
		case "in_array":
			if len(args) != 2 {
				return
			}
			v := phpVarName(m, args[0])
			if v == "" {
				return
			}
			options := phpArrayLiteralStrings(m, args[1])
			if options == nil {
				if av, ok := f.env[phpVarName(m, args[1])]; ok {
					options = phpFiniteStrings(av)
				}
			}
			if len(options) > 0 {
				out[v] = "component"
			}
		}
	}
}

func (f *phpFlow) applyProtections(p map[string]string) *phpFlow {
	for name, protection := range p {
		if v, ok := f.env[name]; ok {
			f.env[name] = phpProtect(v, protection)
			// Branch merges join only dirty variables; a protection-only
			// change must survive the join like an assignment would.
			f.markDirty(name)
		}
	}
	return f
}

// phpFiniteStrings returns a value's unconditional finite string candidate
// set, or nil when the value is anything else (deps, unknown, dynamic
// elements).
func phpFiniteStrings(v phpValue) []string {
	if len(v.deps) > 0 || v.unknown || len(v.arrayLiterals) == 0 {
		return nil
	}
	return append([]string{}, v.arrayLiterals...)
}

// phpArrayLiteralStrings extracts the string elements of a plain array
// literal; nil for any non-literal shape. The first string of a keyed element
// is the key, mirroring array evaluation.
func phpArrayLiteralStrings(m *phpModule, n *sitter.Node) []string {
	if n == nil || n.Kind() != "array_creation_expression" {
		return nil
	}
	var out []string
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pair := n.NamedChild(i)
		if pair.Kind() != "array_element_initializer" {
			return nil
		}
		var valueNode *sitter.Node
		for j := uint(0); j < pair.NamedChildCount(); j++ {
			c := pair.NamedChild(j)
			if valueNode == nil && pair.NamedChildCount() > 1 {
				if _, ok := phpStringLiteral(m, c); ok {
					continue // keyed element: first string is the key
				}
			}
			valueNode = c
		}
		text, ok := phpStringLiteral(m, valueNode)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}

// conditional walks an if statement with its full elseif/else chain. The
// grammar repeats the "alternative" field once per elseif/else clause.
func (f *phpFlow) conditional(n *sitter.Node) bool {
	var alternatives []*sitter.Node
	for i := uint(0); i < n.ChildCount(); i++ {
		if n.FieldNameForChild(uint32(i)) == "alternative" {
			alternatives = append(alternatives, n.Child(i))
		}
	}
	return f.ifChain(phpField(n, "condition"), phpField(n, "body"), alternatives)
}

// ifChain walks one condition/body pair; the false branch continues with the
// remaining elseif/else alternatives.
func (f *phpFlow) ifChain(test, body *sitter.Node, alternatives []*sitter.Node) bool {
	if test != nil && test.Kind() == "parenthesized_expression" && test.NamedChildCount() > 0 {
		test = test.NamedChild(0)
	}
	f.eval(test)
	yesProt, noProt := f.branchProtection(test)
	yes := f.clone()
	yes.context = append(yes.context, f.module.evidence("branch_precondition", test))
	yes.applyProtections(yesProt)
	yt := yes.body(body)
	branches := []*phpFlow{}
	if !yt {
		branches = append(branches, yes)
	} else {
		// A terminated branch still contributes its computed returns.
		f.returns = phpCombine(f.returns, phpTransfer(yes.returns, f.module.evidence("branch_precondition", test)))
	}
	no := f.clone()
	if yt {
		// A rejecting branch that terminates makes the false-branch
		// precondition (for example a membership allowlist) enforcing for
		// everything after the conditional.
		no.applyProtections(noProt)
	}
	no.context = append(no.context, f.module.evidence("branch_false_precondition", test))
	nt := false
	if len(alternatives) > 0 {
		switch alt := alternatives[0]; alt.Kind() {
		case "else_if_clause":
			nt = no.ifChain(phpField(alt, "condition"), phpField(alt, "body"), alternatives[1:])
		case "else_clause":
			nt = no.body(phpField(alt, "body"))
		}
	}
	if !nt {
		branches = append(branches, no)
	} else {
		f.returns = phpCombine(f.returns, phpTransfer(no.returns, f.module.evidence("branch_false_precondition", test)))
	}
	if len(branches) > 0 {
		f.merge(branches...)
	}
	return yt && nt
}

// loop models one conservative iteration plus a gap. The header (including
// fetch-into-variable assignments) is evaluated once before the body. A loop
// never ends the enclosing path: its body may run zero times, and a body that
// stops at break/continue/return is not distinguished from one that falls
// through, so the body's effects (and returns) always join the zero-iteration
// path.
func (f *phpFlow) loop(n *sitter.Node) bool {
	body := phpField(n, "body")
	if n.Kind() == "foreach_statement" {
		b := f.clone()
		b.gaps = append(b.gaps, f.gap("php_loop_unresolved", "loop execution and mutation are not fully modeled", n))
		b.foreachBindings(n, body)
		b.body(body)
		f.merge(f.clone(), b)
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if body != nil && c.Id() == body.Id() {
			continue
		}
		f.eval(c)
	}
	b := f.clone()
	b.gaps = append(b.gaps, f.gap("php_loop_unresolved", "loop execution and mutation are not fully modeled", n))
	b.body(body)
	f.merge(f.clone(), b)
	return false
}

// foreachBindings binds `foreach ($collection as [$key =>] $value)` iteration
// variables to the collection's value: element content and keys both derive
// from it. Destructuring targets stay unbound (and unresolved when read).
func (f *phpFlow) foreachBindings(n, body *sitter.Node) {
	m := f.module
	var collection *sitter.Node
	var targets []*sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if body != nil && c.Id() == body.Id() {
			continue
		}
		if collection == nil {
			collection = c
			continue
		}
		if c.Kind() == "pair" {
			for j := uint(0); j < c.NamedChildCount(); j++ {
				targets = append(targets, c.NamedChild(j))
			}
		} else {
			targets = append(targets, c)
		}
	}
	v := f.eval(collection)
	for _, t := range targets {
		if t.Kind() == "by_ref" && t.NamedChildCount() == 1 {
			t = t.NamedChild(0)
		}
		if name := phpVarName(m, t); name != "" {
			f.env[name] = phpTransfer(v, m.evidence("iteration_binding", t))
			f.markDirty(name)
		}
	}
}

// terminatingCall reports an expression statement that is exactly an
// unshadowed die(...)/exit(...) call.
func (f *phpFlow) terminatingCall(stmt *sitter.Node) bool {
	if stmt.NamedChildCount() != 1 {
		return false
	}
	call := stmt.NamedChild(0)
	if call.Kind() != "function_call_expression" {
		return false
	}
	switch name := strings.ToLower(phpText(f.module, phpCallee(call))); name {
	case "die", "exit":
		return f.builtin(name)
	}
	return false
}

func (f *phpFlow) switchStatement(n *sitter.Node) bool {
	disc := phpField(n, "condition")
	if disc != nil && disc.Kind() == "parenthesized_expression" && disc.NamedChildCount() > 0 {
		disc = disc.NamedChild(0)
	}
	f.eval(disc)
	block := phpField(n, "body")
	if block == nil || block.Kind() != "switch_block" {
		return false
	}
	branches := []*phpFlow{}
	for i := uint(0); i < block.NamedChildCount(); i++ {
		c := block.NamedChild(i)
		if c.Kind() != "case_statement" && c.Kind() != "default_statement" {
			continue
		}
		b := f.clone()
		condition := f.module.evidence("dispatch_condition", c)
		b.context = append(b.context, condition)
		b.condition = append(append([]analysis.Evidence{}, f.condition...), condition)
		for j := uint(0); j < c.NamedChildCount(); j++ {
			if b.stmt(c.NamedChild(j)) {
				break
			}
		}
		// break exits the switch but the case's value effects persist; only a
		// return exits the function, contributing its computed returns.
		f.returns = phpCombine(f.returns, phpTransfer(b.returns, condition))
		branches = append(branches, b)
	}
	// A switch can fall through with the unmodified value.
	branches = append(branches, f.clone())
	f.merge(branches...)
	return false
}

func (f *phpFlow) tryStatement(n *sitter.Node) bool {
	branches := []*phpFlow{}
	b := f.clone()
	b.context = append(b.context, f.module.evidence("try_precondition", n))
	terminated := b.body(phpField(n, "body"))
	if !terminated {
		branches = append(branches, b)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c == nil {
			continue
		}
		if c.Kind() == "catch_clause" {
			h := f.clone()
			h.context = append(h.context, f.module.evidence("exception_precondition", c))
			if !h.body(phpField(c, "body")) {
				branches = append(branches, h)
			}
		}
	}
	f.merge(branches...)
	return len(branches) == 0 && terminated
}

func (f *phpFlow) evalChildren(n *sitter.Node) phpValue {
	var v phpValue
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && c.IsNamed() {
			v = phpCombine(v, f.eval(c))
		}
	}
	return v
}

func (f *phpFlow) eval(n *sitter.Node) phpValue {
	if n == nil {
		return phpValue{}
	}
	m := f.module
	switch n.Kind() {
	case "variable_name":
		name := phpVarName(m, n)
		if v, ok := f.env[name]; ok {
			return phpTransfer(v, m.evidence("value_reference", n))
		}
		if container, origin, ok := superscriptOrigin(name); ok && phpRequestContainer(container) {
			// A whole request superglobal (`reset($_GET)`, `foreach ($_POST
			// ...)`) carries every request value, keyed by no single field.
			return f.source(n, container, origin, "")
		}
		return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Variable is not resolved: $"+name, n)}}
	case "name":
		text := phpText(m, n)
		if c, ok := f.set.constant(m, text); ok {
			return phpValue{literals: []phpLiteral{{text: c}}, constant: true, evidence: []analysis.Evidence{m.evidence("constant_binding", n)}}
		}
		if strings.HasPrefix(text, "\\") {
			// Fully qualified builtin call names resolve through call().
			return phpValue{}
		}
		return phpValue{}
	case "integer", "float", "true", "false", "null":
		return phpValue{literals: []phpLiteral{{text: phpText(m, n)}}, constant: true}
	case "string":
		if text, ok := phpStringLiteral(m, n); ok {
			return phpValue{literals: []phpLiteral{{text: text}}, constant: true, template: text, evidence: []analysis.Evidence{m.evidence("literal", n)}}
		}
		v := f.evalChildren(n)
		v.built = true
		return phpTransfer(v, m.evidence("string_interpolation", n))
	case "encapsed_string":
		v := phpValue{}
		candidates := []phpLiteral{{}}
		allLiteral, interpolated := true, false
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" {
				text := c.Utf8Text(m.src)
				for j := range candidates {
					candidates[j].text += text
				}
				continue
			}
			if !c.IsNamed() {
				continue
			}
			interpolated = true
			part := f.eval(c)
			if len(part.deps) > 0 || len(part.literals) == 0 {
				allLiteral = false
				part.literals = nil
				part.constant = false
				v = phpCombine(v, part)
				continue
			}
			// Interpolation of a finite literal set expands alternatives.
			var expanded []phpLiteral
			for _, base := range candidates {
				for _, lit := range part.literals {
					next := phpLiteral{text: base.text + lit.text}
					next.condition = append(append([]analysis.Evidence{}, base.condition...), lit.condition...)
					expanded = append(expanded, next)
				}
			}
			candidates = expanded
			if len(candidates) > 16 {
				candidates = candidates[:16]
				allLiteral = false
			}
		}
		if allLiteral && len(v.deps) == 0 {
			v.literals = candidates
			v.constant = len(candidates) == 1
		}
		v.template = phpText(m, n)
		if !interpolated {
			// A double-quoted string without interpolation is a literal.
			v.evidence = []analysis.Evidence{m.evidence("literal", n)}
			return v
		}
		v.built = true
		return phpTransfer(v, m.evidence("string_interpolation", n))
	case "binary_expression":
		return f.binaryExpression(n)
	case "parenthesized_expression":
		return f.evalChildren(n)
	case "assignment_expression", "augmented_assignment_expression", "assignment_by_reference_expression":
		return f.assign(n)
	case "subscript_expression":
		return f.subscript(n)
	case "function_call_expression", "member_call_expression", "scoped_call_expression":
		return f.call(n)
	case "object_creation_expression":
		return f.objectCreation(n)
	case "cast_expression":
		kind := castKind(m, n)
		v := f.evalChildren(n)
		switch kind {
		case "int", "integer", "float", "double":
			return phpTransfer(phpProtect(v, "numeric"), m.evidence("numeric_conversion", n))
		case "string":
			return phpTransfer(v, m.evidence("string_conversion", n))
		}
		return phpTransfer(v, m.evidence("type_cast", n))
	case "unary_op_expression", "error_suppression_expression", "clone_expression":
		return f.evalChildren(n)
	case "conditional_expression":
		if n.NamedChildCount() == 3 {
			f.eval(n.NamedChild(0))
			v := phpJoin(f.eval(n.NamedChild(1)), f.eval(n.NamedChild(2)))
			return phpTransfer(v, m.evidence("conditional_value", n))
		}
		return phpValue{gaps: []analysis.Gap{f.gap("php_expression_unresolved", "unsupported conditional shape", n)}}
	case "array_creation_expression":
		v := phpValue{fields: map[string]phpValue{}}
		var elements []string
		allStrings := true
		for i := uint(0); i < n.NamedChildCount(); i++ {
			pair := n.NamedChild(i)
			if pair.Kind() != "array_element_initializer" {
				continue
			}
			var key string
			var valueNode *sitter.Node
			if pair.NamedChildCount() == 1 {
				// Positional element: the sole child is the value.
				valueNode = pair.NamedChild(0)
			} else {
				for j := uint(0); j < pair.NamedChildCount(); j++ {
					c := pair.NamedChild(j)
					if text, ok := phpStringLiteral(m, c); ok && key == "" && valueNode == nil {
						key = text
					} else {
						valueNode = c
					}
				}
			}
			if valueNode == nil {
				continue
			}
			if text, ok := phpStringLiteral(m, valueNode); ok {
				elements = append(elements, text)
			} else {
				allStrings = false
			}
			value := f.eval(valueNode)
			v = phpCombine(v, value)
			if key != "" {
				v.fields[key] = value
			}
		}
		if allStrings && len(elements) > 0 {
			v.arrayLiterals = elements
		}
		return v
	case "shell_execution_expression":
		v := f.evalChildren(n)
		f.commandUse(n, "shell_exec", []string{"shell_command"}, []phpValue{v}, []*sitter.Node{n})
		return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("command_output", n)}}
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		return f.includeExpression(n)
	case "member_access_expression", "scoped_property_access_expression":
		return f.evalChildren(n)
	default:
		return f.evalChildren(n)
	}
}

func castKind(m *phpModule, n *sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil {
			continue
		}
		if !c.IsNamed() {
			text := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Utf8Text(m.src)), ")"))
			return strings.TrimPrefix(text, "(")
		}
		if c.Kind() == "cast_type" {
			return strings.ToLower(strings.Trim(strings.TrimSpace(c.Utf8Text(m.src)), "() "))
		}
	}
	return ""
}

func (f *phpFlow) binaryExpression(n *sitter.Node) phpValue {
	m := f.module
	left, right := phpField(n, "left"), phpField(n, "right")
	if left == nil || right == nil {
		return f.evalChildren(n)
	}
	op := ""
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && !c.IsNamed() {
			op = strings.TrimSpace(c.Utf8Text(m.src))
		}
	}
	a, b := f.eval(left), f.eval(right)
	switch op {
	case ".":
		v := phpCombine(a, b)
		v.built = true
		if a.template != "" && b.template != "" {
			v.template = a.template + b.template
		}
		return phpTransfer(v, m.evidence("string_construction", n))
	case "==", "===", "!=", "!==", "<", ">", "<=", ">=", "<=>":
		return phpTransfer(phpProtect(phpCombine(a, b), "non_content"), m.evidence("comparison", n))
	case "&&", "||", "and", "or", "xor":
		return phpTransfer(phpProtect(phpCombine(a, b), "non_content"), m.evidence("boolean", n))
	}
	return phpTransfer(phpCombine(a, b), m.evidence("expression", n))
}

func (f *phpFlow) assign(n *sitter.Node) phpValue {
	m := f.module
	left, right := phpField(n, "left"), phpField(n, "right")
	v := f.eval(right)
	if n.Kind() == "augmented_assignment_expression" {
		v = phpCombine(f.eval(left), v)
		v.built = true
	}
	v = phpTransfer(v, m.evidence("assignment", n))
	if len(f.condition) > 0 && len(v.literals) > 0 {
		lits := append([]phpLiteral{}, v.literals...)
		for i := range lits {
			lits[i].condition = append(append([]analysis.Evidence{}, f.condition...), lits[i].condition...)
		}
		v.literals = lits
	}
	if left == nil {
		return v
	}
	switch left.Kind() {
	case "variable_name":
		f.markDirty(phpVarName(m, left))
		f.env[phpVarName(m, left)] = v
	case "subscript_expression":
		obj, index := phpSubscriptParts(left)
		key, _ := phpStringLiteral(m, index)
		// $GLOBALS['name'] = ... tracks the DVWA mysqli connection idiom.
		if obj != nil && obj.Kind() == "variable_name" && phpVarName(m, obj) == "GLOBALS" {
			if key != "" {
				if f.globals == nil {
					f.globals = map[string]phpValue{}
				}
				f.markDirty(phpGlobalsKeyPrefix + key)
				f.globals[key] = v
			}
			return v
		}
		if obj != nil && obj.Kind() == "variable_name" && phpVarName(m, obj) == "_SESSION" {
			if key != "" {
				v = phpTransfer(v, m.evidence("storage_write", left))
				f.set.sessionWrites["php-session:"+key] = append(f.set.sessionWrites["php-session:"+key], phpWrite{value: v, entry: f.invocation.EntryID, evidence: m.evidence("storage_write", left)})
			}
			return v
		}
		if obj != nil {
			name := phpVarName(m, obj)
			if base, ok := f.env[name]; ok {
				f.markDirty(name)
				updated := base
				if key != "" {
					if updated.fields == nil {
						updated.fields = map[string]phpValue{}
					}
					updated.fields[key] = v
				}
				updated = phpCombine(updated, v)
				f.env[name] = updated
			}
		}
	}
	return v
}

// unwrapArgument removes an argument wrapper the grammar adds around arguments.
func unwrapArgument(n *sitter.Node) *sitter.Node {
	if n != nil && n.Kind() == "argument" && n.NamedChildCount() > 0 {
		return n.NamedChild(0)
	}
	return n
}

// superscriptOrigin maps a superglobal access to its acquisition origin.
func superscriptOrigin(name string) (container, origin string, ok bool) {
	switch name {
	case "_GET":
		return "GET", "http.query", true
	case "_POST":
		return "POST", "http.form", true
	case "_REQUEST":
		return "REQUEST", "http.query_or_form", true
	case "_COOKIE":
		return "COOKIE", "http.cookies", true
	case "_FILES":
		return "FILES", "http.upload", true
	case "_SERVER":
		return "SERVER", "http.headers", true
	case "_SESSION":
		return "_SESSION", "session", true
	}
	return "", "", false
}

// phpRequestContainer reports a superglobal whose whole value is request
// controlled ($_SERVER mixes server facts and headers; $_SESSION is storage).
func phpRequestContainer(container string) bool {
	switch container {
	case "GET", "POST", "REQUEST", "COOKIE", "FILES":
		return true
	}
	return false
}

// serverKeyOrigin maps selected $_SERVER keys to precise origins.
func serverKeyOrigin(key string) string {
	switch {
	case strings.HasPrefix(key, "HTTP_"):
		return "http.headers"
	case key == "REQUEST_URI", key == "PATH_INFO", key == "PHP_SELF":
		return "http.url_path"
	case key == "QUERY_STRING":
		return "http.query"
	}
	return "unknown"
}

// phpSubscriptParts returns the positional children of a subscript: the
// container expression and the index, which carry no field names in this
// grammar.
func phpSubscriptParts(n *sitter.Node) (obj, index *sitter.Node) {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if obj == nil {
			obj = c
		} else if index == nil {
			index = c
		}
	}
	return obj, index
}

func (f *phpFlow) subscript(n *sitter.Node) phpValue {
	m := f.module
	obj, index := phpSubscriptParts(n)
	key, literal := phpStringLiteral(m, index)
	if !literal && index != nil && index.Kind() == "integer" {
		key = phpText(m, index)
	}
	if obj == nil {
		return f.evalChildren(n)
	}
	if obj.Kind() == "variable_name" {
		name := phpVarName(m, obj)
		if container, origin, ok := superscriptOrigin(name); ok {
			if container == "SERVER" {
				origin = serverKeyOrigin(key)
			}
			return f.source(n, container, origin, key)
		}
		if name == "GLOBALS" {
			if v, ok := f.globals[key]; ok {
				return phpTransfer(v, m.evidence("value_reference", n))
			}
			return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Global variable is not resolved: $"+key, n)}}
		}
		if base, ok := f.env[name]; ok {
			return f.projectValue(base, key, n)
		}
	}
	v := f.eval(obj)
	return f.projectValue(v, key, n)
}

// source records an acquisition fact at a superglobal access.
func (f *phpFlow) source(n *sitter.Node, container, origin, key string) phpValue {
	kind := "input_source"
	if container == "_SESSION" {
		// A session container is storage, not an untrusted request origin:
		// prior writes link as transfers.
		kind = "storage_source"
	}
	e := f.module.evidence(kind, n)
	dep := analysis.Dependency{Source: e, Transfers: []analysis.Evidence{}}
	v := phpValue{deps: []phpDep{{dep: dep, protection: "raw", container: container, key: key}}}
	if container == "_SESSION" {
		key0 := "php-session:" + key
		v.deps[0].dep.StorageKey = key0
		for _, w := range f.set.sessionWrites[key0] {
			for _, wd := range w.value.deps {
				nd := wd
				nd.dep.StorageKey = key0
				nd.dep.Transfers = append(append([]analysis.Evidence{}, nd.dep.Transfers...), w.evidence)
				nd.entry = w.entry
				v.deps = append(v.deps, nd)
			}
		}
		if len(f.set.sessionWrites[key0]) == 0 {
			v.deps[0].protection = "unknown"
		}
	}
	f.recordInput(e, container, key, origin)
	return v
}

// projectValue projects a field of a tracked value (arrays, DB rows).
func (f *phpFlow) projectValue(v phpValue, key string, n *sitter.Node) phpValue {
	if field, ok := v.fields[key]; ok {
		return phpTransfer(field, f.module.evidence("field_projection", n))
	}
	if v.binding == "db_row" && v.table != "" {
		column := key
		if pos, err := strconv.Atoi(column); err == nil && pos >= 0 && pos < len(v.columns) {
			// Numeric row access (fetch_row) resolves through the SELECT
			// header position; an unresolvable position keeps the raw key
			// and fails storage matching honestly.
			column = v.columns[pos]
		}
		e := f.module.evidence("storage_source", n)
		return phpValue{deps: []phpDep{{dep: analysis.Dependency{Source: e, StorageKey: "php-sql:" + v.table + "." + column, Transfers: append([]analysis.Evidence{}, v.evidence...)}, protection: "raw"}}}
	}
	v = phpTransfer(v, f.module.evidence("field_projection", n))
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		if v.deps[i].key == "" {
			v.deps[i].key = key
			v.deps[i].dep.Transfers = append(v.deps[i].dep.Transfers, analysis.Evidence{Kind: "field_projection", Text: key, Span: spanOf(f.module.file, n), SHA256: f.module.hash})
		}
	}
	return v
}

// recordInput indexes acquisition per invocation context.
func (f *phpFlow) recordInput(source analysis.Evidence, container, key, origin string) {
	if f.set.inputs == nil {
		f.set.inputs = map[string]map[analysis.Evidence]phpInputSource{}
	}
	inputs := f.set.inputs[f.invocation.ID]
	if inputs == nil {
		inputs = map[analysis.Evidence]phpInputSource{}
		f.set.inputs[f.invocation.ID] = inputs
	}
	if container == "SERVER" {
		origin = serverKeyOrigin(key)
	}
	inputs[source] = phpInputSource{origin: origin, container: container}
}

// render records a terminal echo/print as the PHP HTML rendering sink.
func (f *phpFlow) render(n *sitter.Node, v phpValue) {
	if len(v.deps) == 0 {
		return
	}
	f.recordXSS(f.module.evidence("html_output", n), v, "html_text")
}

// phpMergeGaps unions gap lists by content: branch clones inherit the parent's
// gaps, so a plain append would double the list at every conditional.
func phpMergeGaps(a, b []analysis.Gap) []analysis.Gap {
	out := make([]analysis.Gap, 0, len(a)+len(b))
	seen := make(map[analysis.Gap]bool, len(a)+len(b))
	for _, g := range a {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, g := range b {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// phpMergeEvidence unions evidence lists by content: clones inherit the
// caller's context, so a plain append would double it per helper call.
func phpMergeEvidence(a, b []analysis.Evidence) []analysis.Evidence {
	out := make([]analysis.Evidence, 0, len(a)+len(b))
	seen := make(map[analysis.Evidence]bool, len(a)+len(b))
	for _, e := range a {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, e := range b {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
