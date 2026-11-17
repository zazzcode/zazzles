package parse

import (
	"sort"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// markDirty records an environment write for branch merge efficiency.
func (f *phpFlow) markDirty(name string) {
	if f.dirty == nil {
		f.dirty = map[string]bool{}
	}
	f.dirty[name] = true
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
			b.narrow(t.bindings)
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

func (f *phpFlow) stmt(n *sitter.Node) bool {
	switch n.Kind() {
	case "php_tag", "text_interpolation", "comment":
		return false
	case "expression_statement":
		echo := phpShortEcho(f.module, n)
		for i := uint(0); i < n.NamedChildCount(); i++ {
			v := f.eval(n.NamedChild(i))
			if echo {
				f.render(n.NamedChild(i), v)
			}
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
	// A decided constant condition walks only its feasible branch; an
	// undecided one walks both.
	truth, known := f.constantCondition(test)
	walkYes, walkNo := !known || truth, !known || !truth
	yesProt, noProt := f.branchProtection(test)
	yes := f.clone()
	yes.context = append(yes.context, f.module.evidence("branch_precondition", test))
	yes.applyProtections(yesProt)
	yt := false
	if walkYes {
		yt = yes.body(body)
	}
	// An infeasible branch contributes nothing; a terminated one contributes
	// only its computed returns.
	branches := []*phpFlow{}
	if walkYes && !yt {
		branches = append(branches, yes)
	} else if walkYes {
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
	if walkNo && len(alternatives) > 0 {
		switch alt := alternatives[0]; alt.Kind() {
		case "else_if_clause":
			nt = no.ifChain(phpField(alt, "condition"), phpField(alt, "body"), alternatives[1:])
		case "else_clause":
			nt = no.body(phpField(alt, "body"))
		}
	}
	if walkNo && !nt {
		branches = append(branches, no)
	} else if walkNo {
		f.returns = phpCombine(f.returns, phpTransfer(no.returns, f.module.evidence("branch_false_precondition", test)))
	}
	if len(branches) > 0 {
		f.merge(branches...)
	}
	switch {
	case !walkYes:
		return nt
	case !walkNo:
		return yt
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

// narrow replaces each dispatch-selecting variable with the single literal
// its alternative chose (D-3), keeping the value's other evidence.
func (f *phpFlow) narrow(bindings map[string]phpLiteral) {
	for _, name := range sortedNames(bindings) {
		v := f.env[name]
		v.literals = []phpLiteral{bindings[name]}
		v.constant = true
		f.env[name] = v
		f.markDirty(name)
	}
}

func sortedNames(m map[string]phpLiteral) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// constantCondition decides an equality test between two exact constants:
// `$level == 'impossible.php'` after narrowing. Loose comparison of numeric
// strings and anything else that is not an exact constant stays undecided.
func (f *phpFlow) constantCondition(test *sitter.Node) (truth, known bool) {
	if test == nil || test.Kind() != "binary_expression" {
		return false, false
	}
	op := phpOperator(f.module, test)
	switch op {
	case "==", "===", "!=", "!==":
	default:
		return false, false
	}
	operand := func(n *sitter.Node) (string, bool) {
		if n == nil {
			return "", false
		}
		switch n.Kind() {
		case "variable_name", "string", "encapsed_string", "integer", "name":
		default:
			return "", false // evaluation could have effects
		}
		return phpSQLText(f.eval(n))
	}
	a, ok := operand(phpField(test, "left"))
	if !ok {
		return false, false
	}
	b, ok := operand(phpField(test, "right"))
	if !ok {
		return false, false
	}
	if op == "==" || op == "!=" {
		if _, err := strconv.ParseFloat(strings.TrimSpace(a), 64); err == nil {
			return false, false
		}
		if _, err := strconv.ParseFloat(strings.TrimSpace(b), 64); err == nil {
			return false, false
		}
	}
	equal := a == b
	if op == "!=" || op == "!==" {
		return !equal, true
	}
	return equal, true
}
