package langphp

import (
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// phpIncludeTarget is one resolved include candidate with its selecting
// condition evidence, when the path came from a finite alternative set.
type phpIncludeTarget struct {
	module    *phpModule
	condition []analysis.Evidence
	literal   string
	// bindings narrows each selecting variable to the literal this
	// alternative chose, so code after the include sees one value per
	// alternative instead of the whole finite set.
	bindings map[string]phpLiteral
}

// phpIncludePart is one evaluated segment of an include path; variable names
// a segment that is a bare variable reference.
type phpIncludePart struct {
	value    phpValue
	variable string
}

// phpIncludeDepthLimit bounds include nesting; the active include chain also
// rejects cycles, which would otherwise recurse without end.
const phpIncludeDepthLimit = 8

// phpIncludeExpression reports whether a node is an include-family expression.
func phpIncludeKind(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		return true
	}
	return false
}

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

// includeExpression handles an include appearing as a nested expression. The
// D-3 composition (literal inlining and dispatch alternatives) runs at
// statement level in stmts; here only the path claim and a gap are recorded,
// because an include nested inside another expression is not composed.
func (f *phpFlow) includeExpression(n *sitter.Node) phpValue {
	operand := firstNamedChild(n)
	if operand == nil {
		return phpValue{}
	}
	v := f.eval(operand)
	f.pathUse(n, n.Kind(), []*sitter.Node{operand}, []phpValue{v}, "php-include-v1", "execute")
	f.gaps = append(f.gaps, f.gap("php_dynamic_include", "include expression is not composed at statement level", operand))
	return phpValue{}
}

// includeTargets resolves an include operand to module targets.
func (f *phpFlow) includeTargets(operand *sitter.Node, v phpValue) []phpIncludeTarget {
	var out []phpIncludeTarget
	candidates := f.includeSegmentCandidates(operand)
	if candidates == nil && phpLiteralsOnly(v) {
		name := phpVarName(f.module, operand)
		for _, lit := range v.literals {
			c := phpIncludeCandidate{phpLiteral: lit}
			if name != "" && len(v.literals) > 1 {
				c.bindings = map[string]phpLiteral{name: lit}
			}
			candidates = append(candidates, c)
		}
	} else if candidates == nil && operand.Kind() == "name" {
		if text, ok := f.constant(phpText(f.module, operand)); ok {
			candidates = []phpIncludeCandidate{{phpLiteral: phpLiteral{text: text}}}
		}
	}
	// PHP resolves a relative include against the include_path ('.', the
	// requested script's working directory) and then the including file's
	// own directory.
	baseDirs := []string{path.Dir(f.entryModule.file)}
	if dir := path.Dir(f.module.file); dir != baseDirs[0] {
		baseDirs = append(baseDirs, dir)
	}
	for _, c := range candidates {
		target := c.text
		if target == "" {
			continue
		}
		for _, baseDir := range baseDirs {
			resolved := phpNormalizePath(baseDir, target)
			if m := f.set.modules[resolved]; m != nil {
				out = append(out, phpIncludeTarget{module: m, condition: c.condition, literal: resolved, bindings: c.bindings})
				break
			}
		}
	}
	return out
}

// phpIncludeCandidate is one literal include path with the selector
// bindings that produced it.
type phpIncludeCandidate struct {
	phpLiteral
	bindings map[string]phpLiteral
}

// includeSegmentCandidates expands a concatenated/interpolated include path
// whose every segment is a finite literal set (Cartesian product), recording
// which literal each variable segment chose; nil for any other shape.
func (f *phpFlow) includeSegmentCandidates(operand *sitter.Node) []phpIncludeCandidate {
	if operand.Kind() != "binary_expression" && operand.Kind() != "encapsed_string" {
		return nil
	}
	parts, ok := f.includePathParts(operand)
	if !ok {
		return nil
	}
	for _, p := range parts {
		if !phpLiteralsOnly(p.value) {
			return nil
		}
	}
	var out []phpIncludeCandidate
	var expand func(i int, prefix string, condition []analysis.Evidence, bindings map[string]phpLiteral)
	expand = func(i int, prefix string, condition []analysis.Evidence, bindings map[string]phpLiteral) {
		if i == len(parts) {
			out = append(out, phpIncludeCandidate{phpLiteral{text: prefix, condition: condition}, bindings})
			return
		}
		p := parts[i]
		for _, lit := range p.value.literals {
			next := bindings
			if p.variable != "" && len(p.value.literals) > 1 {
				next = map[string]phpLiteral{p.variable: lit}
				for k, v := range bindings {
					next[k] = v
				}
			}
			expand(i+1, prefix+lit.text, append(append([]analysis.Evidence{}, condition...), lit.condition...), next)
		}
	}
	expand(0, "", nil, nil)
	return out
}

// includePathParts splits a concatenation/interpolation into evaluable parts.
func (f *phpFlow) includePathParts(n *sitter.Node) ([]phpIncludePart, bool) {
	switch n.Kind() {
	case "binary_expression":
		left, right := phpField(n, "left"), phpField(n, "right")
		if left == nil || right == nil {
			return nil, false
		}
		op := phpOperator(f.module, n)
		if op != "." {
			return nil, false
		}
		a, ok := f.includePathParts(left)
		if !ok {
			return nil, false
		}
		b, ok := f.includePathParts(right)
		if !ok {
			return nil, false
		}
		return append(a, b...), true
	case "encapsed_string":
		var parts []phpIncludePart
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" {
				parts = append(parts, phpIncludePart{value: phpValue{literals: []phpLiteral{{text: c.Utf8Text(f.module.src)}}, constant: true}})
				continue
			}
			if !c.IsNamed() {
				continue
			}
			parts = append(parts, phpIncludePart{value: f.eval(c), variable: phpVarName(f.module, c)})
		}
		return parts, true
	case "string":
		if text, ok := phpStringLiteral(f.module, n); ok {
			return []phpIncludePart{{value: phpValue{literals: []phpLiteral{{text: text}}, constant: true}}}, true
		}
		return nil, false
	case "variable_name", "name", "subscript_expression", "parenthesized_expression":
		v := f.eval(n)
		if phpLiteralsOnly(v) {
			return []phpIncludePart{{value: v, variable: phpVarName(f.module, n)}}, true
		}
		return nil, false
	}
	return nil, false
}

// phpNormalizePath resolves a relative include path against the including
// file's directory, lexically only.
func phpNormalizePath(baseDir, target string) string {
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)[1:]
	}
	return path.Clean(path.Join(baseDir, target))
}
