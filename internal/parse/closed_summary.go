package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// closedCallable is the deliberately small shared summary lattice used by the
// Python and PHP refusal paths. Returns over-approximates all read parameters;
// no caller uses it to discard an argument dependency.
type closedCallable struct {
	params         []string
	reads, returns uint64
	reasons        []summaryReason
	callees        []analysis.Span
	done           bool
}

func (c *closedCallable) closed() bool { return c != nil && c.done && len(c.reasons) == 0 }
func (c *closedCallable) reject(kind, file string, n *sitter.Node) {
	c.reasons = append(c.reasons, summaryReason{Kind: kind, At: spanOf(file, n)})
}
func (c *closedCallable) read(name, file string, n *sitter.Node) {
	for i, p := range c.params {
		if p == name {
			c.reads |= 1 << uint(i)
			c.returns = c.reads
			return
		}
	}
	c.reject("free_variable", file, n)
}
func (c *closedCallable) finish() { c.done = true }

func inertPython(v pythonValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && v.binding == "" && v.table == "" && v.driver == "" && v.templateEscape == "" && !v.unknown && !v.built && !v.rendered && v.callable == nil && v.methods == nil && v.thread == nil
}
func inertPHP(v phpValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && v.binding == "" && v.class == "" && v.driver == "" && v.table == "" && v.columns == nil && v.sqlText == nil && v.sqlParams == nil && v.sqlWrites == nil && v.escapes == nil && v.bindingControls == nil && !v.unknown && !v.built
}
