package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// ClosedCallable is the deliberately small shared summary lattice used by the
// Python and PHP refusal paths. Returns over-approximates all read parameters;
// no caller uses it to discard an argument dependency.
type ClosedCallable struct {
	Params         []string
	reads, returns uint64
	Reasons        []SummaryReason
	Callees        []analysis.Span
	done           bool
}

func (c *ClosedCallable) Closed() bool { return c != nil && c.done && len(c.Reasons) == 0 }
func (c *ClosedCallable) Reject(kind, file string, n *sitter.Node) {
	c.Reasons = append(c.Reasons, SummaryReason{Kind: kind, At: Span(file, n)})
}
func (c *ClosedCallable) Read(name, file string, n *sitter.Node) {
	for i, p := range c.Params {
		if p == name {
			c.reads |= 1 << uint(i)
			c.returns = c.reads
			return
		}
	}
	c.Reject("free_variable", file, n)
}
func (c *ClosedCallable) Finish() { c.done = true }

type SummaryReason struct {
	Kind string
	At   analysis.Span
}
