package parse

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// Callable summaries (source index layer L4, step 1E; spec §8b). A summary is a
// context-insensitive, parameter-indexed description of one JS/TS callable,
// computed once per callable, bottom-up over the in-repository callees that the
// call index resolves, with a bounded fixpoint for recursive components.
//
// A summary records which parameters the body reads, which may reach its result,
// and every reason the body may see data other than its parameters and load-time
// constants. A summary with no reason is closed. Closed is a flow fact, never
// protection: it never marks a value safe and never removes a dependency. Flow
// applies it only where inline expansion refuses a call and every argument the
// body reads is inert (closedSummaryCall).

const (
	summaryMaxParams = 64
	summaryTaintCap  = 8
)

// summaryMaxRounds caps the fixpoint rounds of one recursive component. A
// variable only so a test can reach the cap.
var summaryMaxRounds = 16

type summaryReason struct {
	Kind string
	At   analysis.Span
}

type summarySite struct {
	call   *sitter.Node
	module *sourceModule
	fn     *sitter.Node
	callee *callableSummary
}

type callableSummary struct {
	key    string
	module *sourceModule
	node   *sitter.Node
	params []string
	// indexed is false when the parameter list cannot be bound by name.
	indexed bool
	reads   uint64
	returns uint64
	reasons []summaryReason
	local   []summaryReason
	sites   []summarySite
	// locals are every name declared in the callable, its parameters included;
	// fresh are locals declared once with an object or array literal.
	locals map[string]bool
	fresh  map[string]bool
	done   bool
	open   bool // fixpoint working state: closed so far
	// nested is true for a callable inside another function: its free names may
	// be enclosing-function bindings, so none counts as a module constant.
	nested bool
}

func (c *callableSummary) closed() bool { return c != nil && c.done && len(c.reasons) == 0 }

// firstReason names why a summary is not closed ("" when it is).
func (c *callableSummary) firstReason() string {
	if c == nil {
		return "no_summary"
	}
	if len(c.reasons) == 0 {
		return ""
	}
	return c.reasons[0].Kind
}

func summaryKey(m *sourceModule, fn *sitter.Node) string {
	return fmt.Sprintf("%s:%d", m.file, fn.StartByte())
}

// callableSummary returns the summary of a supported callable, building it and
// every in-repository callee it reaches that has no summary yet.
func (s *moduleSet) callableSummary(m *sourceModule, fn *sitter.Node) *callableSummary {
	if s.summaries == nil {
		s.summaries = map[string]*callableSummary{}
	}
	if c := s.summaries[summaryKey(m, fn)]; c != nil {
		return c
	}
	// A build reads only modules already loaded (summaryNoLoad), so the files a
	// scan reports and the cached call resolutions do not depend on summaries.
	s.summaryNoLoad = true
	defer func() { s.summaryNoLoad = false }()
	b := &summaryBuild{set: s, index: map[string]int{}, low: map[string]int{}, onStack: map[string]bool{}}
	return b.visit(m, fn)
}

// summaryBuild is one Tarjan walk over callees without a summary.
type summaryBuild struct {
	set     *moduleSet
	next    int
	index   map[string]int
	low     map[string]int
	stack   []*callableSummary
	onStack map[string]bool
}

func (b *summaryBuild) visit(m *sourceModule, fn *sitter.Node) *callableSummary {
	key := summaryKey(m, fn)
	c := &callableSummary{key: key, module: m, node: fn}
	b.set.summaries[key] = c
	b.index[key], b.low[key] = b.next, b.next
	b.next++
	b.stack = append(b.stack, c)
	b.onStack[key] = true
	c.scan(b.set)
	for i := range c.sites {
		site := &c.sites[i]
		dk := summaryKey(site.module, site.fn)
		if d := b.set.summaries[dk]; d != nil {
			site.callee = d
			if b.onStack[dk] {
				b.low[key] = min(b.low[key], b.index[dk])
			}
			continue
		}
		site.callee = b.visit(site.module, site.fn)
		b.low[key] = min(b.low[key], b.low[dk])
	}
	if b.low[key] == b.index[key] {
		var members []*callableSummary
		for {
			top := b.stack[len(b.stack)-1]
			b.stack = b.stack[:len(b.stack)-1]
			delete(b.onStack, top.key)
			members = append(members, top)
			if top == c {
				break
			}
		}
		solveComponent(members)
	}
	return c
}

// solveComponent iterates one strongly connected component to its fixpoint:
// closedness is the greatest fixpoint (no member starts with a reason), result
// parameters the least. Both are monotone over finite sets.
func solveComponent(members []*callableSummary) {
	in := map[*callableSummary]bool{}
	for _, c := range members {
		in[c] = true
		c.open = len(c.local) == 0
	}
	calleeOpen := func(d *callableSummary) bool {
		if in[d] {
			return d.open
		}
		return d.closed()
	}
	converged := false
	for round := 0; round < summaryMaxRounds && !converged; round++ {
		converged = true
		for _, c := range members {
			if c.open {
				for _, site := range c.sites {
					if !calleeOpen(site.callee) {
						c.open, converged = false, false
						break
					}
				}
			}
			if r := c.resultParams(); r != c.returns {
				c.returns, converged = r, false
			}
		}
	}
	for _, c := range members {
		c.reasons = append([]summaryReason{}, c.local...)
		if !converged {
			c.reasons = append(c.reasons, summaryReason{Kind: "summary_fixpoint_limit", At: spanOf(c.module.file, c.node)})
			c.returns = c.reads
		}
	}
	for _, c := range members {
		for _, site := range c.sites {
			if !calleeOpen(site.callee) || (!converged && in[site.callee]) {
				c.reasons = append(c.reasons, summaryReason{Kind: "callee_not_closed", At: spanOf(c.module.file, site.call)})
			}
		}
	}
	for _, c := range members {
		c.done = true
	}
}

func (c *callableSummary) reason(kind string, n *sitter.Node) {
	c.local = append(c.local, summaryReason{Kind: kind, At: spanOf(c.module.file, n)})
}

func (c *callableSummary) paramBit(name string) uint64 {
	for i, p := range c.params {
		if p == name {
			return 1 << uint(i)
		}
	}
	return 0
}

func (c *callableSummary) allParams() uint64 {
	if len(c.params) == 0 {
		return 0
	}
	return (uint64(1) << uint(len(c.params))) - 1
}

// resultParams computes the parameters whose names may reach a return, by a
// name-level taint fixpoint over declarations, assignments, receiver mutation
// and in-repository callee summaries. Every return in the callable counts,
// nested callbacks included. A cap falls back to every read parameter.
func (c *callableSummary) resultParams() uint64 {
	if !c.indexed {
		return 0
	}
	src := c.module.src
	tainted := map[string]uint64{}
	for i, p := range c.params {
		tainted[p] |= 1 << uint(i)
	}
	callees := map[uintptr]*callableSummary{}
	for _, site := range c.sites {
		callees[site.call.Id()] = site.callee
	}
	var mention func(*sitter.Node) uint64
	mention = func(n *sitter.Node) uint64 {
		if n == nil {
			return 0
		}
		switch n.Kind() {
		case "identifier", "shorthand_property_identifier":
			if n.Utf8Text(src) == "arguments" && !c.locals["arguments"] {
				return c.allParams()
			}
			return tainted[n.Utf8Text(src)]
		case "call_expression":
			if d := callees[n.Id()]; d != nil && d.indexed && !callHasSpread(n) {
				var bits uint64
				if args := n.ChildByFieldName("arguments"); args != nil {
					for i := uint(0); i < args.NamedChildCount(); i++ {
						if i < 64 && d.returns&(1<<i) != 0 {
							bits |= mention(args.NamedChild(i))
						}
					}
				}
				return bits
			}
		}
		var bits uint64
		for i := uint(0); i < n.NamedChildCount(); i++ {
			bits |= mention(n.NamedChild(i))
		}
		return bits
	}
	assign := func(name string, bits uint64, changed *bool) {
		if bits&^tainted[name] != 0 {
			tainted[name] |= bits
			*changed = true
		}
	}
	var returns uint64
	var visit func(*sitter.Node, *bool)
	visit = func(n *sitter.Node, changed *bool) {
		switch n.Kind() {
		case "variable_declarator":
			bits := mention(n.ChildByFieldName("value"))
			for _, name := range patternNames(n.ChildByFieldName("name"), src) {
				assign(name, bits, changed)
			}
		case "assignment_expression", "augmented_assignment_expression":
			if root := writeRoot(n.ChildByFieldName("left")); root != nil {
				assign(root.Utf8Text(src), mention(n.ChildByFieldName("right")), changed)
			}
		case "for_in_statement":
			bits := mention(n.ChildByFieldName("right"))
			for _, name := range patternNames(n.ChildByFieldName("left"), src) {
				assign(name, bits, changed)
			}
		case "call_expression":
			if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "member_expression" {
				if root := writeRoot(fn); root != nil && c.locals[root.Utf8Text(src)] {
					assign(root.Utf8Text(src), mention(n.ChildByFieldName("arguments")), changed)
				}
			}
		case "return_statement":
			returns |= mention(n)
		case "arrow_function":
			if body := n.ChildByFieldName("body"); body != nil && body.Kind() != "statement_block" {
				returns |= mention(body)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i), changed)
		}
	}
	for round := 0; round < summaryTaintCap; round++ {
		changed := false
		returns = 0
		visit(c.node, &changed)
		if !changed {
			return returns
		}
	}
	return c.reads | returns
}

// writeRoot is the identifier at the root of an assignment target, or nil.
func writeRoot(n *sitter.Node) *sitter.Node {
	for n != nil && (n.Kind() == "member_expression" || n.Kind() == "subscript_expression") {
		n = n.ChildByFieldName("object")
	}
	if n == nil || n.Kind() != "identifier" {
		return nil
	}
	return n
}

// inertValue reports whether a flow value carries nothing: no dependency, no
// gap and no request, response, gRPC, GraphQL, web, model, path or output marker.
func inertValue(v value, depth int) bool {
	if len(v.deps) > 0 || len(v.gaps) > 0 || v.grpcInput != nil || len(v.grpcTransfers) > 0 || v.graphqlArgs != nil || len(v.graphqlTransfers) > 0 ||
		v.web != "" || v.model != "" || v.read != nil || len(v.readAlternatives) > 0 || v.apiPath != "" || v.apiMethod != "" || v.responseField != "" ||
		v.pathArchive != "" || v.pathArchiveBinding != nil || v.templateFile != "" || v.outputHTML || v.outputContext != "" || v.trustedContext != "" ||
		v.domNode || v.jqueryNode || v.urlParams {
		return false
	}
	if depth > 8 && len(v.fields) > 0 {
		return false
	}
	for _, field := range v.fields {
		if !inertValue(field, depth+1) {
			return false
		}
	}
	return true
}

// closedSummaryCall reports whether a closed summary stands in for a call the
// inline engine does not expand (spec §8b D-14): the callee is closed, the call
// has no spread, and every argument at a parameter the body reads is inert and
// is not the request or response name. The call result is then the empty value.
func (f *flow) closedSummaryCall(call *sitter.Node, hm *sourceModule, helper *sitter.Node, args []value) bool {
	if f.set == nil || f.helpers == nil || hm == nil || helper == nil || !supportedCallee(helper) || callHasSpread(call) {
		return false
	}
	sum := f.set.callableSummary(hm, helper)
	if !sum.closed() || !sum.indexed || len(args) > len(sum.params) {
		return false
	}
	nodes := call.ChildByFieldName("arguments")
	for i, a := range args {
		if sum.reads&(1<<uint(i)) == 0 {
			continue
		}
		if !inertValue(a, 0) {
			return false
		}
		if nodes != nil && uint(i) < nodes.NamedChildCount() {
			if arg := nodes.NamedChild(uint(i)); arg.Kind() == "identifier" {
				switch arg.Utf8Text(f.module.src) {
				case f.request, f.response, f.redirectResponse:
					if arg.Utf8Text(f.module.src) != "" {
						return false
					}
				}
			}
		}
	}
	return true
}
