package parse

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

type GuardPolarity int

const (
	guardRejectsWhenTrue  GuardPolarity = iota // if (cond) { return/throw/abort }, or the else branch of an if
	GuardEnforcesWhenTrue                      // if (cond) { sink } inside consequence
)

const (
	// TerminatingGuardKind is the context kind of a guard that ends the invocation on its rejecting side.
	TerminatingGuardKind = "terminating_guard"
	enclosingGuardKind   = "enclosing_guard"
)

// guardSite is one control that dominates or encloses a call. Whole is the node
// recorded as evidence: the condition for an enclosing site, the whole
// statement for a terminating one. End is the byte after which an assignment to
// a name the condition mentions makes the control inspect a different value.
type GuardSite struct {
	Kind     string
	Polarity GuardPolarity
	Cond     *sitter.Node
	Whole    *sitter.Node
	End      uint
}

// guardLang adapts the lexical guard engine to one grammar: which node kinds
// hold statement lists and functions, which statements cannot fall through, and
// how a declaration or assignment names the variable it writes.
type GuardLang struct {
	Src      []byte
	Blocks   map[string]bool
	Function func(*sitter.Node) bool
	Exits    func(*sitter.Node) bool
	// binding returns the identifier a declaration or assignment initializes
	// from a value, for derived-name closure.
	Binding func(*sitter.Node) (name, value *sitter.Node)
	// writes returns the target nodes an assignment, augmented assignment,
	// walrus or loop header writes: identifiers, members, patterns.
	Writes func(*sitter.Node) []*sitter.Node
}

func (l GuardLang) text(n *sitter.Node) string { return n.Utf8Text(l.Src) }

// climb visits every sibling terminating `if` before start in its enclosing
// blocks and every enclosing `if`, innermost first, and returns the enclosing
// function so callers can attribute a local helper's call sites.
func (l GuardLang) Climb(start *sitter.Node, visit func(GuardSite)) *sitter.Node {
	child := start
	for p := start.Parent(); p != nil; p = p.Parent() {
		switch {
		case l.Blocks[p.Kind()]:
			for i := uint(0); i < p.NamedChildCount(); i++ {
				sib := p.NamedChild(i)
				if sib.StartByte() >= child.StartByte() {
					break
				}
				if sib.Kind() == "if_statement" && l.Exits(sib.ChildByFieldName("consequence")) {
					visit(GuardSite{TerminatingGuardKind, guardRejectsWhenTrue, sib.ChildByFieldName("condition"), sib, sib.EndByte()})
					// Later code also runs only when each test of an else-if chain whose
					// consequence exits is false, as long as every earlier arm exits.
					for link := elseIf(sib); link != nil && l.Exits(link.ChildByFieldName("consequence")); link = elseIf(link) {
						visit(GuardSite{TerminatingGuardKind, guardRejectsWhenTrue, link.ChildByFieldName("condition"), link, sib.EndByte()})
					}
				}
			}
		case p.Kind() == "if_statement":
			cond, consequence := p.ChildByFieldName("condition"), p.ChildByFieldName("consequence")
			if cond != nil && consequence != nil {
				if child.StartByte() >= consequence.StartByte() && child.EndByte() <= consequence.EndByte() {
					visit(GuardSite{enclosingGuardKind, GuardEnforcesWhenTrue, cond, cond, cond.EndByte()})
				} else if alt := p.ChildByFieldName("alternative"); alt != nil && alt.Kind() == "else_clause" && child.StartByte() >= alt.StartByte() && child.EndByte() <= alt.EndByte() {
					visit(GuardSite{enclosingGuardKind, guardRejectsWhenTrue, cond, cond, cond.EndByte()})
				}
			}
		}
		child = p
		if l.Function(p) {
			return p
		}
	}
	return nil
}

// scope returns the function enclosing n, or the tree root when there is none.
func (l GuardLang) Scope(n *sitter.Node) *sitter.Node {
	scope := n
	for p := n.Parent(); p != nil; p = p.Parent() {
		scope = p
		if l.Function(p) {
			break
		}
	}
	return scope
}

// derive extends names with variables initialized from a known name
// (`const rel = path.relative(root, full)`) so a check on the derived value is
// attributed to the operand it came from; defs keeps each derived definition.
// The closure is bounded to four rounds.
func (l GuardLang) Derive(scope *sitter.Node, names map[string]bool, defs map[string]string, defNodes map[string]*sitter.Node) {
	list := func() []string {
		out := make([]string, 0, len(names))
		for name := range names {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	for round := 0; round < 4; round++ {
		changed := false
		var walk func(*sitter.Node)
		walk = func(n *sitter.Node) {
			if id, v := l.Binding(n); id != nil && v != nil {
				name := l.text(id)
				if !names[name] && MentionsAny(l.text(v), list()) {
					names[name] = true
					defs[name] = l.text(v)
					defNodes[name] = v
					changed = true
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i))
			}
		}
		walk(scope)
		if !changed {
			return
		}
	}
}

// assignedBetween reports a completed write to one of the mentioned names
// between a control and the call, which makes the control inspect a different
// value. Writes through members (`req.query.c = x`), destructuring, tuple
// targets, walrus expressions and loop headers all count. A write that encloses
// the call (`x = run(x)`) evaluates the call first, so the control still applies.
func (l GuardLang) AssignedBetween(scope *sitter.Node, from, to uint, mentioned []string) bool {
	found := false
	var identifiers func(*sitter.Node, func(string))
	identifiers = func(n *sitter.Node, visit func(string)) {
		if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier_pattern" {
			visit(l.text(n))
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			identifiers(n.NamedChild(i), visit)
		}
	}
	writesName := func(target *sitter.Node) bool {
		text := l.text(target)
		for _, name := range mentioned {
			if text == name || strings.HasPrefix(text, name+".") || strings.HasPrefix(text, name+"[") {
				return true
			}
		}
		hit := false
		identifiers(target, func(id string) {
			for _, name := range mentioned {
				hit = hit || id == name
			}
		})
		return hit
	}
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if found || n.EndByte() <= from || n.StartByte() >= to {
			return
		}
		if n.StartByte() >= from && n.EndByte() <= to {
			for _, target := range l.Writes(n) {
				found = found || writesName(target)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(scope)
	return found
}

// mentionedNames lists, in sorted order, the names a condition mentions.
func mentionedNames(cond string, sortedNames []string) []string {
	var out []string
	for _, name := range sortedNames {
		if MentionsAny(cond, []string{name}) {
			out = append(out, name)
		}
	}
	return out
}

func sortedNameList(names map[string]bool) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// guardSignature identifies a control across call sites by kind, polarity and
// whitespace-normalized condition text.
func (l GuardLang) guardSignature(g GuardSite) string {
	return g.Kind + "|" + string(rune('0'+int(g.Polarity))) + "|" + strings.Join(strings.Fields(l.text(g.Cond)), " ")
}

// commonGuardSites keeps the controls present at every call site of a local
// helper; with one site that site's controls apply unchanged. A control present
// at only some callers does not protect the others.
func (l GuardLang) commonGuardSites(perSite [][]GuardSite) []GuardSite {
	if len(perSite) == 0 {
		return nil
	}
	if len(perSite) == 1 {
		return perSite[0]
	}
	var common []GuardSite
	for _, g := range perSite[0] {
		key, everywhere := l.guardSignature(g), true
		for _, other := range perSite[1:] {
			present := false
			for _, o := range other {
				present = present || l.guardSignature(o) == key
			}
			everywhere = everywhere && present
		}
		if everywhere {
			common = append(common, g)
		}
	}
	return common
}

// elseIf returns the if statement an else clause directly holds (a JavaScript
// else-if link), or nil.
func elseIf(n *sitter.Node) *sitter.Node {
	alt := n.ChildByFieldName("alternative")
	if alt == nil || alt.Kind() != "else_clause" {
		return nil
	}
	for i := uint(0); i < alt.NamedChildCount(); i++ {
		if c := alt.NamedChild(i); c.Kind() != "comment" {
			if c.Kind() == "if_statement" {
				return c
			}
			return nil
		}
	}
	return nil
}
