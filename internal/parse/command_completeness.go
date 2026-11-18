package parse

import (
	"regexp"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// commandRequiredRoles are the mandatory evidence obligations of the claim,
// unioned with the catalog's selected obligations by policy.
var commandRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "command_operands", "execution_configuration"}

const commandScope = "command execution claim over the supplied entry invocation, verified process API contract, effective operands, execution configuration and guard/transfer context; an unsafe witness needs only its own source-to-operand path"

// CommandCompleteness builds the claim-scoped completeness shared by every
// language adapter. Language adapters supply blockers, guard evidence and
// supported-transfer evidence they established from source.
func CommandCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	roles := namespacedRoles(u, "command_")
	c := &analysis.Completeness{ClaimKind: "command_execution", Required: append([]string{}, commandRequiredRoles...),
		Evidence: roles, Blockers: blockers, Coverage: coverage, Scope: commandScope}
	if c.Blockers == nil {
		c.Blockers = []analysis.Gap{}
	}
	if c.Coverage == nil {
		c.Coverage = []analysis.Gap{}
	}
	for role, items := range extraRoles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	c.Evidence["command_operands"] = c.Evidence["command_operand"]
	delete(c.Evidence, "command_operand")
	for _, d := range u.Dependencies {
		c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
	}
	if len(c.Evidence["invoked_callable"]) == 0 {
		c.Evidence["invoked_callable"] = append([]analysis.Evidence{}, c.Evidence["handler"]...)
	}
	return c
}

// commandDepNames lists the identifiers a dependency is reachable by: its
// source text and the names it was assigned or projected to.
var commandIdentifier = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)`)

// CommandDepNames lists the names that stand for dependency d in guard and blocker text.
func CommandDepNames(d analysis.Dependency) []string {
	python := strings.HasSuffix(d.Source.Span.File, ".py")
	var names []string
	if !python {
		names = append(names, d.Source.Text)
	}
	for _, t := range d.Transfers {
		switch t.Kind {
		case "assignment", "value_reference", "argument_to_parameter":
			if m := commandIdentifier.FindStringSubmatch(t.Text); len(m) == 2 {
				names = append(names, m[1])
			}
		case "field_projection":
			if python {
				// The projected request expression, never the bare key literal.
				if strings.ContainsAny(t.Text, "([") {
					names = append(names, t.Text)
				}
			} else if m := commandIdentifier.FindStringSubmatch(t.Text); len(m) == 2 {
				names = append(names, m[1])
			}
		}
	}
	return names
}

var presenceWords = regexp.MustCompile(`\b(not|is|None|and|or|typeof|null|undefined|string|true|false|len)\b`)

// environmentTests are request-method and framework-version comparisons: they
// select a path but never constrain the content of an operand.
var environmentTests = regexp.MustCompile(`[\w.]*\.(method|VERSION)[\w\[\]]*\s*(==|!=|<=|>=|<|>)\s*("[^"]*"|'[^']*'|\d+)`)

// requestAccessors are keyed reads such as request.GET.get("x"): a read, not a constraint.
var requestAccessors = regexp.MustCompile(`[\w.]+\.get\([^)]*\)`)

var stringLiterals = regexp.MustCompile(`"[^"]*"|'[^']*'`)

var presencePunct = regexp.MustCompile(`[\s()!=<>'"&|]`)

// PresenceOnlyCondition reports a condition that only tests whether the
// operands exist, are non-empty or have a runtime type. Such a test does not
// constrain content and is never recorded as a guard.
func PresenceOnlyCondition(condition string, names []string) bool {
	rest := requestAccessors.ReplaceAllString(condition, "")
	ordered := append([]string{}, names...)
	// Longest names first so a container prefix never splits a projection.
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, name := range ordered {
		if name != "" {
			rest = strings.ReplaceAll(rest, name, "")
		}
	}
	rest = environmentTests.ReplaceAllString(rest, "")
	rest = presenceWords.ReplaceAllString(rest, "")
	rest = presencePunct.ReplaceAllString(rest, "")
	return rest == ""
}

// PlainIdentifier matches a bare JS/Python identifier.
var PlainIdentifier = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// MentionsAny matches identifiers by word boundary and expressions exactly.
func MentionsAny(text string, names []string) bool {
	for _, name := range names {
		if name == "" {
			continue
		}
		if PlainIdentifier.MatchString(name) {
			// Text inside string literals is data, never a reference to the operand.
			text := stringLiterals.ReplaceAllString(text, `""`)
			if regexp.MustCompile(`(^|[^\w$.])` + regexp.QuoteMeta(name) + `($|[^\w$])`).MatchString(text) {
				return true
			}
		} else if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// FinishOperandPaths applies the per-path guard and blocker rules to any family
// whose facts hold source-to-operand paths; paths is updated in place.
func FinishOperandPaths(u *analysis.CandidateUse, paths []analysis.CommandPath, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, derived [][]string, touches func(analysis.Gap, analysis.Dependency) bool) {
	for i := range paths {
		p := &paths[i]
		dep := u.Dependencies[p.Dependency]
		names := CommandDepNames(dep)
		if p.Dependency < len(derived) {
			names = append(names, derived[p.Dependency]...)
		}
		var controls []int
		for j, g := range guards {
			if MentionsAny(g.Text, names) {
				controls = append(controls, guardContext[j])
			}
		}
		unknown := false
		for _, g := range c.Blockers {
			if touches(g, dep) {
				unknown = true
			}
		}
		switch {
		case unknown:
			p.Protection = "unknown"
			p.Reason = "an unresolved transfer or helper touches this source-to-operand path"
		case len(controls) > 0:
			p.Protection = "guarded"
			p.Controls = controls
			p.Reason = "a dominating or enclosing control mentions this operand; its adequacy is not established by the scanner"
		default:
			p.Protection = "raw"
		}
	}
	if len(guards) > 0 {
		c.Evidence["guard"] = append(c.Evidence["guard"], guards...)
	}
	// A per-path summary so one unresolved sibling is not mistaken for the state of every path.
	summary := []string{}
	for _, p := range paths {
		summary = append(summary, "dependency "+Itoa(p.Dependency)+" ("+u.Dependencies[p.Dependency].Source.Text+") -> "+p.Operand+": "+p.Protection)
	}
	if len(summary) > 0 {
		c.ModelFacts = append(c.ModelFacts, "Operand path facts: "+strings.Join(summary, "; ")+".")
	}
}

// DedupeGaps drops repeated gaps (same kind, detail and location), keeping first-seen order.
func DedupeGaps(in []analysis.Gap) []analysis.Gap {
	seen := map[string]bool{}
	out := []analysis.Gap{}
	for _, g := range in {
		key := g.Kind + "|" + g.Detail + "|" + g.At.File + "|" + string(rune(g.At.StartByte))
		if !seen[key] {
			seen[key] = true
			out = append(out, g)
		}
	}
	return out
}

// GapTouchesDependency reports whether the gap lies on this dependency's
// source or transfer chain, excluding enclosing statements that merely
// contain unrelated operands.
func GapTouchesDependency(g analysis.Gap, d analysis.Dependency) bool {
	for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
		if e.Kind != "input_source" && e.Kind != "call_argument_dependency" {
			continue
		}
		if g.At.File == e.Span.File && g.At.StartByte >= e.Span.StartByte && g.At.EndByte <= e.Span.EndByte {
			return true
		}
	}
	return false
}
