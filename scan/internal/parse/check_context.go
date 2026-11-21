package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// NodeAt returns the smallest named node under n that spans [start, end], or nil.
func NodeAt(n *sitter.Node, start, end int) *sitter.Node {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if int(c.StartByte()) <= start && int(c.EndByte()) >= end {
			if found := NodeAt(c, start, end); found != nil {
				return found
			}
		}
	}
	if int(n.StartByte()) == start && int(n.EndByte()) == end {
		return n
	}
	return nil
}

// EvidenceRoles groups context evidence by kind.
func EvidenceRoles(context []analysis.Evidence) map[string][]analysis.Evidence {
	out := map[string][]analysis.Evidence{}
	for _, e := range context {
		out[e.Kind] = append(out[e.Kind], e)
	}
	return out
}

// CheckContextMatches reports whether declared check c applies to use u's invocation context.
func CheckContextMatches(r *analysis.AnalysisReport, c analysis.Check, u analysis.CandidateUse) bool {
	for _, ctx := range r.InvocationContexts {
		if ctx.ID == u.InvocationContextID {
			return c.NormalizedSelector().MatchesContext(r, ctx)
		}
	}
	return false
}

// namespacedRoles groups a use's context evidence by role. Control-kind evidence
// in a claim-scoped use must not become an applicable control of the shared
// invocation context: that would change the invocation identity and every
// existing sibling candidate ID. The kinds are namespaced with the family prefix
// here and restored as role names.
func namespacedRoles(u *analysis.CandidateUse, prefix string) map[string][]analysis.Evidence {
	for i, e := range u.Context {
		switch e.Kind {
		case "guard_test", "conditional_test", ConditionalFalseTest, "branch_precondition", "authentication_adapter", "invoked_callable":
			u.Context[i].Kind = prefix + e.Kind
		}
	}
	roles := EvidenceRoles(u.Context)
	for kind, items := range roles {
		if strings.HasPrefix(kind, prefix) {
			switch strings.TrimPrefix(kind, prefix) {
			case "guard_test", "conditional_test", ConditionalFalseTest, "branch_precondition", "authentication_adapter", "invoked_callable":
				roles[strings.TrimPrefix(kind, prefix)] = append(roles[strings.TrimPrefix(kind, prefix)], items...)
				delete(roles, kind)
			}
		}
	}
	return roles
}

// ConditionalFalseTest is the invocation control for a test that is false on
// every path of the invocation (for example an early-throw guard's test).
const ConditionalFalseTest = "conditional_false_test"
