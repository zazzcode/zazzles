package parse

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type guardPolarity int

const (
	guardRejectsWhenTrue  guardPolarity = iota // if (cond) { return/throw/abort }
	guardEnforcesWhenTrue                      // if (cond) { sink } inside consequence
)

// pathGuardInfo records, while the syntax context is available, the kind of
// each guard and which dependencies' derived values it mentions. The assembly
// reads it back when it attaches guards to flows.
type pathGuardInfo struct {
	kinds       map[string]string
	deps        map[string]map[int]bool
	rootContain map[string]bool
	// ambiguousCallers records a helper with several call sites where not every
	// call site enforces containment, so controls cannot be merged across callers.
	ambiguousCallers bool
}

func newPathGuardInfo() *pathGuardInfo {
	return &pathGuardInfo{kinds: map[string]string{}, deps: map[string]map[int]bool{}, rootContain: map[string]bool{}}
}

func guardKey(e analysis.Evidence) string {
	return fmt.Sprintf("%s:%d:%d", e.Span.File, e.Span.StartByte, e.Span.EndByte)
}

func (g *pathGuardInfo) note(e analysis.Evidence, kind string, deps map[int]bool) {
	g.noteWithMeta(e, kind, deps, false)
}

func (g *pathGuardInfo) noteWithMeta(e analysis.Evidence, kind string, deps map[int]bool, rootContain bool) {
	k := guardKey(e)
	g.kinds[k] = kind
	g.deps[k] = deps
	g.rootContain[k] = rootContain
}

var (
	dotDotText      = regexp.MustCompile(`['"]\.\.['"]|\\\.\\\.|/\\\.\\\./|\.\.(?:/|\\\\)`)
	boundaryText    = regexp.MustCompile(`(?:\bsep\b|\bpath\.sep\b|\bos\.sep\b|["'` + "`" + `][\\/]+["'` + "`" + `]|\+\s*["'` + "`" + `][\\/])`)
	startsWithCall  = regexp.MustCompile(`(?:\.\s*(?:startsWith|startswith)\s*\(([^)]*)\))|(?:\.\s*indexOf\s*\(([^)]*)\)\s*===?\s*0)`)
	relativeCall    = regexp.MustCompile(`\.\s*(?:relative|relpath|is_relative_to|relative_to)\s*\(`)
	commonPathCall  = regexp.MustCompile(`\.\s*commonpath\s*\(`)
	membershipCall  = regexp.MustCompile(`([A-Za-z_$][\w$.]*|\[[^\]]*\])\s*\.\s*(?:has|includes|indexOf)\s*\(([^)]*)\)`)
	inOperator      = regexp.MustCompile(`([A-Za-z_$][\w$.\[\]'"]*)\s+(not\s+)?in\s+([A-Za-z_$][\w$]*|\[[^\]]*\]|\([^)]*\)|\{[^}]*\})`)
	jsSubscriptTest = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$.]*)\s*\]`)
	// keyPresenceTest is `'k' [not] in <container>`; emptyComparison is `x == ''`, `x != None`.
	// Neither constrains what a present value contains.
	keyPresenceTest = regexp.MustCompile(`^\s*(?:not\s+)?r?['"][\w -]*['"]\s+(?:not\s+)?in\s+[A-Za-z_][\w.]*\s*$`)
	emptyComparison = regexp.MustCompile(`^\s*(?:not\s+)?[\w.\[\]'"]+\s*(?:==|!=|is not|is)\s*(?:''|""|None|null|undefined)\s*$`)
	// separatorText is a test for a path separator character in the value.
	separatorText = regexp.MustCompile(`(?:includes|indexOf|contains|find)\s*\(\s*(?:path\.sep|os\.sep|['"][\\/]['"])\s*\)|['"][\\/]['"]\s+(?:not\s+)?in\b|\b(?:os|path)\.sep\s+(?:not\s+)?in\b`)
	constantList  = regexp.MustCompile(`^[\[\(\{]\s*(?:(?:r?['"][^'"]*['"])\s*(?::\s*[^,\]\)\}]*)?\s*,?\s*)+[\]\)\}]$`)
)

// sortedRelated appends derived definitions in sorted key order so guard
// classification is strictly deterministic across runs.
func sortedRelated(cond string, defs map[string]string) string {
	related := cond
	keys := make([]string, 0, len(defs))
	for name := range defs {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if mentionsAny(cond, []string{name}) {
			related += " " + defs[name]
		}
	}
	return related
}

// classifyPathGuardText classifies a control condition string deterministically.
func classifyPathGuardText(cond string, names []string, defs map[string]string, collectionIs func(string) bool) string {
	if keyPresenceTest.MatchString(cond) || emptyComparison.MatchString(cond) {
		return analysis.PathGuardPresenceOrType
	}
	text := cond
	related := sortedRelated(cond, defs)
	for _, m := range membershipCall.FindAllStringSubmatch(related, -1) {
		receiver, arg := strings.TrimSpace(m[1]), m[2]
		if !mentionsAny(arg, names) || mentionsAny(receiver, names) {
			continue
		}
		if (strings.HasPrefix(receiver, "[") && constantList.MatchString(receiver)) || collectionIs(receiver) {
			return analysis.PathGuardAllowlist
		}
	}
	for _, m := range inOperator.FindAllStringSubmatch(related, -1) {
		left, right := strings.TrimSpace(m[1]), strings.TrimSpace(m[3])
		if !mentionsAny(left, names) || mentionsAny(right, names) {
			continue
		}
		if constantList.MatchString(right) || collectionIs(right) {
			return analysis.PathGuardAllowlist
		}
	}
	for _, m := range jsSubscriptTest.FindAllStringSubmatch(related, -1) {
		if mentionsAny(m[2], names) && collectionIs(m[1]) {
			return analysis.PathGuardAllowlist
		}
	}
	switch {
	case commonPathCall.MatchString(related):
		return analysis.PathGuardCommonPath
	case relativeCall.MatchString(related):
		return analysis.PathGuardRelative
	}
	if m := startsWithCall.FindStringSubmatch(related); m != nil {
		arg := m[1] + m[2]
		if boundaryText.MatchString(arg) {
			return analysis.PathGuardPrefixBoundary
		}
		if dotDotText.MatchString(arg) {
			return analysis.PathGuardDotDotText
		}
		return analysis.PathGuardPrefixBare
	}
	if dotDotText.MatchString(text) {
		return analysis.PathGuardDotDotText
	}
	if separatorText.MatchString(text) {
		return analysis.PathGuardSeparatorText
	}
	for _, m := range membershipCall.FindAllStringSubmatch(related, -1) {
		if mentionsAny(m[1], names) && !mentionsAny(m[2], names) {
			return analysis.PathGuardSubstring
		}
	}
	return analysis.PathGuardUnclassified
}

func flipPolarity(p guardPolarity) guardPolarity {
	if p == guardRejectsWhenTrue {
		return guardEnforcesWhenTrue
	}
	return guardRejectsWhenTrue
}

// classifyPathGuardAST evaluates condition syntax with branch polarity and boolean
// conjunction/disjunction structure so inverted or conditionally bypassed guards
// cannot acquire enforcing containment kinds.
func classifyPathGuardAST(cond *sitter.Node, src []byte, polarity guardPolarity, names []string, defs map[string]string, defNodes map[string]*sitter.Node, collectionIs, baseConstIs func(string) bool) (string, bool) {
	if cond == nil {
		return analysis.PathGuardUnclassified, false
	}
	raw := classifyPathGuardText(cond.Utf8Text(src), names, defs, collectionIs)
	if raw == analysis.PathGuardPresenceOrType {
		return raw, false
	}
	enforcedKind, rootContain := evalGuardAST(cond, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, 0)
	if enforcedKind != "" {
		return enforcedKind, rootContain
	}
	if analysis.EnforcingPathGuard(raw) {
		return analysis.PathGuardUnclassified, false
	}
	return raw, false
}

func evalGuardAST(n *sitter.Node, src []byte, polarity guardPolarity, names []string, defs map[string]string, defNodes map[string]*sitter.Node, collectionIs, baseConstIs func(string) bool, depth int) (string, bool) {
	if n == nil || depth > 8 {
		return "", false
	}
	switch n.Kind() {
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return evalGuardAST(n.NamedChild(0), src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
		}
	case "unary_expression", "not_operator":
		op := n.ChildByFieldName("operator")
		arg := n.ChildByFieldName("argument")
		if n.Kind() == "not_operator" || (op != nil && op.Utf8Text(src) == "!") {
			return evalGuardAST(arg, src, flipPolarity(polarity), names, defs, defNodes, collectionIs, baseConstIs, depth+1)
		}
	case "identifier":
		if def := defNodes[n.Utf8Text(src)]; def != nil {
			return evalGuardAST(def, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
		}
	case "binary_expression", "boolean_operator":
		opNode := n.ChildByFieldName("operator")
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if opNode != nil {
			switch opNode.Utf8Text(src) {
			case "||", "or":
				lk, lr := evalGuardAST(left, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
				rk, rr := evalGuardAST(right, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
				if polarity == guardRejectsWhenTrue {
					return pickStrongerGuard(lk, lr, rk, rr)
				}
				if analysis.EnforcingPathGuard(lk) && analysis.EnforcingPathGuard(rk) {
					return lk, lr && rr
				}
				return "", false
			case "&&", "and":
				lk, lr := evalGuardAST(left, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
				rk, rr := evalGuardAST(right, src, polarity, names, defs, defNodes, collectionIs, baseConstIs, depth+1)
				if polarity == guardEnforcesWhenTrue {
					return pickStrongerGuard(lk, lr, rk, rr)
				}
				if analysis.EnforcingPathGuard(lk) && analysis.EnforcingPathGuard(rk) {
					return lk, lr && rr
				}
				return "", false
			}
		}
	}
	return evalAtomicGuard(n, src, polarity, names, defs, collectionIs, baseConstIs)
}

func pickStrongerGuard(lk string, lr bool, rk string, rr bool) (string, bool) {
	if analysis.EnforcingPathGuard(lk) {
		return lk, lr
	}
	if analysis.EnforcingPathGuard(rk) {
		return rk, rr
	}
	if lk != "" {
		return lk, lr
	}
	return rk, rr
}

func evalAtomicGuard(n *sitter.Node, src []byte, polarity guardPolarity, names []string, defs map[string]string, collectionIs, baseConstIs func(string) bool) (string, bool) {
	text := strings.TrimSpace(n.Utf8Text(src))
	related := sortedRelated(text, defs)

	for _, m := range inOperator.FindAllStringSubmatch(text, -1) {
		left, neg, right := strings.TrimSpace(m[1]), strings.TrimSpace(m[2]) != "", strings.TrimSpace(m[3])
		if !mentionsAny(left, names) || mentionsAny(right, names) {
			continue
		}
		if constantList.MatchString(right) || collectionIs(right) {
			if (polarity == guardRejectsWhenTrue && neg) || (polarity == guardEnforcesWhenTrue && !neg) {
				return analysis.PathGuardAllowlist, false
			}
			return analysis.PathGuardInverted, false
		}
	}
	for _, m := range membershipCall.FindAllStringSubmatch(text, -1) {
		receiver, arg := strings.TrimSpace(m[1]), m[2]
		if mentionsAny(arg, names) && !mentionsAny(receiver, names) {
			if (strings.HasPrefix(receiver, "[") && constantList.MatchString(receiver)) || collectionIs(receiver) {
				if polarity == guardEnforcesWhenTrue {
					return analysis.PathGuardAllowlist, false
				}
				return analysis.PathGuardInverted, false
			}
		}
	}
	for _, m := range jsSubscriptTest.FindAllStringSubmatch(text, -1) {
		if mentionsAny(m[2], names) && collectionIs(m[1]) {
			if polarity == guardEnforcesWhenTrue {
				return analysis.PathGuardAllowlist, false
			}
			return analysis.PathGuardInverted, false
		}
	}
	if commonPathCall.MatchString(related) {
		notEq := strings.Contains(text, "!=")
		eq := !notEq && strings.Contains(text, "==")
		extractBaseIdentifier(related, names, baseConstIs)
		if (polarity == guardRejectsWhenTrue && notEq) || (polarity == guardEnforcesWhenTrue && eq) {
			return analysis.PathGuardCommonPath, false
		}
		if notEq || eq {
			return analysis.PathGuardInverted, false
		}
		return analysis.PathGuardUnclassified, false
	}
	if relativeCall.MatchString(related) {
		extractBaseIdentifier(related, names, baseConstIs)
		if strings.Contains(related, "is_relative_to") {
			if polarity == guardEnforcesWhenTrue {
				return analysis.PathGuardRelative, false
			}
			return analysis.PathGuardInverted, false
		}
		escapesWhenTrue := dotDotText.MatchString(text) || strings.Contains(text, "isAbsolute") || strings.Contains(text, "isabs")
		if polarity == guardRejectsWhenTrue && escapesWhenTrue {
			return analysis.PathGuardRelative, false
		}
		if polarity == guardEnforcesWhenTrue && escapesWhenTrue {
			return analysis.PathGuardInverted, false
		}
		return analysis.PathGuardUnclassified, false
	}
	if m := startsWithCall.FindStringSubmatch(text); m != nil {
		arg := strings.TrimSpace(m[1] + m[2])
		if dotDotText.MatchString(arg) {
			if polarity == guardRejectsWhenTrue {
				return analysis.PathGuardDotDotText, false
			}
			return analysis.PathGuardInverted, false
		}
		extractBaseIdentifier(arg, names, baseConstIs)
		if polarity == guardEnforcesWhenTrue {
			if boundaryText.MatchString(arg) {
				return analysis.PathGuardPrefixBoundary, false
			}
			return analysis.PathGuardPrefixBare, false
		}
		return analysis.PathGuardInverted, false
	}
	for _, m := range membershipCall.FindAllStringSubmatch(text, -1) {
		receiver, arg := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		if mentionsAny(receiver, names) && !mentionsAny(arg, names) {
			if separatorText.MatchString(text) {
				if polarity == guardRejectsWhenTrue {
					return analysis.PathGuardSeparatorText, false
				}
				return analysis.PathGuardUnclassified, false
			}
			if dotDotText.MatchString(arg) {
				if polarity == guardRejectsWhenTrue {
					return analysis.PathGuardDotDotText, false
				}
				return analysis.PathGuardUnclassified, false
			}
			isRootSub := polarity == guardEnforcesWhenTrue && isPositiveRootArg(arg, baseConstIs)
			return analysis.PathGuardSubstring, isRootSub
		}
	}
	return "", false
}

var identToken = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

func extractBaseIdentifier(expr string, depNames []string, baseConstIs func(string) bool) bool {
	if baseConstIs == nil {
		return false
	}
	found := false
	for _, tok := range identToken.FindAllString(expr, -1) {
		if mentionsAny(tok, depNames) {
			continue
		}
		if baseConstIs(tok) {
			found = true
		}
	}
	return found
}

// isPositiveRootArg reports whether the argument to `full.includes(arg)` is a trusted
// directory root expression, excluding CWD '.' (`path.resolve('.')`).
func isPositiveRootArg(arg string, baseConstIs func(string) bool) bool {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "'.'" || trimmed == `"."` || strings.Contains(trimmed, "('.')") || strings.Contains(trimmed, `(".")`) {
		return false
	}
	if (strings.HasPrefix(trimmed, "'") || strings.HasPrefix(trimmed, `"`)) && strings.ContainsAny(trimmed, "/\\") {
		return true
	}
	return extractBaseIdentifier(trimmed, nil, baseConstIs)
}
