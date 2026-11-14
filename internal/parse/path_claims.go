package parse

import (
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pathRequiredRoles are the mandatory evidence obligations of the claim,
// unioned with the catalog's selected obligations by the evidence validation checks.
var pathRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "path_operands"}

const pathScope = "path traversal claim over the supplied entry invocation, verified filesystem API contract, effective path operand and guard/transfer context; an unsafe witness needs only its own source-to-operand path; write content and options are not path sources"

func pathCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	roles := namespacedRoles(u, "path_")
	c := &analysis.Completeness{ClaimKind: "path_traversal", Required: append([]string{}, pathRequiredRoles...),
		Evidence: roles, Blockers: blockers, Coverage: coverage, Scope: pathScope}
	if c.Blockers == nil {
		c.Blockers = []analysis.Gap{}
	}
	if c.Coverage == nil {
		c.Coverage = []analysis.Gap{}
	}
	for role, items := range extraRoles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	c.Evidence["path_operands"] = c.Evidence["path_operand"]
	delete(c.Evidence, "path_operand")
	for _, d := range u.Dependencies {
		if d.SinkSlot == analysis.PathSlotFile || d.SinkSlot == analysis.PathSlotArchive {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
		}
	}
	if len(c.Evidence["invoked_callable"]) == 0 {
		c.Evidence["invoked_callable"] = append([]analysis.Evidence{}, c.Evidence["handler"]...)
	}
	f := u.Path
	c.ModelFacts = []string{
		"Platform assumption: " + f.Platform + " semantics are a declared analysis assumption, not inferred from the scanner host; Windows drive, UNC and backslash behavior is not modeled. Symbolic-link and race state is never inferred.",
		"Verified operation " + f.Operation + " (" + f.Role + "). Only the path operand slot is a path source; request data in the content or option slots is not.",
		"Dependency, operand, guard and flow records in path facts refer to the evidence table by index. Each flow keeps its own source, transformations and guard facts; a guard or constraint on one value, branch or invocation does not protect another.",
	}
	return c
}

// pathTransformKinds maps a callee's last member name to its transformation kind.
var pathTransformKinds = map[string]string{
	"join": analysis.PathTransformJoin, "resolve": analysis.PathTransformResolve, "normalize": analysis.PathTransformNormalize,
	"basename": analysis.PathTransformReduce, "dirname": analysis.PathTransformReduce, "extname": analysis.PathTransformReduce,
	"realpath": analysis.PathTransformRealpath, "realpathSync": analysis.PathTransformRealpath, "native": analysis.PathTransformRealpath,
	"decodeURIComponent": analysis.PathTransformDecode, "decodeURI": analysis.PathTransformDecode, "unescape": analysis.PathTransformDecode,
	"secure_filename": analysis.PathTransformSanitize, "unquote": analysis.PathTransformDecode, "unquote_plus": analysis.PathTransformDecode,
	"abspath": analysis.PathTransformAbsolutize, "normpath": analysis.PathTransformNormalize, "Path": analysis.PathTransformPathObject,
	"replace": analysis.PathTransformStringShape, "trim": analysis.PathTransformStringShape, "substring": analysis.PathTransformStringShape,
	"slice": analysis.PathTransformStringShape, "lower": analysis.PathTransformStringShape, "toLowerCase": analysis.PathTransformStringShape,
	"strip": analysis.PathTransformStringShape, "lstrip": analysis.PathTransformStringShape, "rstrip": analysis.PathTransformStringShape,
}

// pathOperationNames are the path-module members whose receiver must be a path module.
var pathOperationNames = map[string]bool{"join": true, "resolve": true, "normalize": true, "basename": true, "dirname": true, "extname": true, "abspath": true, "normpath": true, "realpath": true}

var pathReceivers = map[string]bool{"path": true, "posix": true, "posixpath": true, "ntpath": true, "fs": true}

var calleeText = regexp.MustCompile(`^\s*(?:await\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(`)

// transformKind classifies one transfer's shape from its source text.
func transformKind(e analysis.Evidence) string {
	text := strings.TrimSpace(e.Text)
	switch e.Kind {
	case "call_argument_dependency", "call_transfer", "path_call", "string_construction", "string_transform":
		if m := calleeText.FindStringSubmatch(text); len(m) == 2 {
			parts := strings.Split(strings.ReplaceAll(m[1], " ", ""), ".")
			last := parts[len(parts)-1]
			kind, ok := pathTransformKinds[last]
			// A path operation named on some other receiver (`parts.join`) is not one.
			if ok && pathOperationNames[last] && len(parts) > 1 && !pathReceivers[parts[len(parts)-2]] {
				ok = false
			}
			if ok {
				return kind
			}
		}
	case "expression", "string_interpolation":
		switch {
		case strings.HasPrefix(text, "`") || strings.HasPrefix(text, "f\"") || strings.HasPrefix(text, "f'"):
			return analysis.PathTransformTemplate
		case strings.HasSuffix(e.Span.File, ".py") && strings.Contains(text, " / ") && !strings.Contains(text, "+"):
			return analysis.PathTransformJoin
		case strings.Contains(text, "+"):
			return analysis.PathTransformConcat
		}
	case "binary_operator":
		if strings.Contains(text, "/") {
			return analysis.PathTransformJoin
		}
		return analysis.PathTransformConcat
	}
	return ""
}

// pathTransforms lists the path-shaping steps on a dependency's value chain in order.
func pathTransforms(d analysis.Dependency) []string {
	var out []string
	for _, e := range d.Transfers {
		if kind := transformKind(e); kind != "" {
			out = append(out, kind)
		}
	}
	return out
}

// pathRoot returns the constant base segment of a join/resolve construction.
func pathRoot(d analysis.Dependency) string {
	names := commandDepNames(d)
	for _, e := range d.Transfers {
		kind := transformKind(e)
		if kind != analysis.PathTransformJoin && kind != analysis.PathTransformResolve {
			continue
		}
		args := topLevelArguments(e.Text)
		if len(args) < 2 {
			continue
		}
		first := strings.TrimSpace(args[0])
		if first == "" || strings.Contains(first, d.Source.Text) || mentionsAny(first, names) {
			continue
		}
		return first
	}
	return ""
}

// topLevelArguments splits the first call's argument list at depth-zero commas.
func topLevelArguments(text string) []string {
	open := strings.Index(text, "(")
	if open < 0 {
		return nil
	}
	var out []string
	depth, start := 0, open+1
	quote := byte(0)
	for i := open + 1; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return append(out, text[start:i])
			}
			depth--
		case c == ',' && depth == 0:
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	return out
}

// selectionProjection matches an index into a comprehension, `[k for k in R if k == v][0]`:
// the result is an element chosen by comparison, not the request value, and how
// strongly that comparison constrains it is not modeled.
var selectionProjection = regexp.MustCompile(`^\s*\[[^\]]*\bfor\b[^\]]*\bin\b[^\]]*\]\s*\[`)

func selectsByComprehension(d analysis.Dependency) bool {
	for _, e := range d.Transfers {
		if e.Kind == "field_projection" && selectionProjection.MatchString(e.Text) {
			return true
		}
	}
	return false
}

var decodeCallText = regexp.MustCompile(`\b(?:decodeURIComponent|decodeURI|unescape|unquote|unquote_plus)\s*\(`)

func guardDescription(kind string) string {
	switch kind {
	case analysis.PathGuardAllowlist:
		return "a membership test against a constant finite collection"
	case analysis.PathGuardPrefixBoundary:
		return "a separator-bounded prefix comparison"
	case analysis.PathGuardPrefixBare:
		return "a prefix comparison without a separator boundary"
	case analysis.PathGuardRelative:
		return "a relative-path comparison against a root"
	case analysis.PathGuardCommonPath:
		return "a commonpath comparison against a root"
	case analysis.PathGuardDotDotText:
		return "a '..' text test"
	case analysis.PathGuardLibraryEntryCheck:
		return "an extractor release that rejects entry names escaping the destination (declared exact version): a lexical boundary, answer lexical_boundary"
	case analysis.PathGuardFrameworkRoot:
		return "a framework-enforced root that rejects a path escaping it (Express send with a constant root option, Flask send_from_directory with a directory that is not request-derived): a lexical boundary, answer lexical_boundary"
	case analysis.PathGuardSeparatorText:
		return "a path-separator text test that rejects multi-component values but not a bare '..' component"
	case analysis.PathGuardComponentSanitizer:
		return "a verified werkzeug secure_filename reduction to one safe path component (no separator or '..' can remain), which is a lexical boundary: answer lexical_boundary"
	}
	return "an unclassified condition"
}

// finishPathFlows records, per flow, the guards found for that dependency,
// whether an unresolved transfer blocks it and whether a decode follows a
// control. A guard that does not mention a dependency never covers it;
// adequacy is never decided here.
func finishPathFlows(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, info *pathGuardInfo, touches func(analysis.Gap, analysis.Dependency) bool) {
	f := u.Path
	f.Guards = make([]analysis.PathGuard, 0, len(guards))
	for i, g := range guards {
		kind := info.kinds[guardKey(g)]
		if kind == "" {
			kind = analysis.PathGuardUnclassified
		}
		f.Guards = append(f.Guards, analysis.PathGuard{Context: guardContext[i], Kind: kind})
	}
	for i := range f.Paths {
		p := &f.Paths[i]
		dep := u.Dependencies[p.Dependency]
		var controls []int
		for j, g := range guards {
			if info.deps[guardKey(g)][p.Dependency] {
				controls = append(controls, j)
			}
		}
		unknown := false
		for _, g := range c.Blockers {
			if touches(g, dep) {
				unknown = true
			}
		}
		switch {
		case info.ambiguousCallers:
			p.Protection = "unknown"
			p.Reason = "the operation is in a helper with several call sites, at least one without a control; per-call-site coverage is not modeled"
		case unknown:
			p.Protection = "unknown"
			p.Reason = "an unresolved transfer or helper touches this source-to-operand path"
		case selectsByComprehension(dep):
			p.Protection = "unknown"
			p.Reason = "the operand is an element selected from a collection by comparison with the request value; the selection is neither a raw request value nor a modeled allow-list control"
		case len(controls) > 0:
			p.Protection = "guarded"
			p.Controls = controls
			p.Reason = "a dominating or enclosing control mentions this value; its adequacy is not established by the scanner"
			for _, e := range dep.Transfers {
				if transformKind(e) != analysis.PathTransformDecode && !decodeCallText.MatchString(e.Text) {
					continue
				}
				for _, ci := range controls {
					if e.Span.File == guards[ci].Span.File && e.Span.StartByte >= guards[ci].Span.EndByte {
						p.DecodedAfterGuard = true
					}
				}
			}
			if p.DecodedAfterGuard {
				p.Reason += "; a decoding step follows the control, so it inspected the pre-decoded text"
			}
		default:
			p.Protection = "raw"
		}
	}
	if len(guards) > 0 {
		c.Evidence["guard"] = append(c.Evidence["guard"], guards...)
	}
	summary := []string{}
	for _, p := range f.Paths {
		line := "dependency " + itoa(p.Dependency) + " (" + u.Dependencies[p.Dependency].Source.Text + ") -> path: " + p.Protection
		if len(p.Transforms) > 0 {
			line += " via " + strings.Join(p.Transforms, ",")
		}
		if p.Root != "" {
			line += " (base " + p.Root + ", not a containment proof)"
		}
		if p.Protection == "guarded" {
			var kinds []string
			for _, i := range p.Controls {
				kinds = append(kinds, guardDescription(f.Guards[i].Kind))
			}
			line += " under " + strings.Join(kinds, " and ") + " (scanner syntax classification; whether it rejects before the operation and covers this value is for the assessment)"
		}
		summary = append(summary, line)
	}
	if len(summary) > 0 {
		c.ModelFacts = append(c.ModelFacts, "Path flow facts: "+strings.Join(summary, "; ")+". A raw or guarded flow is an independent source-to-operand witness; an unknown sibling flow stays visible as a blocker for that flow only and does not make a supported raw flow unknown.")
	}
}

// assemblePathClaims completes every Node path candidate before catalog attachment.
func (s *moduleSet) assemblePathClaims(report *analysis.AnalysisReport) {
	info := newPathGuardInfo()
	s.assembleClaims(report, claimHooks{
		kind:            "path_traversal_candidate",
		checkID:         "automatic-path",
		checkKind:       "path_traversal",
		present:         func(u *analysis.CandidateUse) bool { return u.Path != nil },
		fields:          commandFields,
		guards:          s.pathGuards(info),
		gapCovered:      s.pathGapCovered,
		chainGapCovered: s.pathModeledGap,
		complete:        pathCompleteness,
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int) {
			finishPathFlows(u, c, guards, guardIndex, info, func(g analysis.Gap, d analysis.Dependency) bool { return gapTouchesDependency(g, d) })
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.PathContract(u.Path.ContractID)
		},
	})
}
