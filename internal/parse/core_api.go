package parse

import (
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// Language core API.
//
// The identifiers below are the extension point for language adapters that
// live outside this package (internal/langphp today). They expose only
// functions and small value types over analysis records and Tree-sitter nodes;
// no adapter reaches into the JS/TS flow model (flow, value, moduleSet,
// sourceModule). Defined elsewhere in this package and part of the same API:
//
//   - Inventory (Root, Files): the one walked file inventory a runner reads.
//   - Inventory.HasLanguage: reports whether any inventory file has one of the languages.
//   - ClosedCallable (Params, Callees): the shared closed-summary lattice for refusal paths.
//   - ClosedCallable.Closed: true once finished with no refusal reason.
//   - ClosedCallable.Reject: records a refusal reason at a node.
//   - ClosedCallable.Read: marks a parameter read, or refuses a free variable.
//   - ClosedCallable.Finish: marks the summary complete.
//
//   - TextSources (NewTextSources, Root, Read, ReadBounded, Add, Get, Files): bounded,
//     root-confined reader and snapshot set for template and schema text.
//   - InlineScript, AnalyzeInlineScripts: the one bridge from a non-JS adapter to the browser
//     adapter (inline scripts isolated from text sources).
//   - GuardLang (Climb, Derive, Scope, AssignedBetween; grammar hooks Src, Blocks, Function,
//     Exits, Binding, Writes): the lexical guard engine adapted to one grammar.
//   - GuardSite, GuardPolarity: one control that dominates or encloses a call.
//   - CommandGuardScan (Collect, Derived): guard collection for one command sink.
//   - PathGuardInfo (Note, NoteWithMeta; Kinds, AmbiguousCallers): path guard classifications.

// SourceComment is the byte range of one comment excluded from model source.
type SourceComment = sourceComment

// SnapshotID returns the versioned, content-addressed record ID for one snapshot record, or an
// unresolved placeholder that FinalizeEntries rejects.
func SnapshotID(kind string, source analysis.Evidence, owner, key string) string {
	return snapshotID(kind, source, owner, key)
}

// Span returns the file span of a Tree-sitter node.
func Span(file string, n *sitter.Node) analysis.Span { return spanOf(file, n) }

// OpenParser opens a Tree-sitter parser for one grammar; the caller closes it.
func OpenParser(language unsafe.Pointer) (*sitter.Parser, error) { return openParser(language) }

// SourceComments lists the comments (and, for Python, standalone docstrings) under root.
func SourceComments(root *sitter.Node, src []byte, python bool) []SourceComment {
	return sourceComments(root, src, python)
}

// ModelSource returns src[start:end] with comment prose blanked, for model input.
func ModelSource(src []byte, start, end uint, comments []SourceComment) string {
	return modelSource(src, start, end, comments)
}

// RegisterInvocation appends the entry, its registration, dispatch binding, handler callable (when
// new) and invocation context to out, and returns that context.
func RegisterInvocation(out *analysis.AnalysisReport, entry analysis.EntryPoint, handler *analysis.Evidence, mechanism string, inputs []analysis.InputBinding, gaps []analysis.Gap) analysis.InvocationContext {
	return registerInvocation(out, entry, handler, mechanism, inputs, gaps)
}

// FinalizeEntries dedups callables, rekeys invocations, orders and validates entry records.
func FinalizeEntries(out *analysis.AnalysisReport) error { return finalizeEntries(out) }

// AssembleXSSClaims drops code-owned XSS uses and attaches XSS claim completeness to xss_candidate uses.
func AssembleXSSClaims(out *analysis.AnalysisReport) { assembleXSSClaims(out) }

// HTMLOutputContext classifies the HTML output context that follows prefix.
func HTMLOutputContext(prefix string) string { return htmlOutputContext(prefix) }

// RenderMarkup returns bounded surrounding markup for the interpolation at file.Text[start:end].
func RenderMarkup(file analysis.Evidence, start, end int) analysis.Evidence {
	return renderMarkup(file, start, end)
}

// CheckContextMatches reports whether declared check c applies to use u's invocation context.
func CheckContextMatches(r *analysis.AnalysisReport, c analysis.Check, u analysis.CandidateUse) bool {
	return checkContextMatches(r, c, u)
}

// AppendUniqueString appends s to a unless a already holds it.
func AppendUniqueString(a []string, s string) []string { return appendUniqueString(a, s) }

// Shared claim, guard, entry and text helpers (phase 3B, Python).

// TerminatingGuardKind is the context kind of a guard that ends the invocation on its rejecting side.
const TerminatingGuardKind = terminatingGuardKind

// SimpleTemplateField matches a dotted field path, the only template expression treated as a plain field read.
var SimpleTemplateField = simpleTemplateField

// ClassifyPathGuardAST evaluates condition syntax with branch polarity and boolean
// conjunction/disjunction structure so inverted or conditionally bypassed guards
// cannot acquire enforcing containment kinds.
func ClassifyPathGuardAST(cond *sitter.Node, src []byte, polarity GuardPolarity, names []string, defs map[string]string, defNodes map[string]*sitter.Node, collectionIs func(string) bool, baseConstIs func(string) bool) (string, bool) {
	return classifyPathGuardAST(cond, src, polarity, names, defs, defNodes, collectionIs, baseConstIs)
}

// CollectionDefinitions returns the declarations of the constant collections
// that guard conditions test (`ALLOWED` in `if (!ALLOWED.has(cmd))`), once
// each, in source order. A guard against an allow-list cannot be judged without
// the list's contents, which live outside the handler.
func CollectionDefinitions(conditions []*sitter.Node, src []byte, declaration func(name string) *sitter.Node) []*sitter.Node {
	return collectionDefinitions(conditions, src, declaration)
}

// CommandCompleteness builds the claim-scoped completeness shared by every
// language adapter. Language adapters supply blockers, guard evidence and
// supported-transfer evidence they established from source.
func CommandCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers []analysis.Gap, coverage []analysis.Gap) *analysis.Completeness {
	return commandCompleteness(u, extraRoles, blockers, coverage)
}

// CommandDepNames lists the names that stand for dependency d in guard and blocker text.
func CommandDepNames(d analysis.Dependency) []string {
	return commandDepNames(d)
}

// CommandGuardEvidenceKind names a guard site for the command claim. A
// condition that holds only on the rejecting side of an enclosing `if` (its
// else branch) is a false-branch fact, never an enforced one.
func CommandGuardEvidenceKind(site GuardSite) string {
	return commandGuardEvidenceKind(site)
}

// DedupeGaps drops repeated gaps (same kind, detail and location), keeping first-seen order.
func DedupeGaps(in []analysis.Gap) []analysis.Gap {
	return dedupeGaps(in)
}

// FinishOperandPaths applies the per-path guard and blocker rules to any family
// whose facts hold source-to-operand paths; paths is updated in place.
func FinishOperandPaths(u *analysis.CandidateUse, paths []analysis.CommandPath, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, derived [][]string, touches func(analysis.Gap, analysis.Dependency) bool) {
	finishOperandPaths(u, paths, c, guards, guardContext, derived, touches)
}

// FinishPathFlows records, per flow, the guards found for that dependency,
// whether an unresolved transfer blocks it and whether a decode follows a
// control. A guard that does not mention a dependency never covers it;
// adequacy is never decided here.
func FinishPathFlows(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, info *PathGuardInfo, touches func(analysis.Gap, analysis.Dependency) bool) {
	finishPathFlows(u, c, guards, guardContext, info, touches)
}

// GapTouchesDependency reports whether the gap lies on this dependency's
// source or transfer chain, excluding enclosing statements that merely
// contain unrelated operands.
func GapTouchesDependency(g analysis.Gap, d analysis.Dependency) bool {
	return gapTouchesDependency(g, d)
}

// GuardKey is the file and byte-span key of a guard evidence item.
func GuardKey(e analysis.Evidence) string {
	return guardKey(e)
}

// HTTPEntry builds the snapshot HTTP entry for route r registered at source.
func HTTPEntry(r analysis.Route, source analysis.Evidence, instance string) analysis.EntryPoint {
	return httpEntry(r, source, instance)
}

// HTTPInput binds an external request input of role to handler parameter param.
func HTTPInput(role string, param string, e analysis.Evidence) analysis.InputBinding {
	return httpInput(role, param, e)
}

// InputRole strips the "http." prefix from an input binding role.
func InputRole(role string) string {
	return inputRole(role)
}

// Itoa formats a non-negative int in decimal.
func Itoa(i int) string {
	return itoa(i)
}

// LogDataClass classifies a logged request container and key as credential, personal or container data, with a lexicon hint.
func LogDataClass(container string, key string) (string, string) {
	return logDataClass(container, key)
}

// MentionsAny matches identifiers by word boundary and expressions exactly.
func MentionsAny(text string, names []string) bool {
	return mentionsAny(text, names)
}

// NewCommandGuardScan starts a guard scan for one sink call, with helperSites listing the call sites of an enclosing helper.
func NewCommandGuardScan(lang GuardLang, call *sitter.Node, helperSites func(*sitter.Node) []*sitter.Node) *CommandGuardScan {
	return newCommandGuardScan(lang, call, helperSites)
}

// NewPathGuardInfo returns empty path guard classifications.
func NewPathGuardInfo() *PathGuardInfo {
	return newPathGuardInfo()
}

// NodeAt returns the smallest named node under n that spans [start, end], or nil.
func NodeAt(n *sitter.Node, start int, end int) *sitter.Node {
	return nodeAt(n, start, end)
}

// PathCompleteness builds the path claim completeness shared by every language adapter.
func PathCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers []analysis.Gap, coverage []analysis.Gap) *analysis.Completeness {
	return pathCompleteness(u, extraRoles, blockers, coverage)
}

// PathRoot returns the constant base segment of a join/resolve construction.
func PathRoot(d analysis.Dependency) string {
	return pathRoot(d)
}

// PathTransforms lists the path-shaping steps on a dependency's value chain in order.
func PathTransforms(d analysis.Dependency) []string {
	return pathTransforms(d)
}

// PresenceOnlyCondition reports a condition that only tests whether the
// operands exist, are non-empty or have a runtime type. Such a test does not
// constrain content and is never recorded as a guard.
func PresenceOnlyCondition(condition string, names []string) bool {
	return presenceOnlyCondition(condition, names)
}

// RequestOrigin reports a dependency whose source is a request input field.
func RequestOrigin(d analysis.Dependency) bool {
	return requestOrigin(d)
}

// SSRFCompleteness builds the claim-scoped completeness shared by every
// language adapter.
func SSRFCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers []analysis.Gap, coverage []analysis.Gap) *analysis.Completeness {
	return ssrfCompleteness(u, extraRoles, blockers, coverage)
}

// TextRange returns e narrowed to e.Text[start:end] as kind, with byte and line spans.
func TextRange(e analysis.Evidence, start int, end int, kind string) analysis.Evidence {
	return textRange(e, start, end, kind)
}

// TransformKind classifies one transfer's shape from its source text.
func TransformKind(e analysis.Evidence) string {
	return transformKind(e)
}
