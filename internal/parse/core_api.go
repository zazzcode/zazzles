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
// Phase 3B extends this list for Python and JS/TS.

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
