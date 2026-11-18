// Package parse is the language core. It holds what at least two language
// adapters (internal/langjs, internal/langpy, internal/langphp), Assemble or
// internal/pipeline use: the walked Inventory and runner selection, entry
// finalization, Assemble, the shared claim, completeness and guard engines,
// spans, model source and text sources. It imports no language adapter and
// decides no validation adequacy locally.
package parse

// Language core API.
//
// This file is the index of the identifiers the language adapters
// (internal/langjs, internal/langpy, internal/langphp) use. Each is defined in
// the file named in its group and documented there. They expose functions and
// small value types over analysis records and Tree-sitter nodes; no adapter
// reaches into another adapter's flow model.
//
// Inventory (inventory.go):
//   - Inventory (Root, Files): the one walked file inventory every runner reads.
//   - Inventory.HasLanguage: reports whether any inventory file has one of the languages.
//
// Spans, parsers and model source (syntax.go, model_source.go, text_sources.go, string_sets.go):
//   - Span: the file span of a Tree-sitter node.
//   - OpenParser: opens a Tree-sitter parser for one grammar; the caller closes it.
//   - SourceComment: the byte range of one comment excluded from model source.
//   - SourceComments: the comments (and Python standalone docstrings) under a node.
//   - ModelSource: a source range with comment prose blanked, for model input.
//   - TextRange: evidence narrowed to a byte range of its text, with spans.
//   - SimpleTemplateField: matches a dotted field path in a template expression.
//   - PlainIdentifier: matches a bare JS/Python identifier.
//   - AppendUniqueString: appends a string unless the slice already holds it.
//   - Itoa: formats a non-negative int in decimal.
//
// Text sources (text_sources.go):
//   - TextSources: bounded, root-confined reader and snapshot set for template and schema text.
//   - NewTextSources: an empty set for one scan root.
//   - TextSources.Root: the scan root the set reads under.
//   - TextSources.Read: reads a file with the default 2 MiB limit.
//   - TextSources.ReadBounded: reads a regular file inside the root no larger than a limit.
//   - TextSources.Add: records a snapshot for a file.
//   - TextSources.Get: returns a file's snapshot.
//   - TextSources.Files: the files with snapshots, sorted.
//
// Entries and checks (entry_context.go, check_context.go):
//   - SnapshotID: the versioned, content-addressed ID of one snapshot record.
//   - HTTPEntry: the snapshot HTTP entry for a route registration.
//   - HTTPInput: binds an external request input to a handler parameter.
//   - InputRole: an input binding role without its "http." prefix.
//   - RegisterInvocation: appends an entry's registration, dispatch, callable and invocation context.
//   - FinalizeEntries: dedups callables, rekeys invocations, orders and validates entry records.
//   - CheckContextMatches: whether a declared check applies to a use's invocation context.
//   - EvidenceRoles: groups context evidence by kind.
//   - ConditionalFalseTest: the context kind of a test false on every path of the invocation.
//
// XSS and HTML (xss_claims.go, html_context.go, render_context.go):
//   - AssembleXSSClaims: drops code-owned XSS uses and attaches XSS claim completeness.
//   - HTMLOutputContext: the HTML output context that follows a prefix.
//   - RenderMarkup: bounded surrounding markup for one interpolation.
//
// Closed summaries (closed_summary.go):
//   - ClosedCallable (Params, Callees): the shared closed-summary lattice for refusal paths.
//     Reasons is exported for the adapters' tests.
//   - ClosedCallable.Closed: true once finished with no refusal reason.
//   - ClosedCallable.Reject: records a refusal reason at a node.
//   - ClosedCallable.Read: marks a parameter read, or refuses a free variable.
//   - ClosedCallable.Finish: marks the summary complete.
//   - SummaryReason: one refusal reason and its span.
//
// Guard engine (guard_climb.go, command_completeness.go, command_guards.go):
//   - GuardLang (grammar hooks Src, Blocks, Function, Exits, Binding, Writes): the
//     lexical guard engine adapted to one grammar.
//   - GuardLang.Climb: visits the controls that dominate or enclose a call.
//   - GuardLang.Derive: extends names with values derived from them in a scope.
//   - GuardLang.Scope: the function scope that encloses a node.
//   - GuardLang.AssignedBetween: whether a name is written between a guard and a call.
//   - GuardSite: one control that dominates or encloses a call.
//   - GuardPolarity: whether a guard rejects or enforces on its true branch.
//   - GuardEnforcesWhenTrue: the polarity of a guard whose true branch holds the call.
//   - TerminatingGuardKind: the context kind of a guard that ends the invocation.
//   - PresenceOnlyCondition: a condition that only tests presence, emptiness or type.
//   - MentionsAny: matches identifiers by word boundary and expressions exactly.
//   - CollectionDefinitions: the declarations of constant collections guards test.
//
// Command claims (command_guards.go, command_completeness.go):
//   - CommandGuardScan (Scope): guard collection for one command sink.
//   - CommandGuardScan.Collect: the guard sites that cover the sink's dependencies.
//   - CommandGuardScan.Derived: names derived from each dependency in the guarded scopes.
//   - NewCommandGuardScan: starts a scan for one sink call and its helper call sites.
//   - CommandGuardEvidenceKind: names a guard site for the command claim.
//   - CommandCompleteness: claim-scoped command completeness shared by every adapter.
//   - CommandDepNames: the names that stand for a dependency in guard and blocker text.
//   - FinishOperandPaths: per-path guard and blocker rules for source-to-operand paths.
//   - GapTouchesDependency: whether a gap lies on a dependency's source or transfer chain.
//   - DedupeGaps: drops repeated gaps, keeping first-seen order.
//
// Path claims (path_guard_classify.go, path_claims.go):
//   - PathGuardInfo (Kinds, AmbiguousCallers): path guard classifications.
//   - PathGuardInfo.Note: records a guard's kind for covered dependencies.
//   - PathGuardInfo.NoteWithMeta: Note with root-containment metadata.
//   - NewPathGuardInfo: empty path guard classifications.
//   - ClassifyPathGuardAST: classifies a guard condition with polarity and boolean structure.
//   - EmptyComparison: matches a comparison with an empty string, None, null or undefined.
//   - GuardKey: the file and byte-span key of a guard evidence item.
//   - PathCompleteness: claim-scoped path completeness shared by every adapter.
//   - FinishPathFlows: records per-flow guards, blocking transfers and decodes after controls.
//   - PathRoot: the constant base segment of a join/resolve construction.
//   - PathTransforms: the path-shaping steps on a dependency's value chain.
//   - TransformKind: one transfer's shape from its source text.
//   - RequestOrigin: whether a dependency's source is a request input field.
//
// SSRF, logging and syntax helpers (ssrf_completeness.go, log_data_class.go, check_context.go):
//   - SSRFCompleteness: claim-scoped SSRF completeness shared by every adapter.
//   - LogDataClass: classifies a logged request container and key.
//   - LexiconHint: classifies a key name as credential or personal data.
//   - NodeAt: the smallest named node that spans a byte range.
//
// Used by internal/pipeline rather than the adapters (inventory.go, assemble.go):
// Inventory.Runners, Languages, NormalizeEntry, Options and Assemble.
