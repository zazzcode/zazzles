---
last_updated_at: 2026-11-18
---

# PR process

This standard governs how PRs are titled, scoped, structured, and merged in this repository. It covers
the bracketed scope-label format used in every PR title, the one-logical-change-per-PR rule, the
prohibition on transitional cruft that lands dead on merge, and the CVE-prefix convention for security
remediations.

## PR titles — bracketed scope labels

Every PR title begins with one or more bracketed scope labels, before any descriptive text. Labels map to
the package layout in [architecture package map](../architecture/README.md#11-implemented-package-boundaries), so a reader can tell which part of
the tool a PR touches before opening it.

| Label | Scope |
|---|---|
| `CLI` | `cmd/scan` — flags, output formats, exit codes |
| `PARSE` | `internal/parse`, `internal/lang` — Tree-sitter integration, grammars, parsing |
| `PIPELINE` | `internal/pipeline` — one walk, language-runner selection and concurrency, fixed-order assembly |
| `ANALYSIS` | `internal/analysis` — shared route, candidate, evidence and assessment records |
| `GUIDELINES` | `internal/guidelines` — embedded language Analysis Guidelines |
| `TRACE` | Bounded flow and witnesses currently in `internal/parse`; future dedicated packages |
| `SCOPES` | future bounded scope checks, if separately approved |
| `JUDGE` | `internal/judge` — provider transport, questions, answers, evidence and claim policy |
| `LLM` | Planned independent Findings Reviewer; no implemented reviewer package |
| `CONTEXT` | Evidence assembly in `internal/parse` and `internal/judge`; dedicated packages are planned |
| `FIND` | Planned finding identity/baseline/diffing; presentation currently lives in `internal/report` |
| `REPORT` | `internal/report` — JSON, HTML and SARIF emitters |
| `CI` | GitHub Actions, tooling, and format gates |
| `DOC` | Documentation, standards, and specifications |
| `AGENT` | Agent skills and agent configuration under `.agents/` |

Cross-cutting PRs combine labels with `+` and **no spaces** inside the brackets. The canonical form is
`[ANALYSIS+TRACE]`, never `[ANALYSIS + TRACE]` or `[ANALYSIS] + [TRACE]`.

A label that maps to a package does not mean every change in that package needs every label — use the
labels for the packages the PR actually changes.

### Desired ✅

```text
[PARSE] Add TypeScript grammar and extension registry
[PARSE] Resolve barrel re-exports through index.ts
[TRACE] Bound path search depth and report dropped candidates
[GUIDELINES] Clarify SQL parameter-binding analysis guidelines
[JUDGE] Validate typed answers and uncertainty outcomes
[FIND] Fingerprint findings from rule identity and scoped sink site
[CI] Add race-detector test job
[DOC] Add path-tracking standard and register in index
[ANALYSIS+TRACE] Add argument bindings and consume them in path search
[CLI+REPORT] Report incomplete analysis and candidate evidence
```

### Not desired ❌

```text
Add TypeScript grammar
# missing scope label entirely

[ANALYSIS] + [TRACE] Add argument bindings
# split brackets; canonical form is [ANALYSIS+TRACE]

[ANALYSIS + TRACE] Add argument bindings
# spaces around +; canonical form is [ANALYSIS+TRACE]
```

## PR scope — one logical change per PR

A single PR scopes one logical change: one feature, one fix, one refactor, or one migration. Incidental
fixes discovered while working on a feature go in their own one-liner PR, or at minimum an isolated commit
on a separate PR. Drive-by edits ("while I'm here") go in their own PR.

Multi-scope PRs are reserved for changes that are genuinely cross-cutting — a graph change plus the
tracker code that consumes it — not for bundling unrelated work behind a multi-scope label. The label
declares cross-cutting *coupling*, not "I happened to touch all of these this week."

The rule extends to commits inside a PR: when a feature commit unavoidably includes an unrelated fix, the
fix lands in its own commit with a clear message so `git revert` and `git blame` work cleanly.

### Desired ✅

```text
[TRACE] Fix depth bound excluding sinks at the boundary
# one-liner extracted from a feature PR

[ANALYSIS+TRACE] Track paths across resolved barrel imports
# feature only, no bundled refactors or drive-by fixes
```

### Not desired ❌

```text
[ANALYSIS+TRACE] Track barrel-import paths + rename Node.Role + reformat package
# three logically distinct changes bundled into one PR
```

## No transitional cruft on merge

Transitional types, parameters, and interfaces added "for the migration" are removed in the same PR if
they offer no value after merge. If the only reason the code exists is "support for the previous
signature," update the callers in the same PR and delete the bridge.

Concrete patterns to remove before merge:

- An unused parameter retained "for compatibility" with a previous signature.
- An exported symbol kept only because one caller has not been updated yet.
- A deprecated struct field the new implementation never reads.
- A legacy adapter type whose only consumer is the code this PR replaces.

### Desired ✅

```go
// walk.Walk emits jobs on the channel; the consumer owns closing it.
func Walk(root string, jobs chan<- Job) error {
	// ...
}
```

### Not desired ❌

```go
// _ignorePaths is retained "for compatibility" with the previous signature.
// The new implementation never reads it; it becomes cruft the moment this
// PR merges.
func Walk(root string, _ignorePaths []string, jobs chan<- Job) error {
	// ...
}
```

```go
// LegacyNode is kept only so the old builder still compiles.
type LegacyNode struct {
	// shape matches the pre-refactor model, not the new one
}
```

## CVE remediation PR titles

PR titles that remediate a published CVE include the CVE identifier in the descriptive portion of the
title, after the scope label, in the form `[<scope>] <CVE-ID>: <human description>`. The identifier in the
title is what makes PR-list grep, dashboards, and post-incident audits work — burying it in the body
breaks all three.

This applies to zazzles's own code, dependencies, and build tooling. Maintaining zazzles's dependencies is
distinct from the excluded product capability of scanning target repositories for vulnerable dependencies
(see [scope exclusions](../project/02-project-scope.md#exclusions-and-limits)).

### Desired ✅

```text
[PARSE] CVE-2026-12345: bump tree-sitter runtime past parser overflow
[CI] CVE-2026-99999: pin actions/checkout to a patched release
```

### Not desired ❌

```text
[PARSE] Bump tree-sitter
# no CVE identifier; remediation context is invisible in PR lists
# and the changelog
```

## Draft-first, human merge

- Open PRs as drafts. A draft PR is the normal working state, and CI runs on it.
- Feature/deliverable PRs target `stage`; human release promotion alone targets `main`.
- **Agents do not merge PRs.** A human reviewer approves and merges.
- Do not merge locally into `stage`; the PR is the integration path.
- Release promotion (`stage` → `main` plus a version tag) is human-operated.

## Related standards

- [`code-structure.md`](code-structure.md) — the package layout the scope labels map to.
- [`spec-hygiene.md`](spec-hygiene.md) — the quality bar for the specification a deliverable PR
  implements.
- [`docs-hygiene.md`](docs-hygiene.md) — `[DOC]`-scoped conventions for standards documents and READMEs.
