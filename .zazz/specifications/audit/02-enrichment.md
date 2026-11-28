# Dependency Audit 02: Advisory enrichment — Deliverable Specification

**Worktree / branch:** `audit-mvp`, branch `audit-02-enrichment`, cut from `stage` after 01 merges (or
stacked on 01's branch with `gh-stack` if 01 is still in review)
**Feature:** Dependency Audit (`audit/`)
**Milestone:** [Dependency Audit series](README.md), specification 02 of 5
**Deliverable:** Advisory detail from OSV, NIST's NVD, CISA's KEV catalog and FIRST's EPSS, in the
findings file, the HTML report and the summary
**Project Owner:** zazzles owner
**Deliverable Owner:** zazzles owner
**Delivery topology:** single-deliverable branch
**Review artifact:** one draft PR into `stage`
**Approved review shape:** one PR
**Decomposition rationale:** This is the module's main value over running the audit tools alone,
so it comes straight after 01 and before more ecosystems. It is its own PR because it adds the only
network access `audit` makes itself.
**Integration branch:** `stage`
**Merge policy:** PR review required — agents commit/push feature branches only
**Drafted:** 2026-11-28
**Shared run log:** `.zazz/ephemeral/dependency-audit-run-log.md` (section `02 Advisory enrichment`)
**Execution tracking:** local run log only
**Implementation coordination:** Lead Agent, with Sonnet Contributor Agents allowed for the four
source clients
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability

The audit tools name an advisory but say little about it. On `vuln-nextjs`, `pnpm audit` gave
titles, ranges and patched versions for 71 advisories and filled no CVE field for any of them. After
the audit, `audit` now looks up every advisory in four public sources and adds what each knows:

| Source | What it adds | Looked up by |
| --- | --- | --- |
| OSV (`api.osv.dev`) | CVE and other aliases, description, CWE, CVSS vector, affected and fixed versions for every package the advisory covers, and typed references including the fixing commit | Advisory ID (GHSA, PYSEC and others) |
| NIST NVD (`services.nvd.nist.gov`) | NIST's CVSS scores (version 3.1 and 4.0 where present) with vectors, analysis status, CWE, description, publication dates, and references tagged as patch, exploit or advisory | CVE ID |
| CISA KEV (`www.cisa.gov`) | Whether the flaw is in the Known Exploited Vulnerabilities catalog, with the date added, the remediation due date, known ransomware use and the required action | CVE ID, matched against one downloaded catalog |
| FIRST EPSS (`api.first.org`) | The probability of exploitation in the next 30 days and its percentile | CVE ID |

Each source's answer is stored beside the audit tool's facts, never merged into them. The report
shows every source's severity side by side, breaks the CVSS vector into plain terms, flags known
exploited flaws, and orders findings by real-world risk: known exploited first, then EPSS, then the
highest CVSS score, then the tool's severity. Results are cached in the run directory, `--offline`
makes no request at all, and `audit enrich` refreshes an existing run.

---

## 1. Required Reading For The Implementor

### 1.a This Specification

Read this specification end to end first.

### 1.b Feature / Milestone Context

- [Series index](README.md) — the shared rules and "Running locally and in CI".
- [SCA design](../../architecture/sca-design.md) — §Findings and graph correlation: advisory data
  establishes the match; nothing is invented.

### 1.c Prior Specifications In This Delivery Effort

- [01 npm and pnpm](01-node.md) — the findings model, report, summary, exit codes, `--out` rule and
  invariants 2 to 6, all reused.

### 1.d Standards

The same as [01 §1.d](01-node.md#1d-standards). [testing.md](../../standards/testing.md)'s "no
network in unit tests" applies: every client test uses a local HTTP stub.

### 1.e Existing Code References

- `scan/internal/judge` transport — the retry rule for transient failures that [AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls)
  describes. Mirror the rule, not the code (no import across modules).
- `audit/internal/model`, `audit/internal/report` (from 01).

### 1.f Project Orientation

As [01 §1.f](01-node.md#1f-project-orientation). The live check in AC12 calls free public services
only; it needs no key and has no cost.

---

## 2. Invariants

### INVARIANT 1 — Four hosts, identifiers only

`audit` makes HTTPS `GET` requests only, to `api.osv.dev`, `services.nvd.nist.gov`, `www.cisa.gov`
and `api.first.org`, and to no other host. A request carries only advisory or CVE identifiers (the
KEV catalog download carries none). It never sends a package name, a version, a path, file contents
or anything else from the target. The User-Agent is `zazzles-audit/<version>` with no user details.

### INVARIANT 2 — `--offline` means no network

With `--offline`, `audit` makes no network request of any kind, and the report and summary say that
advisory detail was not fetched.

### INVARIANT 3 — Sources stay separate

Enrichment adds an `enrichment` object to each advisory and changes no field the audit tool supplied.
When sources disagree (a GitHub severity of `high` and an NVD score of 9.8, say), the file and the
report show both, each labelled with its source. No combined score is computed.

### INVARIANT 4 — A missing answer is shown, not hidden

Every advisory records, per source, `fetched`, `not applicable` (no CVE for NVD, KEV or EPSS),
`not found`, or `failed` with the reason. A failed lookup adds a `limits` entry and a line in the
summary; it does not change a project's status or the exit code.

### INVARIANT 5 — The NVD key is a secret

An NVD API key is read only from the `NVD_API_KEY` environment variable, sent only in the request's
`apiKey` header, and never printed, logged, cached or written to any output file. There is no flag
for it.

### INVARIANT 6 — Third-party text is data

As [01 INVARIANT 6](01-node.md#invariant-6--third-party-text-is-data), with descriptions and KEV
required actions cut to 1,000 characters.

---

## 3. Scope

### Approved Review Shape

One PR. Stop for Deliverable Owner sign-off if a different shape is needed.

### Strict Scope Constraint

Code changes live under `audit/`. Documentation changes are limited to the files below.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `audit/internal/enrich/` (`client.go`, `osv.go`, `nvd.go`, `kev.go`, `epss.go`, `cache.go`, `enrich.go`, tests) | New | The HTTP client with pacing and retries, one reader per source, the cache, and the step that fills each advisory |
| `audit/internal/model/` | Modified | The `enrichment` object and per-source status (§8 skeleton) |
| `audit/internal/report/` | Modified | Enriched advisory rows, the risk ordering, the summary's known-exploited and EPSS lines |
| `audit/cli/` (`enrich.go`, `run.go`, `ingest.go`, tests) | New / Modified | `audit enrich`; `--offline`, `--sources`, `--max-age` on `run`, `ingest` and `enrich` |
| `audit/testdata/enrich/` | New | Captured responses from each source and golden files |
| `docs/audit/advisory-sources.md` | New | What each source adds, what is sent, rate limits, the NVD key, offline use |
| `docs/audit/README.md`, `docs/audit/findings-schema.md` | Modified | The enrichment fields and the risk ordering |
| `.zazz/project/implementation-plan.md`, `.zazz/specifications/spec-index.md`, `.zazz/specifications/audit/README.md` | Modified | State |

### Out Of Scope

- Any other source (GitHub's advisory API, vendor feeds, exploit databases beyond NVD's reference
  tags) and any source needing an account other than the optional free NVD key.
- A combined risk score.
- Reachability, which belongs to Zazzles Agent.
- CWE names: the report shows CWE IDs linked to MITRE's pages, without a local copy of the catalog.

---

## 4. Decisions

### D-1 — OSV and NVD together, not NVD alone

**Decision.** Look every advisory up in OSV by its own ID, then look every CVE (from the tool or
from OSV's aliases) up in NVD.
**Why.** NVD is keyed by CVE, and the audit tools often give none: pnpm gave no CVE for any of
`vuln-nextjs`'s 71 advisories, and two of its six critical Next.js advisories have no CVE at all.
OSV, keyed by the GHSA ID the tool does give, covers every advisory and supplies the CVE NVD needs.
NVD then adds NIST's own scoring and exploit-tagged references.

### D-2 — KEV and EPSS for real-world risk

**Decision.** Add CISA's KEV catalog and FIRST's EPSS scores, both free and keyless.
**Why.** CVSS says how bad a flaw could be; KEV says attackers are using it now, and EPSS estimates
how likely that is soon. These two decide what to fix first far better than severity alone, and
CISA's due dates are what many teams' policies follow. The KEV catalog is one download matched
locally, so it reveals nothing about the project.

### D-3 — Show each source; order by a documented rule, not a score

**Decision.** Rows are ordered: KEV listed first; then by EPSS score, highest first; then by the
highest CVSS base score from any source; then by the tool's severity; then by name. The order is
stated in the report.
**Why.** A combined number hides where it came from and invites argument about weights. A stated
order is easy to check and easy to change later.

### D-4 — On by default, with `--offline` and `--sources`

**Decision.** `run` and `ingest` enrich unless `--offline` is given. `--sources osv,nvd,kev,epss`
(the default is all four) chooses sources. `audit enrich --out <dir>` enriches or refreshes an
existing run and rewrites `findings.json`, `report.html` and `summary.md`.
**Why.** The richer report is the point of the command, so it should not need a flag; offline use and
air-gapped CI still work.

### D-5 — Cache in the run directory

**Decision.** Store each response under `<out>/advisories/` (`osv/<id>.json`, `nvd/<cve>.json`,
`epss/<cve>.json`, `kev.json`) with its fetch time and source URL. A cached answer younger than
`--max-age` (default 24 hours) is reused; `--max-age 0` refetches.
**Why.** A report can be rebuilt offline, a re-run is fast, and the evidence for every enriched
field is on disk.

### D-6 — Pace NVD and retry only transient failures

**Decision.** NVD requests are paced to 5 per rolling 30 seconds without a key and 50 with one.
Requests to OSV and EPSS run up to 4 at a time; EPSS takes up to 100 CVEs per request. Every source
retries only HTTP 408, 429, 500, 502, 503 and 504, timeouts and dropped connections, up to 3 times,
honoring `Retry-After`. Each request has a 30-second timeout.
**Why.** NVD's published limits are strict and a blocked key hurts every later run. The retry rule
matches the one [AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls) sets for the judge
transport. Without a key, about 70 CVEs take about 7 minutes; the docs recommend a free key in CI.

### D-7 — Readers pinned to captured responses

**Decision.** Each source reader is written against responses captured in phase 1 and rejects a
shape it does not recognize as `failed: unrecognized response` for that advisory.
**Why.** A quick NVD lookup on 2026-11-28 returned `metrics` entries in a different shape from older
documentation, so each reader must be built from real responses, not from memory.

### D-8 — Fill a missing fix target from OSV

**Decision.** When the audit tool gave no fix version (Composer never does), the lowest OSV `fixed`
event above the installed version for that package becomes `fix.target`, with `fix.source: "osv"`;
the change size follows [01 D-7](01-node.md#d-7--fix-target-and-change-size-only-when-exact).
**Why.** Zazzles Agent needs a target to plan an upgrade, and OSV states it exactly.

---

## 5. Agent Implementation Rules

As [01 §5](01-node.md#5-agent-implementation-rules), with these changes:

- Branch `audit-02-enrichment` in the `audit-mvp` worktree. Scope verification:
  `git diff stage --stat` lists exactly the files in §3.
- Contributor Agents: after phases 1 and 2, up to four Sonnet agents may each write one source
  reader with its tests (`osv.go`, `nvd.go`, `kev.go`, `epss.go`). The Lead Agent owns `client.go`,
  `cache.go`, `enrich.go`, the model, the report and the CLI.
- Never print, log or write `NVD_API_KEY`. Tests use a fake key value and assert it appears only in
  the stub's received headers.
- Additional halt conditions:
  7. A source's live response differs from its captured fixture in a way the reader rejects.
  8. Any code path could send something other than an identifier, or reach a host outside
     INVARIANT 1.
  9. The NVD service answers 403, which means the key or the pacing is wrong.

---

## 6. Acceptance Criteria

- **AC1 — OSV.** From captured responses, the reader records aliases, description, CWE, CVSS vector,
  affected and fixed ranges for the advisory's package, and references by type, including `FIX`
  commits. A 404 is `not found`. Verified by `TestOSVReader`.
- **AC2 — NVD.** From captured responses, the reader records each CVSS version present with base
  score, severity, vector and source, analysis status, CWE, English description, dates, and
  references with their tags. A CVE NVD does not list is `not found`; an advisory with no CVE is
  `not applicable`. Verified by `TestNVDReader`.
- **AC3 — KEV.** From a captured catalog, a listed CVE records date added, due date, known ransomware
  use and required action; an unlisted CVE records `listed: false`; the catalog version is recorded.
  Verified by `TestKEVReader`.
- **AC4 — EPSS.** From captured responses, each CVE records score, percentile and score date; a
  batch of more than 100 CVEs is split. Verified by `TestEPSSReader`.
- **AC5 — Only identifiers leave.** Against a local stub, every request is a `GET` to one of the four
  hosts' paths, and its URL and headers hold no package name, version or path from the fixture
  project. Verified by `TestRequestsCarryOnlyIdentifiers`.
- **AC6 — Offline.** With `--offline`, a transport that fails the test on any request is never
  called, and the report and summary say detail was not fetched. Verified by `TestOffline`.
- **AC7 — Pacing and retries.** With a fake clock, 12 NVD requests without a key take three
  30-second windows, and with a key one window; 429 with `Retry-After` waits that long; 404 and 400
  are not retried; a fourth transient failure gives `failed`. Verified by `TestNVDPacing` and
  `TestRetryRule`.
- **AC8 — Key handling.** With `NVD_API_KEY` set, the key reaches the stub only in the `apiKey`
  header and appears in no output file, cache file, log line or error. Verified by `TestNVDKeyNeverWritten`.
- **AC9 — Cache.** A second run within `--max-age` makes no request; `--max-age 0` refetches;
  `audit enrich` on an existing run rewrites the three output files from the cache with no request
  when the cache is fresh. Verified by `TestEnrichCache`.
- **AC10 — Separate sources and fix fill.** No audit-tool field changes after enrichment; a fixture
  where GitHub says `high` and NVD scores 9.8 shows both; a Composer-style library with no fix gets
  `fix.target` from OSV with `fix.source: "osv"`. Verified by `TestEnrichmentKeepsToolFacts` and
  `TestFixFromOSV`.
- **AC11 — Report and summary.** Rows are ordered by D-3; each enriched advisory shows severities by
  source, the CVSS vector in plain terms (attack vector, attack complexity, privileges, user
  interaction, scope, and confidentiality, integrity and availability impact), a "Known exploited"
  badge with dates for KEV entries, EPSS score and percentile, CWE links, description, and fix,
  advisory and exploit references; `summary.md` lists every KEV entry and the ten highest EPSS
  scores. Golden files for `vuln-nextjs` with captured responses:
  `vuln-nextjs.enriched.findings.json`, `.report.html`, `.summary.md`. Verified by
  `TestEnrichedGolden` and `TestRiskOrder`.
- **AC12 — Live check on a sample copy.** `./bin/audit run` on a copy of `vuln-nextjs` with all four
  sources: every advisory has an OSV status, every advisory with a CVE has NVD, KEV and EPSS
  statuses, GHSA-f82v-jwr5-mffw shows CVE-2025-29927 with an NVD CVSS score, and the owner reviews
  the report. The request counts per source are recorded. Verified by the run log's evidence entry.
- **AC13 — Clean and in scope.** As 01 AC13 and AC14.

---

## 7. Test Strategy

Reference data, captured in phase 1 and committed under `audit/testdata/enrich/`:

- `osv/`: responses for the `vuln-nextjs` advisories, plus `GHSA-35jh-r3h4-6jhm` (lodash, two fixed
  ranges across packages) and one 404.
- `nvd/`: responses for the CVEs those advisories carry, one with CVSS 3.1 and 4.0, one awaiting
  analysis, and one 404.
- `kev/catalog.json`: the catalog as downloaded, trimmed to the entries the fixtures need plus a few
  others, with a note of the trim.
- `epss/`: responses for the fixture CVEs, including one batch request.
- Each capture's date and URL in the run log. These downloads are free public requests.

Every client test runs against `httptest.Server` with the base URLs injected; no unit test reaches
the network. Tests: `TestOSVReader`, `TestNVDReader`, `TestKEVReader`, `TestEPSSReader`,
`TestRequestsCarryOnlyIdentifiers`, `TestOffline`, `TestNVDPacing`, `TestRetryRule`,
`TestNVDKeyNeverWritten`, `TestEnrichCache`, `TestEnrichmentKeepsToolFacts`, `TestFixFromOSV`,
`TestEnrichedGolden`, `TestRiskOrder`.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

### TDD Entry Point

```go
func TestRequestsCarryOnlyIdentifiers(t *testing.T) {
	// Enrichment must reveal nothing about the project except advisory and CVE identifiers.
	seen := recordRequests(t) // stub server for all four sources
	enrichFixture(t, "pnpm/vuln-nextjs", seen.URLs())
	for _, r := range seen.Requests() {
		if r.Method != http.MethodGet || containsProjectData(r) {
			t.Fatalf("request leaks project data: %s %s", r.Method, r.URL)
		}
	}
}
```

### Prescriptive Execution Sequence

**Phase 1: Captures.** Fetch the §7 responses on the owner's machine, record dates and URLs, and
write down each source's response shape. Halt on anything §4 did not expect.

**Phase 2: Client and cache.** `client.go` (hosts allow-list, pacing, retries, timeouts, User-Agent,
key header) and `cache.go`, with `TestNVDPacing`, `TestRetryRule`, `TestNVDKeyNeverWritten`,
`TestEnrichCache`.

**Phase 3: Readers**, in parallel: OSV, NVD, KEV, EPSS, each with its test.

**Phase 4: Enrichment step and model.** `enrich.go` fills each advisory; `TestEnrichmentKeepsToolFacts`,
`TestFixFromOSV`, `TestRequestsCarryOnlyIdentifiers`, `TestOffline`.

**Phase 5: Report, summary and CLI.** Risk order, enriched rows, summary lines, `audit enrich` and
the flags; golden files.

**Phase 6: Docs**, then AC12.

### Skeleton: `audit/internal/model/enrichment.go`

```go
// Enrichment holds what each advisory source said about one advisory. Tool facts are untouched.
type Enrichment struct {
	Aliases []string      `json:"aliases"`
	OSV     *OSVDetail    `json:"osv,omitempty"`
	NVD     []NVDDetail   `json:"nvd,omitempty"` // one per CVE alias
	KEV     []KEVEntry    `json:"kev,omitempty"`
	EPSS    []EPSSScore   `json:"epss,omitempty"`
	Status  SourceStatus  `json:"status"`
}

// SourceStatus is fetched | not_applicable | not_found | failed per source, with a reason.
type SourceStatus struct {
	OSV, NVD, KEV, EPSS string
	Reasons             map[string]string `json:"reasons,omitempty"`
}

type CVSSScore struct {
	Version   string  `json:"version"` // "3.1", "4.0"
	BaseScore float64 `json:"base_score"`
	Severity  string  `json:"severity"`
	Vector    string  `json:"vector"`
	Source    string  `json:"source"` // who scored it, as NVD reports
}
```

The other detail types follow the fields in §6; JSON tags use lower-case `snake_case`. The golden
file and `docs/audit/findings-schema.md` are the contract once written. The fields are additive, so
the schema stays `zazzles.audit/v1`.

---

## 9. Definition Of Done

As [01 §9](01-node.md#9-definition-of-done), with AC1–AC13 of this specification and the AC12 live
check recorded.

---

## 10. Open Questions

- **OQ-1** — Include KEV and EPSS (D-2)? Recommended: yes; both are free, keyless and decide what to
  fix first.
- **OQ-2** — Enrichment on by default (D-4)? Recommended: yes, with `--offline` for air-gapped use.
- **OQ-3** — Will you register a free NVD API key for local use and CI? Recommended: yes; without one,
  `vuln-nextjs` takes about 7 minutes to enrich, with one about 45 seconds. `audit` works either way.

---

## 11. Run Log Protocol

As [01 §11](01-node.md#11-run-log-protocol), section `02 Advisory enrichment`.

---

## 12. Agent Implementation Prompt

```text
You are starting in the zazzles worktree `audit-mvp`. Verify pwd, branch and status per AGENTS.md.
Create branch audit-02-enrichment from stage (01 merged) or stack it on 01's branch with gh-stack.
Implement Dependency Audit 02: advisory enrichment from OSV, NVD, KEV and EPSS.

Specification: .zazz/specifications/audit/02-enrichment.md (read 01-node.md first)
Run log: .zazz/ephemeral/dependency-audit-run-log.md, section "02 Advisory enrichment"
Coordination: Lead Agent; up to four Sonnet Contributor Agents may each write one source reader
after phases 1 and 2. Companion skills: spec-driven, doc-check.

Resolve OQ-1 to OQ-3 with the owner first. Requests go only to the four hosts in INVARIANT 1 and
carry only identifiers. Never print, log or write NVD_API_KEY. Unit tests never reach the network.
Follow §5 halt conditions. Finish with the DoD and a verifier:

"Verify Dependency Audit 02 in audit-mvp. Read 02-enrichment.md, 01-node.md and the run log. Run each
AC's test or command. Read every HTTP call site and confirm INVARIANTs 1, 2 and 5. Check git diff
stage --stat against §3. Do not modify anything. Return PASS or FAIL per AC with evidence."

Prepare a draft PR into stage. Do not merge.
```

---

## 13. Implementation And Review Change Log

No changes recorded.
