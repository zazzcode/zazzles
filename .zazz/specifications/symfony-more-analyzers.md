# Symfony application-security analyzers — stacked lane contract

> This document is the shared contract of a stacked branch lane. Each branch has its own
> specification with its scope, decisions, acceptance criteria, tests and execution sequence:
> [-1](symfony-more-analyzers-1.md), [-2](symfony-more-analyzers-2.md),
> [-3](symfony-more-analyzers-3.md) and [-4](symfony-more-analyzers-4.md). Rules stated here are
> not repeated there. Execution state lives in the run log.

- **Worktree / lane** `symfony-more-analyzers`, a sibling worktree of the bare repository.
- **Baseline** `stage` at `af5dbc1` (merge of [PR #39](https://github.com/zazzcode/zazzles/pull/39)).
  Every path is relative to the repository root.
- **Feature** PHP and Symfony website support in Code Scan.
- **Milestone** Close Symfony website support: every defect class the sample documents is either
  detected by a general analyzer or stated as outside Code Scan with the reason.
- **Deliverables** Four, one per branch (§0).
- **Deliverable Owner** The human user. **Project Owner** the same.
- **Specification storage** `.zazz/specifications/`, tracked in Git and reviewed in the PRs.
- **Run log** `.zazz/ephemeral/symfony-more-analyzers-run-log.md` (gitignored), one section per
  branch. No tracker is used.
- **Implementation coordination** One Lead Agent per session. Each branch is implemented in its
  own unattended session, in dependency order (§4.2).
- **Companion guides** [Using gh-stack](../docs/using-gh-stack.md), `spec-driven`, `pr-builder`.
- **Integration branch** `stage`. Every PR needs human review. Agents never merge.
- **Approved review shape** Bounded stacked review lane of four draft PRs.

## 0. Stacked-branch model

### Why this is stacked

The punch list from the review of PR #39 names eight analyzer gaps. They are not independent:

- Mass assignment and authorization both need to know which stored fields carry privilege. That
  fact is built once, in branch 1.
- Account enumeration applies only to an entry that needs no login. The access rules of an entry
  are built in branch 2 and read by branches 3 and 4.
- The CSRF configuration check counts state-changing entries, and the address-guard record names
  the proxy configuration that decides whether the address can be forged. Both read facts of
  branch 2.

One PR for all of it would exceed what a reviewer can hold. Sibling PRs would each have to rebuild
or duplicate the shared facts. A stack lets each analyzer group be reviewed on its own diff while
the shared facts land once.

Rejected alternatives: one milestone PR (too large to review, as PR #39 showed at 112 fixture
cases), and sibling worktrees (the three shared facts above would be written three times).

The stack shape is fixed before implementation. A session that finds it needs to add, remove,
split or merge a branch treats that as a halt (§4.2). The owner then updates this document and
its change log.

### Branches

| Order | Branch | Specification | Delivers | Base |
|---:|---|---|---|---|
| 1 | `symfony-more-analyzers-1` | [-1](symfony-more-analyzers-1.md) | Information exposure, mass assignment, the security-field census, and all four specifications | `stage` |
| 2 | `symfony-more-analyzers-2` | [-2](symfony-more-analyzers-2.md) | Entry access rules and the authorization family, including address-based guards | Branch 1 |
| 3 | `symfony-more-analyzers-3` | [-3](symfony-more-analyzers-3.md) | Account enumeration, recovery-secret delivery, weak password hashing, the mailer sink | Branch 2 |
| 4 | `symfony-more-analyzers-4` | [-4](symfony-more-analyzers-4.md) | Framework and deployment configuration, SSRF through a shell URL client, whole-sample acceptance, closing documentation | Branch 3 |

All four branches live in this one worktree. No branch gets its own worktree.

### Lane setup

**Done on 2026-11-22.** The branch was renamed, the stack was initialized on `stage`, and the
documentation checkpoint is commit `28c3e7f` on `symfony-more-analyzers-1`, pushed to `origin`.
The branch 1 session verifies this state with `gh stack view --json` and `git log` and does not
repeat it. The commands that were run:

```bash
git config rerere.enabled true
git branch -m symfony-more-analyzers symfony-more-analyzers-1
gh stack init --base stage symfony-more-analyzers-1
```

Check `gh stack init --help` first: extension `v0.3.0` is installed, and an older form needs
`--adopt`.

**First checkpoint.** Before any analyzer work starts, the documentation written with this
contract is committed on branch 1 and pushed: the five specifications, the
[specification index](spec-index.md), the `README.md` index entry and the implementation-plan
change. It is the first commit of branch 1, so it reaches `stage` with the branch 1 PR. Each later
session adds its branch from the top of the stack with `gh stack add symfony-more-analyzers-<n>`.

### Rebase rule

An upper branch is rebased upstack from the branch below it until the lower PR lands on `stage`
through human review. After a lower PR lands, run `gh stack sync` and verify that the upper PR's
diff holds only its own work. Never squash an upper branch onto `stage` while it is stacked.

A change to a lower branch is committed on that branch, followed by `gh stack rebase --upstack`.
All `gh stack` commands are non-interactive: pass branch names, use `gh stack view --json`, use
`gh stack submit --auto`, and pass `--remote origin` when more than one remote exists.

## 1. Required reading for every branch

- [AGENTS.md](../../AGENTS.md), then the orientation sections it points to for the task.
- [Using gh-stack](../docs/using-gh-stack.md): "Sync versus rebase", "Correct misplaced changes"
  and scenarios 3, 5 and 6.
- [PHP Symfony support](php-symfony-support.md) §3 (invariants), §5 D-1, D-9 to D-11, D-15, D-25
  to D-27, and [its results](../evaluation/symfony-results.md).
- [Unsafe deserialization](unsafe-deserialization.md) §4 "Wiring checklist": the list of sites a
  new family touches. It is the precedent for every family this lane adds.
- [Evidence and claims](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [finding types](../architecture/finding-types.md) and
  [component ownership](../architecture/analysis-packs.md#boundary-and-ownership).
- Standards from `.zazz/standards/index.yaml`: [code structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [PR process](../standards/pr-process.md),
  [docs hygiene](../standards/docs-hygiene.md), [spec hygiene](../standards/spec-hygiene.md).
- [Sample reference policy](../../docs/samples/reference-policy.md).

## 2. Cross-branch contract

### 2.1 Generality (the load-bearing rule)

`zazzcode/vuln-symfony` is a measuring sample, not the target. Every analyzer in this lane is a
general capability for PHP websites, and for any Symfony website where the claim needs framework
facts.

- A rule is a contract of the PHP language, a PHP built-in, Symfony, Doctrine, Twig, Apache,
  nginx, Docker or cron. It cites that component's documentation. No rule names an application's
  class, method, field, route, file or message.
- A field is privileged because of what the framework or the code does with it (§2.3), never
  because of its name. A name is recorded only as a hint the decision model can weigh.
- Each family proves itself on synthetic fixtures first. Every fixture set includes a **transfer
  project**: a second synthetic application with different class, field, route and message names
  and a different code shape from the first. A rule that matches on vocabulary fails there.
- Where a claim needs no framework fact, it also works on plain PHP (server-mapped files and
  superglobals). The table below states which.
- The sample's source, comments and identifiers never enter a detector, a fixture, a component
  text or a model request.

| Family | Any PHP website | Additional Symfony facts |
|---|---|---|
| `exposure` | Yes | Routes as entries |
| `mass-assignment` | Yes: superglobal keys into dynamic property writes | Request bags, Doctrine entities, Form, serializer and payload mapping shapes |
| `authorization` | Address-guard and session-check facts | Access rules, entity arguments, role and ownership checks. Function-level and object-level claims need these |
| `account` | Yes: weak password hashing, PHP `mail()`, literal `echo` responses | Finders, flashes, Symfony Mailer, the security user contract |
| `configuration` | Yes: Apache, nginx, `.htaccess`, `php.ini`, Dockerfile, cron | `framework.yaml`, `security.yaml`, `web_profiler.yaml` |
| `ssrf` (extended) | Yes | None |

### 2.2 Names introduced by this lane

Names are fixed here so upper branches and documents can refer to them before they exist. A
family's `--only-family` name is user-visible.

| Branch | Family | Candidate kinds | Finding type IDs | CWE |
|---:|---|---|---|---|
| 1 | `exposure` | `info_exposure_candidate` | `information-exposure` | 200, 215 |
| 1 | `mass-assignment` | `mass_assignment_candidate` | `mass-assignment` | 915 |
| 2 | `authorization` | `authorization_candidate` | `missing-authorization`, `address-based-access` | 862, 639, 285, 291 |
| 3 | `account` | `account_enumeration_candidate`, `recovery_delivery_candidate`, `password_hash_candidate` | `account-enumeration`, `weak-password-recovery`, `weak-password-hash` | 204, 640, 1287, 916 |
| 4 | `configuration` | `configuration_candidate` | `insecure-configuration` | 548, 352, 1004, 614, 732, 269, 489 |
| 4 | `ssrf` (existing) | `ssrf_candidate` with contract `api.php-shell-url-client-v1` | `server-side-request-forgery` | 918 |

Every new family takes new component, contract and protocol identifiers. No existing component's
bytes, version or digest changes.

### 2.3 Facts a lower branch exposes

These are the seam. An upper branch reads them and does not rebuild them.

**Security-field census (branch 1).** For each stored field, the roles that source evidence
establishes. The roles are a closed list.

| Role | Established by |
|---|---|
| `credential` | The field returned by `getPassword()` of a class implementing `PasswordAuthenticatedUserInterface`, or a field written from a password-hash operation (`password_hash`, a `PasswordHasherInterface` or `UserPasswordHasherInterface` call) |
| `login_identifier` | The `property` of an entity user provider in `security.yaml`, or the field returned by `getUserIdentifier()` |
| `role_source` | A field returned by `getRoles()` of a `UserInterface` class, and any field that method or a Doctrine lifecycle callback reads to compute that value, one step deep |
| `recovery_secret` | Added by branch 3: a field written from a random-secret source and compared with a request value |
| `name_hint` | A field name on the closed hint list of branch 1 D-4. A hint only. It never sets another role |

Go shape, in `scan/internal/langphp/security_fields.go`:

```go
type securityField struct {
	storageKey string              // "php-sql:<table>.<column>", as doctrine_storage.go builds it
	roles      []string            // sorted, from the closed list above
	evidence   []analysis.Evidence // one per role, at the establishing source
}
// securityFields returns the census for one project. Deterministic; computed once per phpSet.
func (s *phpSet) securityFields(p *symfonyProject) map[string]securityField
```

On the wire a candidate carries `security_fields: [{storage_key, roles, evidence}]` for the fields
its operation writes or reads. Fact schema name: `security-fields-v1`.

**Entry access (branch 2).** For each Symfony entry, in the report's entry record and available
to every candidate under that entry:

```go
type EntryAccess struct {
	Authentication string     `json:"authentication"` // "required" | "none" | "unresolved"
	Roles          []string   `json:"roles,omitempty"`  // from the first matching rule and attributes
	Sources        []Evidence `json:"sources"`          // the rule, attribute or firewall that decided
	Gaps           []Gap      `json:"gaps,omitempty"`   // voters, custom authenticators, expressions
}
```

**Guard kinds (branch 2).** A dominating condition recorded on a candidate carries one kind from
this closed list: `role_check`, `ownership_check`, `authenticated_check`, `secret_check`,
`address_check`. Branch 3 reads `secret_check`. Branch 4 reads `address_check`.

**State changes (branch 2).** Each entry lists the stored writes its action performs:
`state_changes: [{storage_key, operation, span}]` with `operation` one of `create`, `update`,
`delete`, `file_write`, `file_delete`. Branch 4 reads it for the CSRF and method checks.

**Mailer and input shape (branch 3).** Not read by branch 4. Stated in the branch 3 specification.

### 2.4 Contract change rule

If an upper branch needs a different shape from a lower branch's fact, that is a halt (§4.2). An
unattended session does not change the shape itself. After the owner approves, the change is made
on the lower branch, the stack is rebased upstack, and both specifications and this section are
updated in place with a change-log entry.

### 2.5 File ownership

`gh-stack` does not track which branch owns a file. The session stages paths deliberately.

- A file created by a lower branch is changed by an upper branch only to add that branch's own
  rows or section: family registration lists, `calls.go` dispatch lines, `check.py` kind maps,
  `cases.json` rows, the shared architecture and user documents, and
  `scan/cli/testdata/architecture-baseline.json` additions.
- Each upper specification has a no-drift criterion that lists the lower-owned files it must not
  change.

### 2.6 Extend before adding

A new family is the last choice, not the first. Existing analyzers and detection code are
extended and improved wherever the claim fits them.

- A claim joins an existing family when that family's questions already ask it and no existing
  request changes. SSRF through `curl` (branch 4) is the case: it is a new contract on `ssrf`.
- A claim gets a new family only when it asks a different question on different evidence. Each
  branch specification's decisions say why for each family it adds.
- New claims are built on evidence the scanner already records, and improve that code in place
  rather than beside it:

| Existing code | Reused or improved by |
|---|---|
| Wildcard storage write (`storage_write_wildcard`) | Mass assignment reads it as its sink evidence |
| Guard engine (`control.go`, `guards.go`): dominating conditions and early exits | Authorization guard kinds, exposure guards, the lookup branch of enumeration. No second guard engine |
| Entity argument binding and `#[CurrentUser]` | Subject provenance for authorization |
| Finder and flash models | Enumeration lookups and responses |
| Storage writer census | State changes per entry, peer access, the recovery-secret field |
| Command model and `filter_var` guard contracts | The shell URL client contract |
| Upload `destination_served` fact | The directory-listing join |
| Bounded YAML reader and walk allow-list | `security.yaml`, `framework.yaml` |
| `ssrf` and `command` families | Unchanged requests; new records only |

- The owner decided the packaging in §5. A session that finds a claim would fit an existing
  family better records the evidence in the run log and the results document as a follow-up and
  implements the contract as written.
- A defect the work exposes in an existing analyzer is fixed on the branch that found it, with a
  fixture case, when the fix is inside that branch's scope. Otherwise it is recorded in the
  results document as a follow-up.

### 2.7 Protocol and policy pattern for a new family

Every new family is judged the way the existing families are. Each branch specification gives a
protocol table for its families with exact question names, the allowed answers, and the status
rules. The shared rules are here. `scan/internal/judge/deserialization.go` is the code to mirror.

**Statuses.** A judged candidate ends in one of three statuses, the ones the existing policies
set: `confirmed_vulnerability` (a Confirmed finding), `protected_for_claim` (Protected) and
`needs_evidence` (Review). In this lane's criteria, "Confirmed" means `confirmed_vulnerability`.
"A control is not a finding" means its candidate, when one exists, is not
`confirmed_vulnerability` and is not presented as a poor-practice finding. A control with offline
expectation `guarded` must end `protected_for_claim`.

**Policy order.** Each `apply<Family>Policy` function does these steps in this order and returns
at the first that applies:

1. Start at `needs_evidence`.
2. The answers carry the family's protocol identifier. Otherwise gap `<family>_protocol_missing`.
3. The candidate's facts exist and validate, its completeness record names the claim kind, and
   every required evidence role of the branch's table has evidence. Otherwise
   `<family>_claim_missing`, `<family>_facts_invalid` or `<family>_evidence_missing`.
4. No answer contradicts a recorded fact. The branch's table lists the contradictions.
   Otherwise `<family>_answers_inconsistent`.
5. Any gap the branch's table marks **blocking** keeps the candidate at `needs_evidence`.
6. The table's Protected rule gives `protected_for_claim`.
7. The table's Confirmed rule gives `confirmed_vulnerability`.
8. Anything else stays `needs_evidence`.

**Operation-centered claims.** `exposure`, `configuration` and `password_hash_candidate` have no
request source. Their completeness record requires the operation and entry (or file) evidence
only, and `check.py` treats a positive of these kinds as present when the candidate is at its
anchor with no blocker. No policy step for them asks for an `input_source`.

**A policy test per family.** Each family has a table-driven policy test with one row per rule
of its table: an answer combination and the recorded facts, and the status and gap expected. It
runs offline with no model.

**Wiring.** A new family touches every site the deserialization family touched. Find them with:

```bash
grep -rn 'deserialization_candidate\|DeserializationKind\|\.Deserialization\b\|DeserializationProtocol\|"deserialization"' --include='*.go' scan | grep -v _test.go
```

Each hit gets a sibling for the new family or a recorded reason for skipping it in the run log.

## 3. Sample answer key for the lane

Source-reviewed at `086f81f941501bd1170b249e01107ba99beb2962` on 2026-11-22. Each branch
specification owns the rows of its families with their anchors and offline expectations, freezes
them into `.zazz/evaluation/recall-gap-inventory/cases.json` and the
[detection guide](../evaluation/vuln-symfony-detection-guide.md) as its first step, and never
relabels a row. The table maps the sample README's 21 entries to the lane.

| README entry | Row | Branch |
|---|---|---:|
| 1 SSRF half of the `Referer` command | `SYM-SSRF-02` | 4 |
| 2, 3, 4, 5, 11, 12, 14, 15 | Found at the baseline (14 required positives of PR #39) | — |
| 6 User enumeration | `SYM-ENUM-01` | 3 |
| 7, 9, 10, 13 Missing right control | `SYM-AUTHZ-01` to `-04` | 2 |
| 8 Missing right control on `/user/delete/{user}` | Not present in source at the pin. The delete action is routed under `^/admin` and is control `SYM-AUTHZ-N03` | 2 |
| 16 Sensitive endpoint for SSRF | `SYM-LOCAL-01`, `SYM-LOCAL-02` | 2 |
| 17 `phpinfo` | `SYM-INFO-01` | 1 |
| 18 Directory listing | `SYM-CONF-01` | 4 |
| 19 Mass assignment on `/user/edit/` | `SYM-MASS-01` | 1 |
| 20 Recovery token to request-chosen recipients | `SYM-RESET-01` | 3 |
| 21 Cron privilege escalation | `SYM-CONF-02` | 4 |
| Unlisted, source-reviewed | `SYM-ENUM-02`, `SYM-HASH-01` (3), `SYM-CONF-03`, `SYM-CONF-04` (4) | 3, 4 |

Closing state after branch 4: 20 of the 21 README entries are detected, entry 8 is recorded as not
reproducible, and committed secrets in `.env` stay outside the lane (§5 OQ-3).

## 4. Agent implementation rules for every branch

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md).

- **Session start.** Verify `pwd`, `git branch --show-current`, `git status --short --branch`,
  `git worktree list` and `gh stack view --json`. Read this document, the branch specification,
  the run log and `git log`. Confirm the stack still matches §0.
- **Integration.** Commit and push stack branches only. Open draft PRs with
  `gh stack submit --auto`. Never merge. Verify `git config user.name` is `zazzcode`.
- **Branch discipline.** Be on the intended branch before staging. Use `git add <path>`, not
  `gh stack add -Am`. After a lower-branch change run `gh stack rebase --upstack`.
- **Working directory.** Run every command from the worktree root, where `go.mod` is.
- **Test first.** Each slice adds its fixtures and its failing test first and records the failing
  output in the run log before a non-test file changes.
- **Fixtures.** Written for the branch from its case tables. No fixture copies sample source or
  contains a `#VULNERABILITY` comment. Expected line numbers are computed by hand when the fixture
  is written and kept in the test table.
- **Sample.** Read-only. Verify the pin and `git status --porcelain --ignored` is empty before and
  after every scan. Write reports with `--output-dir` under
  `<DEV_ROOT>/zazzcode/zazzles/_test-findings/vuln-symfony/run-<id>/`, outside the repository.
- **Hard constraints.** §2, each branch's invariants, decision tables, acceptance criteria and
  case expectations.
- **Adaptive guidance.** File names inside a package, helper names, skeleton bodies and test
  mechanics may change when the code calls for it. Record each change in the run log.
- **Scope.** A branch's diff stays inside `scan/`, `docs/`, `.zazz/`, `README.md`, `go.mod` and
  `go.sum`. If required wiring needs a file its scope table does not list, add the row and the
  reason to that table and the run log and continue.
- **Paid calls.** Paid judged runs of the sample are authorized by the owner for this lane
  within §4.1. Follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls) for keys.
  Offline criteria need no key.
- **Gate.** The contributor gate is `gofmt -l cmd scan` (prints nothing), `go vet ./...`,
  `go build ./...` and `go test -race ./... -count=1`.
- **Verifier.** Each branch ends with a fresh-context, read-only Verifier Agent running the
  checks its specification lists.

### 4.1 Judged checkpoint protocol

The owner requires paid judged runs in every branch. Offline tests prove that the evidence is
recorded. Only a judged run proves that the decision model reaches the right status from it.

| Run | When | Scope | Passes when |
|---|---|---|---|
| **Family checkpoint** | After each family (or the `ssrf` extension) passes its offline criteria, before the next family starts | `--only-family <family>` on the sample | Every required positive of that family is Confirmed and none of its controls is a finding |
| **Branch acceptance** | Last step of branches 1, 2 and 3, on the commit submitted for review | Full scan, no `--only-family`, `--entry` or `--route` | Every required positive of this branch and of everything below it is Confirmed, and no control is a finding |
| **Lane acceptance** | Last step of branch 4 | Full scan, same rule | All 30 required positives of the lane and of PR #39 are Confirmed, no control of any branch is a finding, and the closing table of the README's 21 entries is recorded |

- Provider, model and limits are those of AGENTS.md's standing live check: `--judge openai
  --judge-model gpt-6-luna`, the default judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`.
  Pass only that provider's key to the scanner process. No fallback provider or model.
- A missed positive or a control reported as a finding is a failed criterion. Find the first
  failing stage (evidence missing, evidence wrong, question wording, policy gate), fix it with a
  fixture case that reproduces it, and rerun. A fix never names the sample and never relabels a
  row.
- A fix that changes a family's request composition takes a new protocol identifier for that
  family before the next run.
- Each run is logged in the run log and in
  [symfony-results.md](../evaluation/symfony-results.md): run ID, scanner commit, scope, request
  count, input tokens, and the status of each row in scope.
- The bound is 8 judged runs per branch, or two consecutive full runs with no row changing
  status (§5 OQ-1). Reaching it with a criterion unmet is a halt, reported with each open row and
  its first failing stage.
- A judged run of another sample, provider or model needs the owner's word.

### 4.2 Unattended operation

Each branch is implemented by one unattended session. The owner is not available during the run.
These rules replace "ask the owner" wherever the lane or a branch specification says it.

- **No questions.** Every owner decision is in §5. Do not wait for confirmation of anything this
  contract or the branch specification already decides.
- **The specification is the instruction.** Implement the decision tables and case tables as
  written. Where a table is silent or two readings are possible, take the narrower one (record
  less, claim less), write the reading and its reason in the run log under "Deviations", and
  continue. Do not add a rule, a contract name or a list entry that no table contains.
- **One slice at a time.** For each slice: write its fixtures and failing tests, see them fail,
  implement, see them pass, run the package tests, commit on the branch. Do not start the next
  slice with the current one red.
- **Check your own claims.** Before marking a criterion met, run its command and paste the
  output into the run log. A criterion with no recorded output is not met.
- **Blocked item protocol.** When a halt condition of this section or of the branch applies:
  1. Stop work on the blocked item only. Do not work around it, and do not weaken, delete,
     skip or relabel a test, a case, a key row or a criterion to get past it.
  2. Write it in the run log under "Blocked": what blocked, the evidence, the exact decision
     needed, and which criteria depend on it.
  3. Finish every slice and criterion that does not depend on the blocked item.
  4. Commit and push. Update the draft PR body with a "Blocked" section at the top.
  5. End the session with a report that lists each criterion as met, blocked or not reached.
- **Recoverable failures are not halts.** A failing test, a build error, a rebase conflict in
  your own files, a transient provider error or a tool that needs a retry is ordinary work. Fix
  it and continue.
- **Session end.** The last actions are always: run the gate, run the Verifier Agent, update the
  run log and the PR body, push. Leave the worktree clean on the branch being delivered.

A halt condition starts the blocked item protocol of §4.2. The halt conditions are:

1. An existing row of `scan/cli/testdata/architecture-baseline.json`, a DVWA keyed outcome or one
   of the 14 Symfony positives and their controls from PR #39 changes.
2. Registering a family or contract changes the selected component digest of any existing
   request.
3. A required positive cannot reach a witnessed candidate without a rule that names the sample,
   or a row looks wrong on source review. Bring the source evidence. Do not relabel the row.
4. A lower-branch fact of §2.3 needs a different shape (§2.4).
5. The same test fails five iterations in a row with no new diagnosis between them.
6. The stack shape needs to change, or `gh stack view --json` shows a chain or PR base that does
   not match §0.
7. The judged-run bound is reached with a judged criterion unmet (§4.1).
8. A paid call would be needed outside §4.1: another sample, provider or model.

## 5. Owner decisions

Every open question was answered by the owner on 2026-11-22. None is open. An implementation
session does not ask them again.

| ID | Question | Decision |
|---|---|---|
| OQ-1 | Paid judged runs | Required at every checkpoint (§4.1). OpenAI `gpt-6-luna`. A branch stops judged iteration at 8 judged runs, or at two consecutive full runs with no row changing status |
| OQ-2 | Configuration scanning in Code Scan | In scope, bounded: allow-listed framework and deployment files with closed check lists (branch 4) |
| OQ-3 | Defects in source that the README does not list | In scope: weak password hashing (branch 3), disabled CSRF protection and the session cookie flags (branch 4). Out of scope: committed secrets, left to the roadmap's secret-scanning item |
| OQ-4 | README entry 8 | Accepted as not present in source at the pin. Recorded with its evidence. Not required. The sample is not changed |
| OQ-5 | Authorization scope | State changes on a request-selected record, plus reads that return a `credential`, `login_identifier` or `role_source` field. Other reads make no record |
| OQ-6, OQ-7 | Families | Five new families with the names of §2.2, and one extension of `ssrf`. No claim is folded into an existing family's protocol. `account` stays one family with three kinds |
| OQ-8 | Behavior on a halt in an unattended run | Finish everything that does not depend on the blocked item, then stop with a report (§4.2). Never weaken a row or a criterion |
| OQ-9 | Draft pull requests | Each session opens its draft PR with `gh stack submit --auto` after its first green slice and keeps it current. Never marked ready. Never merged |

## 6. Cross-branch acceptance bar

The four landed PRs together satisfy every per-branch criterion, keep the §2 contract, and leave
the sample in the closing state of §3. Every PR needs human sign-off before merge.

## 7. Definition of done for the lane

- [ ] Each branch's definition of done is complete.
- [ ] `gh stack view --json` shows four PRs in the order of §0, each based on the branch below.
- [ ] Each upper branch's no-drift check passed while stacked and again after the lower PR landed.
- [ ] The judged sample scan on branch 4 reports every required positive of the lane and of PR #39
      and no control as a finding.
- [ ] [Implementation plan](../project/implementation-plan.md) and the
      [specification index](README.md) name the delivered state.

## 8. Change log

Accepted steering, review feedback and contract changes update the sections above in place. This
section records the audit trail.

### 2026-11-22 — Owner decisions, second pass, unattended execution

Source: the owner answered every open question, asked for a second review pass, and stated that
each branch will be implemented unattended by a less capable model than the one that wrote the
specifications.

- **§5.** Open questions became the owner-decision table. OQ-8 and OQ-9 are new.
- **§2.7 (new).** Statuses, the policy order, operation-centered completeness, the policy test
  and the wiring command. The first draft named families and facts but did not say how a judged
  status is reached, which a session could not have derived.
- **§4, §4.2 (new).** Unattended operation and the blocked item protocol. "Ask the owner"
  became a halt that finishes the unblocked work first.
- **Branch specifications.** Each gained a protocol table, a policy test criterion, a report
  criterion and corrections listed in its own change log.
- **Verification impact.** New offline policy and report tests in every branch.

### 2026-11-22 — Drafted

Written from the [independent review](../evaluation/symfony-results.md#independent-review) punch
list for PR #39, a source read of the sample at its pin, and the PHP adapter at `af5dbc1`. The
owner asked for three or four stacked specifications in one worktree, general PHP detection with
the sample as a measure only, user documentation under `docs/scan/detection-capabilities/`, and
analyzer design documents under `.zazz/architecture/`. The owner also asked that existing
analyzers be extended where a claim fits them (§2.6), and that the documentation be committed and
pushed on the first stacked branch as the first checkpoint (§0). No code changed.
