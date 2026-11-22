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
  own session, in dependency order.
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

The stack shape is fixed before implementation. A session that needs to add, remove, split or
merge a branch stops and asks the owner, then updates this document and its change log.

### Branches

| Order | Branch | Specification | Delivers | Base |
|---:|---|---|---|---|
| 1 | `symfony-more-analyzers-1` | [-1](symfony-more-analyzers-1.md) | Information exposure, mass assignment, the security-field census, and all four specifications | `stage` |
| 2 | `symfony-more-analyzers-2` | [-2](symfony-more-analyzers-2.md) | Entry access rules and the authorization family, including address-based guards | Branch 1 |
| 3 | `symfony-more-analyzers-3` | [-3](symfony-more-analyzers-3.md) | Account enumeration, recovery-secret delivery, weak password hashing, the mailer sink | Branch 2 |
| 4 | `symfony-more-analyzers-4` | [-4](symfony-more-analyzers-4.md) | Framework and deployment configuration, SSRF through a shell URL client, whole-sample acceptance, closing documentation | Branch 3 |

All four branches live in this one worktree. No branch gets its own worktree.

### Lane setup (first session only)

The worktree starts on branch `symfony-more-analyzers` at the baseline, with the specifications
uncommitted. The first session renames that branch and starts the stack:

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
| 4 | `configuration` | `configuration_candidate` | `insecure-configuration` | 548, 352, 1004, 732, 269, 489 |
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

If an upper branch needs a different shape from a lower branch's fact, the session stops, the
owner approves, the lower branch is changed on the lower branch, the stack is rebased upstack, and
both specifications and this section are updated in place with a change-log entry.

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

- An implementation session that finds a claim fits an existing family better than this contract
  states brings the evidence to the owner. Folding a family into another changes a user-visible
  name and a protocol, so it follows the contract change rule of §2.4.
- A defect the work exposes in an existing analyzer is fixed on the branch that found it, with a
  fixture case, when the fix is inside that branch's scope. Otherwise it is recorded in the
  results document as a follow-up.

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
- **Paid calls.** Follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls) and the
  judged checkpoint protocol of §4.1. Offline criteria need no key.
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
- The bound is §5 OQ-1. Reaching it with a criterion unmet is a halt, reported with each open
  row and its first failing stage.
- A judged run of another sample, provider or model needs the owner's word.

Halt and ask the owner when:

1. An existing row of `scan/cli/testdata/architecture-baseline.json`, a DVWA keyed outcome or one
   of the 14 Symfony positives and their controls from PR #39 changes.
2. Registering a family or contract changes the selected component digest of any existing
   request.
3. A required positive cannot reach a witnessed candidate without a rule that names the sample,
   or a row looks wrong on source review. Bring the source evidence. Do not relabel the row.
4. A lower-branch fact of §2.3 needs a different shape (§2.4).
5. The same test fails three iterations in a row with no clear recovery.
6. The stack shape needs to change, or `gh stack view --json` shows a chain or PR base that does
   not match §0.
7. The judged-run bound of §5 OQ-1 is reached with a judged criterion unmet (§4.1).

## 5. Open questions

A default is applied to each so the specifications are complete. The owner confirms or overrules
them before the first implementation session writes code. The answer is recorded here and in the
run log.

- **OQ-1. Paid judged runs. Answered 2026-11-22:** required. Each branch validates its
  checkpoints with paid judged runs on the sample, and branch 4 confirms every capability on the
  whole sample (§4.1). Still to confirm with the owner at the first session: the numeric bound
  per branch. Default: OpenAI `gpt-6-luna` as in the Symfony contract's D-28, and a halt at 8
  judged runs per branch or two consecutive full runs with no row changing status.
- **OQ-2. Configuration scanning in Code Scan.** Default: in scope for branch 4 as a bounded
  `configuration` family over allow-listed files, because README entries 18 and 21 cannot close
  without it. The alternative is to record both as outside Code Scan and remove the deployment
  slice from branch 4.
- **OQ-3. Unlisted defects.** Default: weak password hashing (branch 3), disabled CSRF protection
  and the script-readable session cookie (branch 4) are in scope. Committed secrets are out: the
  roadmap has a separate secret-scanning item with its own placeholder and test-data rules.
- **OQ-4. README entry 8.** Default: accepted as not present in source at the pin, recorded with
  its evidence, and not required.
- **OQ-5. Authorization scope.** Default: one `authorization` family. A candidate is a state
  change on a request-selected record, or a read that returns a census field. Public reads of
  other fields make no record.
- **OQ-6. Family names.** Default: the five names of §2.2 as `--only-family` values.
- **OQ-7. New families or extensions.** Default: five new families and one extension, as §2.2
  and §2.6 state. The owner may prefer fewer families, for example enumeration as a check inside
  the validation family, at the cost of a protocol change to that family.

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

### 2026-11-22 — Drafted

Written from the [independent review](../evaluation/symfony-results.md#independent-review) punch
list for PR #39, a source read of the sample at its pin, and the PHP adapter at `af5dbc1`. The
owner asked for three or four stacked specifications in one worktree, general PHP detection with
the sample as a measure only, user documentation under `docs/scan/detection-capabilities/`, and
analyzer design documents under `.zazz/architecture/`. The owner also asked that existing
analyzers be extended where a claim fits them (§2.6), and that the documentation be committed and
pushed on the first stacked branch as the first checkpoint (§0). No code changed.
