# 04 — Jev Assessment and Findings Review research

**Research reviewed 2026-10-19; concept-stage recommendations.** No live Jev tests have been run for
zazzles. The Project Owner has not yet signed up or obtained a key. This durable note preserves the
research independently of temporary chat attachments. Related:
[proposal](03-jev-design-proposal.md), [architecture](../architecture/README.md),
[implementation plan](implementation-plan.md).

## Answer to the capability question

Jev can evaluate supplied source snippets and return typed predictions about validation/sanitization.
The evidence supports investigating it as a semantic helper, especially for short, direct questions.
It does **not** establish that Jev can reliably certify arbitrary strings as safe across all contexts
or correctly reason through arbitrary application paths.

“Adequately validated” needs a declared requirement and sink. A string can satisfy a field format
while remaining inappropriate for HTML, SQL text, shell syntax, a path, or another user's resource.
Validation, context-specific encoding/sanitization, parameterization, and authorization are distinct.
[OWASP input-validation guidance](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
and [XSS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
provide the basis for corpus expectations rather than a universal “sanitized” flag.

## Published evidence and limits

| Source | What it reports | Interpretation for zazzles |
|---|---|---|
| [TypeSafe introduction](https://docs.typesafe.ai/introduction) | State and typed atomic questions, composed by application code | Appropriate interface for narrow semantic classification; no security-specific accuracy guarantee |
| [TypeSafe Jev 1.13 limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13) | Weaknesses with indirection, irrelevant context, adversarial text, option ordering, and generation | Keep evidence focused; test helper indirection, misleading comments, and question sensitivity |
| [jev-sec-bench](https://github.com/Gaurav-Gosain/jev-sec-bench) | On 200 synthetic vulnerable/secure pairs, vulnerable snippets ranked higher in 178 pairs (89%); absolute accuracy at 0.5 was 71.5%, precision 68.5%, recall 79.5% | Ranking and classification are different. Author disputes some labels; do not replace ground truth with that interpretation. No scan-specific sanitizer guarantee |
| [Security-prioritization experiment, section 13](https://github.com/san3ncrypt3d/jev-security-prioritization/blob/main/blog/jev-security-prioritization.md) | On 450 author-generated findings, 90% sanitization-field accuracy; hidden-helper sanitizer cases 51/62 correct; misleading TODO above working validation 7/11 correct | Directly relevant but synthetic and author-run. Sanitizer adequacy was a weak spot; short unfamiliar helper cases belong in our gate |
| [TypeSafe 1.14 announcement](https://typesafe.ai/blog/jev-1-14) | Oct 14 announcement of a new preview and a moving `jev-latest` alias | Older 1.13 measurements are not evidence for a newly selected model; pin and re-evaluate |
| [IRIS paper](https://arxiv.org/abs/2405.17238) and [authors' implementation](https://github.com/iris-sast/iris) | Combines LLM-assisted specifications/context review with static analysis on a Java benchmark | Supports researching a hybrid architecture; does not validate Jev, JS/TS, our resolver, or our quality bar |

For the probability/confidence distinction, see [TypeSafe confidence](https://docs.typesafe.ai/confidence).
These are source-reported results, not independently reproduced measurements. Synthetic snippets,
small per-family samples, noisy labels, model snapshots, and differing transport/question formats
limit transfer. Prompt-injection benchmark scores are not sanitizer-detection scores. Scan must measure
its own false-safe outcomes, false alarms, uncertainty, and cost.

## Questions suitable for an initial experiment

Go supplies the exact candidate value, validator body, call site, branch/result use, sink context,
library/version facts, and any gaps. It establishes supported flow/control facts itself.

| Question family | Example question shape | Proposed response |
|---|---|---|
| Validator intent | “Which constraint does `validator_body` attempt to enforce for `candidate_value`?” | Choice: known constraint categories plus `other`/`unknown` |
| Named format check | “Does the shown check reject strings outside the explicitly supplied format?” | Noul or Choice with an explicit unclear outcome |
| Context match | “Is the shown transformation intended for the named output context?” | Choice over supplied contexts and `unknown` |
| Partial protection | “Does the shown check address only part of the named dangerous input class?” | Noul, with precise criteria and counterexamples |
| Evidence adequacy | “Does the supplied helper definition state the behavior required by this check?” | Supporting prediction only; Go's missing-evidence markers remain authoritative |

These are candidate wording patterns, not validated prompts. Jev should not be asked to rediscover a
multi-file execution graph or infer absent business rules. Exact regex equivalence, arithmetic, or
universal proof over all strings belongs in deterministic analysis/testing where feasible.
Avoid asking “is this safe?” without a threat, sink, input domain, and evidence boundary.

## Chosen assessment and review approach

The architecture uses **Jev Assessment**, followed by **Findings Review** by the **LLM Findings
Reviewer**. Jev experiments focus on recognizing whether candidate strings are adequately validated
or sanitized for the named sink; the reviewer examines identified issues against source evidence.
These roles are the chosen direction. Effectiveness, model selection, evidence needs, and thresholds
remain experimental. The [architecture](../architecture/README.md#8-decision-assessment-and-findings-review)
owns the stage contracts, diagrams, independent-review procedure, and disagreement handling.

A capable LLM may help assess custom helpers, interacting checks, and unfamiliar framework behavior,
but its conclusion is another prediction, not ground truth. Human-labeled cases must expose incorrect
agreement as well as useful corrections. Review every identified issue and uncertain candidate; also
audit sampled Jev-protected cases to measure missed issues. Reviewing only raised issues cannot
measure Jev's false-negative rate.

Diagnostic deterministic-only, Jev-only, and LLM-only baselines measure each component's contribution;
they do not replace the planned full sequence. A provider adapter is required for the reviewer, with
provider/model and request budgets selected in its future spec.

## Proposed corpus and evaluation protocol

Prepare fixtures and expectations without a key first. Live evaluation starts only under a future
greenlit experiment spec after credentials and source policy are ready.

- Pair safe/vulnerable cases differing in one meaningful mitigation, plus intentional unknowns.
- Include absent checks, ignored return values, checks after use, bypass branches, reassigned values,
  helpers in another file, misleading function names/comments, and partial sanitizers.
- Cover regex anchors/flags/engine behavior, length/character constraints, decoding/normalization
  order, HTML text versus attribute/JavaScript contexts, SQL values versus identifiers, shell versus
  argument arrays, and path normalization versus containment. Specify supported cases precisely.
- Human-review labels using stated requirements and library behavior. Do not treat synthetic “secure”
  labels or another model as unquestionable ground truth.
- Keep tuning and held-out partitions, with helper/framework variants separated to reduce leakage.
- Freeze question text, model version, evidence schema, policy, dataset revision, and acceptance
  thresholds before the held-out run. Re-run the gate for model/question/adapter changes.
- Compare the full Jev Assessment → Findings Review sequence with diagnostic deterministic-only,
  Jev-only, and LLM-only baselines on the same evidence. Report per-family confusion matrices,
  false-safe rate, false alarms, uncertainty, calibration, repeated-call variation, reviewer agreement/
  disagreement, incorrect agreement, citation validity, review completeness, p50/p95 latency, and spend.
- Measure candidate discovery recall separately from classification quality: no model recovers a
  vulnerability absent from the candidate set it receives.
- For sampled missed/changed cases, inspect whether the error came from resolution, flow, missing
  context, classifier prediction, or policy. Improve the responsible layer rather than only prompts.

No numerical quality/spend thresholds are set by these notes. A future Deliverable Owner must agree
on acceptable false-safe/error rates and review load before interpreting results as success.

## Juice Shop as an acceptance reference

Use the [acceptance-target plan](implementation-plan.md#acceptance-targets) for Juice Shop's role,
revision/challenge mapping, safe counterparts, exclusions, and label-leakage controls. The
[orientation](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root) owns local clone lookup;
[worktree setup](../docs/worktree-setup.md#reference-application-checkout) owns reference-clone handling. Evaluate only the selected source-analysis cases when measuring model capability.

## Current integration direction

The [architecture](../architecture/README.md#current-provider-decision) owns the current provider decision.
This file preserves TypeSafe-specific research and setup only; it does not establish OpenAI behavior.
[Setup](../docs/openai-decisions-setup.md) owns credentials; no live OpenAI evaluation has been run.

## What can happen before a key exists

Jev signup and key setup are pending; no live scan evaluation has been run.

Research, architecture refinement, candidate question design, fixture mapping, and future spec authoring
can proceed without credentials. Offline implementation still requires its own greenlit spec.
Live latency, billing, model behavior, and threshold calibration remain unmeasured.

When ready, the Project Owner can use the [official console](https://console.typesafe.ai/) and
[quick start](https://docs.typesafe.ai/introduction/quickstart). Future tooling should read the key from
a local secret/environment source such as `TYPESAFE_API_KEY`, without committing or logging it. No key
needs to be pasted into chat. The LLM Findings Reviewer also needs provider credentials; configure these separately.

## Next definition work

Refine the first rule families, framework subset, required flow constructs, and human-labeled
acceptance criteria for Jev Assessment and Findings Review. The [spec sequence](implementation-plan.md#ordered-specification-backlog)
sets the implementation prerequisites; provider/model selection and empirical outcomes remain open,
while Jev and the LLM Findings Reviewer have fixed roles in the architecture.
