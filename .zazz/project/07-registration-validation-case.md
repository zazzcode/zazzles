# Registration validation: next graph and judging case

Historical contract/evidence below retains its original names. Current package, CLI and report
names are documented in the [implemented architecture](../architecture/README.md#naming-and-compatibility).

**Source review, 2026-10-31; target Juice Shop `v20.3.0`.** This is a concrete design/acceptance case
for the next scanner increment, not a finding already emitted by scan. No application was started,
HTTP request sent to the target, or additional model request made for this investigation.

## What the pinned target actually does

The local registration spelling is `POST /api/Users`. The source contains validation; the important
question is whether it is adequate and unavoidable before account creation.

| Source location in the target repository | Observed evidence |
|---|---|
| `server.ts:436–447` | An inline middleware checks presence of email, password and passwordRepeat before checking nonzero email/password lengths; it calls next() after the outer conditional |
| `server.ts:437` | Omitting passwordRepeat skips the entire validation block even if email/password are empty |
| `server.ts:438–441` | Length is tested before trimming; whitespace can pass the length check and then become empty |
| `server.ts:443–446` | The error response is not followed by return; next() is still called. Whether later processing persists requires framework/control-flow evidence |
| `server.ts:448–450` | Additional same-path middleware factories, including challenge verifiers |
| `server.ts:509–535` | finale-rest initialization plus a loop over autoModels generates CRUD endpoints; UserModel is associated with `/api/Users` |
| `models/user.ts:56–75` | Email setter and password hashing exist; no explicit nonempty/email-format validator is declared for those fields in this model definition |
| `routes/verify.ts:23–28` | Empty-input challenge observer checks the body, records the challenge, and calls next(); it does not reject invalid input |
| `test/api/user.test.ts:80–94` | The checked-in API test expects 201 for whitespace email/password without passwordRepeat; not executed during this review |
| `test/cypress/e2e/register.spec.ts:95–114` | The challenge test submits empty fields, but only conditionally logs success for 201; its assertion checks the challenge flag, not persisted creation |

Payload shapes to distinguish in a future controlled test:

- Empty email/password, passwordRepeat absent: outer condition false, no local nonempty check.
- All three fields present and empty: local error response executes, but next() still follows.
- All three fields present and whitespace: local length check passes before trim.
- Valid strings: expected ordinary registration, subject to remaining application requirements.
- Null, wrong JSON types and absent required fields: separate outcomes; do not infer these from the
  empty-string case or TypeScript annotations.

The existence of an adequate model/database constraint, applicable global middleware, or framework
error behavior could change the full result. The source review establishes local guard bypass and
ordering defects; it does not prove every candidate payload is persisted.

The [OWASP chapter](https://help.owasp-juice.shop/part2/improper-input-validation.html) distinguishes
Empty User Registration from Repetitive Registration (the repeat-password/DRY challenge). The
[Cornucopia mapping](https://cornucopia.owasp.org/news/20260302-cornucopia-juice-shop-challenge) is
benchmark context, not a substitute for checking this pinned revision's behavior. Challenge names,
solution comments and test labels MUST NOT be supplied to the judge as expected answers.

## Initial scanner gaps (before the two-case increment)

The offline command below found five same-path registration records (one GET and four POST), resolved
only the inline middleware body, and emitted zero candidate uses:

```bash
go run ./cmd/scan --strings --json --entry server.ts --route /api/Users <target-root>
```

That original result was a coverage gap, not evidence that registration is safe. Before checked mode, discovery only
models SQL `.query` and outbound HTTP candidate shapes. It did not resolve namespace factory
references such as `verify.emptyUserRegistration`, combine same-path middleware into an effective
chain, expand generated finale resources, or associate model constraints with an account-creation use.
The exact-path selector currently includes all methods; finding analysis must distinguish POST/GET.

The initial judge policy made any use with any gap policy-uncertain, even
when the model says insufficient. This was a conservative bootstrap policy, not a Luna
capability limit. Checked mode now uses claim-specific evidence roles and blockers; legacy candidates
retain the conservative policy. See the current implementation/results sections below.

## Structural increment before prompt tuning

| Work | Required evidence / behavior | Plan location |
|---|---|---|
| Effective route chains | Group method/path/receiver/mount context, preserve registration order, next(), early return, response and exception edges | Phases 3 and 5 |
| Namespace and concise factories | Resolve imported namespace members and arrow factories without assuming every member call is a wrapper | Phase 3 |
| Generated persistence endpoints | Versioned finale-rest model expands the supported resource/table loop; link generated create operation to UserModel and request payload | Phases 3 and 6 |
| Field constraints and transformations | Collect relevant model validators, setters, hooks, schema/database constraints, and transformation order | Phases 3, 5 and 6 |
| Control/value witnesses | Identify the same field's definitions and one feasible bypass to the sensitive operation; do not flatten all branches | Phases 5 and 6 |
| Typed evidence completeness | Tag gaps with affected claim/dependency and required missing facts; retain unrelated gaps as scan coverage | Phase 7 |
| Claim-specific judge and reporting | Named constraints, atomic questions, separate raw model answer and supported-finding eligibility | Phase 8 / minimal output |

The sensitive operation here is **account creation**, not necessarily raw SQL or injection. Ordinary
ORM parameter binding does not enforce a nonempty email/password requirement. Source/sink models
identify this operation and its semantics; the judge assesses custom validation code. No scanner rule
needs to hard-code each permissible validation regex or a Juice Shop path/helper name.

## Judge question and report contract

Declare the intended constraint, field, actual input shape, sensitive operation and relevant path.
For example, the experiment can ask:

> Given the supplied POST registration chain and model constraints, is a nonempty string requirement
> for email enforced before account creation on the path where passwordRepeat is absent?

Ask password validation, whitespace normalization order and runtime type constraints separately.
Supply the outer condition, branch facts, next()/return behavior, relevant helper/setter bodies,
framework persistence semantics, source hashes and explicit gaps. Do not ask only “is the route
validated?” or put the known challenge outcome in the instructions. Provider probabilities are not
proof of path feasibility.

A proposed report separates:

- **Observed local fact:** a specific guard is bypassed for an input shape.
- **Supported potential vulnerability:** a justified feasible path reaches account creation with a
  named constraint violated and no unresolved protective dependency on that path.
- **Unknown:** a missing framework/middleware/model fact could still block the path.
- **Runtime confirmed:** a controlled regression test verifies invalid input actually creates an
  account. This is separate evidence, not a status bestowed by the decision model.

A positive finding can be supported by one complete violating path; a claim of adequate protection
requires coverage of the relevant allowed paths or an established invariant. An unrelated missing
response decoder should not invalidate a pre-request destination finding, but an unknown registration
validator remains a blocker for this account-creation claim. Tests must establish this distinction
before replacing the current blanket gap policy.

## Acceptance before calling this case definitive

Use a small generic fixture for vulnerable, fixed and unknown variants, then the pinned target:
missing passwordRepeat, empty values, whitespace-before-normalization, correct early rejection,
model-level nonempty checks, ignored validator results, and an unresolved framework helper. Include a
fixed case where a custom helper enforces the constraint without relying on its name or regex shape.

The graph must reconstruct a source-backed route→middleware→branch→persistence witness. A protected
variant must not produce the vulnerable finding. An unknown variant must not become protected or
confirmed-vulnerable. A runtime test must assert rejection/no database row for fixed variants and
assert successful creation plus the persisted invalid field for a vulnerable case. Challenge flags
and HTTP response alone are insufficient evidence of persistence.

Then run a small capped Luna-only evaluation on the same labeled bundles. Measure discovery,
path validity and semantic judgment independently. A prompt change alone cannot produce a finding
for a candidate that never reaches the judge.

## Implemented increment and result

Checked mode now associates the declared POST registration requirement with its middleware chain,
imported concise factories, model/setter/hook context and supported generated resource mapping.
It emits 11 local branch/successor edges and separates required blockers from unrelated coverage.
After relevant helper selection, the final Luna run returned insufficient validation/protection and
supported_potential with no declared blocker. See [results](../evaluation/juice-shop/results.md).
The original offline zero-candidate observation above remains the before-state, not current checked
behavior. This result is advisory under declared models, not runtime confirmation of persisted data.
