# Unsafe deserialization analyzer (CWE-502)

- **Status** Proposal, drafted 2026-11-19, language coverage revised 2026-11-21. No code is written.
  Implementation starts on owner assignment.
- **Worktree and branch** `analyzer-unsafe-deserialization`, a sibling worktree cut from `stage`.
- **Baseline** The sample table below was measured at `stage` `58e94e7`. The worktree was cut at
  `e608c86`, after the repository moved to `scan/`, `fix/` and `probe/`. Step 1 of §9 re-records
  the baseline at the worktree's own base.
- **Prerequisite** None for Python, JS/TS or PHP fixtures. The PHP sample row needs
  [PHP Symfony support](php-symfony-support.md) slices S2 and S4 (service binding and Twig service
  globals), which are not merged at `e608c86`.
- **Delivery** One draft PR into `stage`.
- **Run log** `.zazz/ephemeral/unsafe-deserialization-run-log.md`

## 1. Capability

Add a `deserialization` family. It asks whether request-derived bytes reach the data operand of a
verified deserializer that builds objects or runs code chosen by the data. It uses a new claim kind
`deserialization_candidate`, protocol `deserialization-components-v1` and finding type
`unsafe-deserialization` (CWE-502), for Python, JavaScript and TypeScript, and PHP.

The scanner establishes four facts and the model judges only what is left:

1. **Which operation.** A verified deserializer call and its contract.
2. **What the format can do.** Run code by design, build objects of data-chosen classes, or build
   plain data only. This comes from the contract and the call's options, never from the model.
3. **Where the bytes come from.** The request, a stored field, another service, or the server.
4. **What stands in between.** A restricting option, an integrity check, or a class allow-list.

### Language coverage

Every supported language gets each of the four facts. JavaScript and TypeScript share one adapter
(`langjs`) and one set of contracts, and each has its own fixtures (D-15).

| | Python | JavaScript and TypeScript | PHP |
|---|---|---|---|
| Operations (D-2) | `pickle` family, PyYAML, `ruamel.yaml`, `jsonpickle` | `node-serialize`, `funcster`, js-yaml | `unserialize`, Symfony `Yaml::parse` |
| Option fact | PyYAML loader, `ruamel.yaml` `typ` (D-3) | js-yaml schema (D-5) | `allowed_classes`, `PARSE_OBJECT` (D-4) |
| Version fact | PyYAML, only when the loader is absent or `FullLoader` (D-3, D-17) | js-yaml (D-5) | None |
| Transfers | D-6 | D-6 | D-6 |
| Integrity control | D-7 | D-7 | D-7 |
| Type restriction | `Unpickler.find_class` override | None exists | `allowed_classes` class list |
| Request origins | Existing Python input facts (D-9) | Existing Node, Next.js, GraphQL and gRPC input facts, server context only (D-9, D-16) | Existing PHP input facts (D-9) |
| Positive sample | VulnPy, four sinks | None in any local sample (OQ-4) | vuln-symfony, one sink, after Symfony S2 and S4 |
| Acceptance | AC1, AC4, AC7 | AC3, AC4 | AC2, AC4 |

Until Symfony support merges, PHP and JS/TS are proven by fixtures only. JS/TS stays fixture-only
after that unless OQ-4 adds a sample case.

### Baseline today

Offline, scanner `58e94e7`, samples at their pins. No sample has a deserialization candidate.

| ID | Sample and location | Operation | Expectation |
|---|---|---|---|
| `VP-DESER-01` | VulnPy `src/vulnpy/trigger/deserialization.py:8` | `pickle.load` on a `BytesIO` of the request value | Positive |
| `VP-DESER-02` | VulnPy `…/deserialization.py:12` | `pickle.loads` | Positive |
| `VP-DESER-03` | VulnPy `…/deserialization.py:17` | `yaml.load(…, Loader=yaml.UnsafeLoader)` | Positive |
| `VP-DESER-04` | VulnPy `…/deserialization.py:23` | `yaml.load_all(…, Loader=yaml.UnsafeLoader)` | Positive |
| `SYM-DESER-01` | vuln-symfony `src/Services/UserPref.php:36` | `unserialize` of the `USER_PREF` cookie after `urldecode` and `base64_decode` (`:30`–`35`) | Positive, once Symfony entries exist |
| `VFA-DESER-01` | Vulnerable Flask App `vulnerable-flask-app.py:97` | `pickle.loads` of bytes from a raw socket | Review-expected. The bytes are not HTTP request input (OQ-2) |
| `TS-DESER-N01` | Vulnerable TypeScript app `src/server.ts:187` | `yaml.safeLoad`, js-yaml 3.10.0 | Control: not a finding. The sample's comment calls it vulnerable, but `safeLoad` builds plain data |
| `JS-DESER-N01` | Juice Shop `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90`, `server.ts:140` | `yaml.load` of file content, js-yaml 3.x | Control: not a finding. The content comes from a file, not the request |
| `JS-DESER-X01` | Juice Shop `routes/fileUpload.ts:114` | `yaml.load(data)` written inside a constant code string run by `vm.runInContext` | Excluded: the call is text, not syntax |
| `DRUPAL-DESER-01` | vuln-drupal `modules/custom/vulnerable_auth/src/Controller/AuthController.php:47` | `unserialize` of a method parameter | Deferred to [phase 9](architecture-phase-9-drupal.md) |

VulnPy mounts each trigger under 11 framework adapters: the published report has 139 entries on
`/vulnpy/deserialization/…` routes. The four sinks will therefore appear in roughly 30 contexts
each, as its two command sinks do today.

DVWA, Node.js Goof, vuln-nextjs, OopsSec Store, ThreatByte, vuln-demo-app and Python insecure app
have no deserializer call (searched 2026-11-21). No local sample calls `node-serialize`, `funcster`,
`jsonpickle`, `ruamel.yaml` or Symfony `Yaml::parse`.

## 2. Required reading

- [Code injection rules](../../docs/scan/analysis/code-injection.md) and the `code` family as the
  structural precedent: `scan/internal/analysis/interpreter_redirect.go`,
  `scan/internal/analysispacks/code_redirect.go`, `scan/internal/judge/code_redirect.go`, and the
  per-language adapters `scan/internal/langpy/code_redirect.go`,
  `scan/internal/langjs/code_redirect.go` with `code_libraries.go`, and
  `scan/internal/langphp/code_redirect.go`.
- [Component ownership](../architecture/analysis-packs.md#boundary-and-ownership) and the family
  registry in `scan/internal/analysispacks/families.go`.
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates) and
  [calibration pairs](../../docs/scan/analysis/calibration.md#regression-pairs).
- [Model-assisted evidence resolution](model-assisted-evidence-resolution.md) D-4 (stored origin)
  and D-7 (which records are sent).
- [VulnPy guide](../evaluation/vulnpy-detection-guide.md) and
  [recall inventory](../evaluation/recall-gap-inventory.md).
- Input facts each adapter already publishes: `scan/internal/analysispacks/python_inputs.go`,
  `node_inputs.go` and `php_inputs.go`.
- Version resolution. JS/TS has it: `scan/internal/langjs/package_manifest.go`, `package_lock.go`
  and `xss_versions.go`. Python has none today (D-17). PHP needs none.
- Existing transfers. Python models percent-decoding only (`scan/internal/langpy/decode.go`); it has
  no `base64`, stream or compression transfer. D-6 lists what each adapter must add.

## 3. Invariants

- Decoding is a transfer, never a control. `base64`, URL, hex and compression decoding, `.encode()`
  and stream wrappers keep the request origin.
- What a format can do is a contract fact. A model answer that contradicts it is rejected.
- The scanner makes no gadget-chain claim. It does not read `vendor/`, `node_modules/` or installed
  packages, and a finding never states that code execution was shown for an object-injection format.
- A version-dependent behavior needs a version read from a manifest or lockfile. An unknown version
  stays Review. The version of a type package (`@types/js-yaml`, `types-PyYAML`) is not the
  library's version.
- A comment or label in the target is not evidence.
- The three languages use one claim kind, one facts record, one question set and one policy. A
  language differs only in its contracts, option facts and transfers.
- Every existing family is unchanged. `TestArchitectureBaseline` changes only by new fixture rows.
  The recall floor in [`check.py`](../evaluation/recall-gap-inventory/check.py) holds, and no keyed
  control becomes a finding.
- Paid calls follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `scan/internal/analysis/deserialization.go`, `analysis.go`, `findings.go` | New, modified | `DeserializationFacts`, the claim kind and the finding type |
| `scan/internal/analysispacks/deserialization.go`, `families.go`, `contracts.go`, `questions.go`, catalog material | New, modified | Family registration, contracts, questions, protocol version |
| `scan/internal/judge/deserialization.go`, tests | New | Policy and consistency gates |
| `scan/internal/langpy/deserialization.go`, `decode.go`, `package_versions.go`, tests, `testdata/deserialization/` | New, modified | Python operations, loader facts, decode and stream transfers, exact-pin version reader (D-17) |
| `scan/internal/langjs/deserialization.go`, tests, `testdata/deserialization/` | New | JS and TS operations with schema and version facts; `.js` and `.ts` fixtures |
| `scan/internal/langphp/deserialization.go`, `values.go`, tests, `testdata/deserialization/` | New, modified | `unserialize` and its options, Symfony `Yaml::parse` flags, decode transfers, magic-method evidence |
| `scan/internal/guidelines`, `scan/internal/report` | Modified | Guidance per language, labels, SARIF rule for CWE-502 |
| `docs/scan/analysis/deserialization.md` (new), `docs/scan/analysis/README.md`, `docs/scan/detection-capabilities.md`, `docs/scan/detection-capabilities/unsafe-deserialization.md` (new), `docs/scan/python-support.md`, `docs/scan/php-support.md`, `README.md` | New, modified | Rules, supported subset per language, limits |
| `.zazz/evaluation/deserialization-results.md` (new), `recall-gap-inventory/cases.json`, the VulnPy and TypeScript app guides, `docs/samples/vulnpy/cases.json`, `.zazz/project/implementation-plan.md` | New, modified | Key rows, results, capability checklist |
| `scan/cli/testdata/architecture-baseline.json` | Modified | New fixture rows only |

Out of scope, all languages:

- XML external entities (deferred by the owner) and prototype pollution through `JSON.parse` and
  merge, which has its own family.
- Gadget-chain discovery and dependency advisories (Audit).
- Java, .NET and Ruby deserializers.
- Library mode. Scanning a deserializer's own source is the npm library scan (D-14).
- New input origins beyond D-9.
- Calls reached through a callable string or dynamic dispatch: `array_map('unserialize', …)`,
  `call_user_func('unserialize', …)`, `getattr(pickle, name)`, `require(name)` and dynamic
  `import()`. No adapter resolves these for any family today.

Out of scope, Python:

- Loads addressed by a file path: `joblib.load`, `pandas.read_pickle`, `numpy.load`, `torch.load`
  and `shelve.open`. They need a file-content origin model first. Their stream forms
  (`pandas.read_pickle(io.BytesIO(x))`) wait for the same work, so each library has one contract.
- `marshal`. It does not build objects of data-chosen classes, so it needs its own capability and
  contract.
- Framework configuration that selects a pickle serializer (Django `PickleSerializer` sessions,
  Celery `accept_content`). These are settings, not calls with a data operand.

Out of scope, JavaScript and TypeScript:

- Browser execution context (D-16).
- `serialize-to-js`, `cryo` and other small deserializers with no local sample. Add each as a
  contract row when a sample or owner request needs it.
- `serialize-javascript`. It has no deserializer; its output is run with `eval`, which the `code`
  family owns.

Out of scope, PHP:

- `phar://` metadata. It needs a file-content origin model first.
- Extension deserializers: `igbinary_unserialize`, `msgpack_unpack`, `yaml_parse`,
  `session_decode` and `wddx_deserialize`. Their behavior depends on installed extensions and
  `php.ini`, which the scanner does not read.
- `Symfony\Component\Yaml\Parser` instances and the Symfony Serializer component. The Serializer
  builds the type the code names, not a type the data names.

## 5. Decisions

- **D-1. A separate family.** `deserialization` is registered next to `code`, with its own facts,
  questions and policy, and reuses the operand-path record (`CommandPath`).
  **Why.** The operand is data, not source text, and the controls differ: a safe loader, a class
  allow-list and an integrity check have no meaning for `eval`.
  **Rejected.** A second claim kind inside `code`: its questions ask about code operands and its
  contracts say "interprets argument 0 as code".
- **D-2. Verified operations and what each can do.** Calls resolve through imports and aliases, as
  the code family's do (binding forms in D-15). Shadowed or reassigned bindings are excluded.

  | Contract | Language | Operations | Capability |
  |---|---|---|---|
  | `python-pickle-v1` | Python | `pickle.load`, `loads`, `Unpickler(…).load`; the same in `_pickle`, `cPickle`, `dill` and `cloudpickle` | `code_execution` |
  | `python-yaml-v1` | Python | PyYAML `load`, `load_all`, `unsafe_load`, `full_load` and their `_all` forms | By loader (D-3) |
  | `python-ruamel-yaml-v1` | Python | `ruamel.yaml.YAML(…).load` and `load_all` on an immutable local instance | By `typ` (D-3) |
  | `python-jsonpickle-v1` | Python | `jsonpickle.decode`, `jsonpickle.loads` | `code_execution` |
  | `node-serialize-v1` | JS/TS | `unserialize` from `node-serialize`; `funcster.deserialize` and `deepDeserialize` | `code_execution` |
  | `js-yaml-v1` | JS/TS | js-yaml `load`, `loadAll`; `safeLoad` and `safeLoadAll` only with an explicit unsafe schema | By version and schema (D-5) |
  | `php-unserialize-v1` | PHP | The built-in `unserialize` | `object_injection`, or `data_only` by option (D-4) |
  | `php-symfony-yaml-v1` | PHP | Static `Symfony\Component\Yaml\Yaml::parse`. `parseFile` takes a path and is excluded | `object_injection` with `PARSE_OBJECT`, else `data_only` (D-4) |

  Excluded as data-only operations, with no record:
  - Python: `json.loads`, `yaml.safe_load` and `safe_load_all`, `ast.literal_eval`.
  - JS/TS: `JSON.parse`, js-yaml `safeLoad` without a schema option, the `yaml` npm package's
    `parse`, `v8.deserialize`, `structuredClone`.
  - PHP: `json_decode`, `Yaml::parse` without `PARSE_OBJECT`.
- **D-3. Python YAML loader facts.** The `Loader` argument, keyword or second positional, decides
  the capability:
  - `SafeLoader`, `CSafeLoader`, `BaseLoader`, `CBaseLoader`: data only, no record.
  - `UnsafeLoader`, `CUnsafeLoader`, `Loader`, `CLoader`, and `unsafe_load`: `code_execution`.
  - `FullLoader`, `CFullLoader` and `full_load`: `restricted_types`, with the resolved PyYAML
    version as a fact when one is known.
  - No `Loader` argument, by resolved PyYAML version (D-17): before 5.1 the default is the unsafe
    loader, `code_execution`; from 5.1 and before 6.0 it is `FullLoader`, `restricted_types`; from
    6.0 the call raises and makes no record. An unknown version is `loader_unresolved`.
  - A loader passed as a variable, a parameter or a project-defined subclass:
    `loader_unresolved`, Review.
  - `ruamel.yaml`: `YAML(typ='unsafe')` is `code_execution`. `typ='safe'`, `'rt'`, `'base'` or no
    `typ` is data only, no record. A non-literal `typ`, or an instance that is a parameter, an
    attribute or reassigned, is `loader_unresolved`.
- **D-4. PHP options.**
  - `unserialize($d, ['allowed_classes' => false])` is `data_only` and makes no record. A literal
    class list (strings or `Foo::class`) is a class allow-list control. A missing, `true` or
    non-literal option is `object_injection`. The option is read from the second positional
    argument or the named argument `options:`, and through an immutable local or constant array.
  - `Yaml::parse($d, $flags)` is `object_injection` when the literal flags include
    `Yaml::PARSE_OBJECT`, alone or in a `|` expression. Literal flags without it make no record.
    Non-literal flags are `loader_unresolved`.
  - PHP has no version fact: `allowed_classes` exists in every PHP version the adapter parses.
- **D-5. js-yaml facts.** Before 4.0.0, `load` and `loadAll` use the full schema, which includes
  `!!js/function`: `code_execution`. From 4.0.0, `load` is safe by default: no record. An explicit
  `schema` option overrides either way:
  - `DEFAULT_FULL_SCHEMA` (3.x), or a 4.x schema extended with `js-yaml-js-types`:
    `code_execution`, on `load` and on `safeLoad`.
  - `DEFAULT_SAFE_SCHEMA`, `DEFAULT_SCHEMA` (4.x), `CORE_SCHEMA`, `JSON_SCHEMA`,
    `FAILSAFE_SCHEMA`: no record.
  - A schema passed as a variable or parameter: `loader_unresolved`, Review.

  The version comes from the nearest manifest and lockfile entry for `js-yaml` itself. An unknown
  version, a range with no lockfile, or two resolved versions for the calling package is Review.
- **D-6. Transfers.** These keep the operand's origin and add a transfer step. Each adapter adds the
  ones it lacks; a transfer already modeled for another family is reused, not redefined.

  | Language | Transfers |
  |---|---|
  | Python | `.encode()`, `.decode()`, `bytes()`, `bytearray()`, `str()`; `io.BytesIO` and `io.StringIO` construction; `.read()`, `.getvalue()` and `.stream` on a request body or upload; `base64.b64decode`, `urlsafe_b64decode`, `b32decode`, `b16decode`; `binascii.unhexlify`, `a2b_base64`; `bytes.fromhex`; `codecs.decode`; `zlib.decompress`, `gzip.decompress`, `bz2.decompress`, `lzma.decompress`; the existing `urllib.parse` decoders |
  | JS/TS | `Buffer.from(x)`, `Buffer.from(x, 'base64' \| 'hex' \| …)`, `.toString()`, `String(x)`, `atob`, `decodeURIComponent`, `decodeURI`, `unescape`, `zlib.inflateSync`, `gunzipSync`, `unzipSync`, `brotliDecompressSync`, TypeScript `as`, `!` and `<T>` casts |
  | PHP | `base64_decode`, `urldecode`, `rawurldecode`, `hex2bin`, `gzuncompress`, `gzinflate`, `gzdecode`, `stripslashes`, `trim`, `(string)` cast |

  A stream operand (`pickle.load(stream)`, `yaml.load(stream)`) is the stream's content. An
  operand that is one field of a parsed request body keeps the body's origin.
- **D-7. Controls.** Each is recorded on the path with its contract. None is Protected alone.
  - **Integrity check.** A keyed verification that dominates the sink on the same bytes. The
    contract states that an unkeyed hash is not integrity. The model judges adequacy.

    | Language | Recognized verifications |
    |---|---|
    | Python | `hmac.compare_digest` over an `hmac` digest; `itsdangerous` `Signer.unsign` and `Serializer.loads`; `django.core.signing.loads` and `Signer.unsign` |
    | JS/TS | `crypto.timingSafeEqual` over a `crypto.createHmac(…).digest()`; `jsonwebtoken.verify`; a value read from `cookie-parser`'s `req.signedCookies` |
    | PHP | `hash_equals` over `hash_hmac`; `sodium_crypto_auth_verify` |

    An HMAC compared with `==` or `===` is recorded as the same control with the comparison
    operator as a fact; the model judges it.
  - **Class allow-list.** PHP `allowed_classes` list; a Python `Unpickler` subclass overriding
    `find_class`. JS/TS has none: `node-serialize` and `funcster` take no restricting option, so
    `type_restriction` is always `none` for `node-serialize-v1`. The model judges adequacy.
  - **Format checks** by regular expression or prefix are recorded as guards and are model-judged.
- **D-8. Questions** (`deserialization-components-v1`):
  - `deserialization_exposure`: `vulnerable`, `protected`, `not_applicable`, `unknown`.
  - `integrity_control`: `none`, `verified_before_decode`, `present_inadequate`, `unknown`.
  - `type_restriction`: `none`, `adequate`, `inadequate`, `unknown`.
  - `protection_coverage`: `complete`, `incomplete`, `unknown`.
- **D-9. Origins.** Request origins (query, body, cookie, header, upload content, path) make a raw
  path. The family consumes the input facts each adapter already publishes and adds no source:
  - Python: Flask, RESTX and FastAPI sources, and the framework adapters VulnPy mounts.
  - JS/TS: Node HTTP, Express and the other modeled server frameworks, Next.js route handlers,
    server actions and `getServerSideProps`, GraphQL resolver arguments and gRPC messages.
  - PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` content, the modeled `$_SERVER`
    keys and `php://input`. `$_SESSION` stays a storage container. Symfony `Request` sources
    arrive with [PHP Symfony support](php-symfony-support.md) and need no change here.

  A stored origin follows the existing stored-origin rules and questions. A server-generated or
  literal operand makes no record. Bytes from a raw socket or another service are an
  external-source witness kept separate from request input, as the remote response body is for
  Python insecure app's XSS.
- **D-10. Policy.**
  - **Confirmed** needs a verified contract whose capability is `code_execution` or
    `object_injection`, a complete raw request-to-operand path, `vulnerable` with consistent
    answers, and no unresolved gap on that path.
  - **Protected** needs a control on every path and answers that call it adequate and complete.
  - **Contradictions.** `not_applicable` with a request path present; `protected` with no control;
    `vulnerable` when every path is unresolved. Each is kept for audit and changes nothing.
  - `loader_unresolved`, an unknown version, a `restricted_types` capability and a stored origin
    without a resolved writer stay Review.
- **D-11. The finding names its impact.** `code_execution` formats report "code execution by
  format design". `object_injection` formats report "object injection: effect depends on the
  classes available" and list the in-repository classes that declare `__wakeup`, `__unserialize`,
  `__destruct`, `__toString`, `__call`, `__get`, `__set` or `__invoke`, or implement
  `Serializable`, as evidence, bounded to 20. Both are CWE-502 findings.
  **Why.** The weakness is deserializing untrusted bytes into objects. Stating code execution for
  PHP would claim an exploit the scanner did not show; withholding the finding would hide a
  serious defect. See OQ-1.
- **D-12. Practice findings without a model.** An unsafe YAML loader where the safe one would do
  (PyYAML, `ruamel.yaml` `typ='unsafe'`, js-yaml full schema, Symfony `PARSE_OBJECT`), and any use
  of `node-serialize` or `funcster`, are poor practice whatever the origin, like the `notevil`
  rule. `pickle` and `unserialize` on non-request data make no practice finding: both are common
  for trusted internal data.
- **D-13. Reporting.** Records at one sink group under it, so VulnPy's adapter fan-out reads as
  four defects with their contexts.
- **D-14. Relation to the npm library RCE scan.** The container-root npm proposal treats
  deserialization as a vector label on code and pollution candidates and builds no deserialization
  analyzer for library mode. That stands. This family covers an application calling a
  deserializer whose source is not scanned (`node_modules`, `vendor`, the standard library), where
  only a contract can say what the call does. In library mode, `node-serialize`'s own `eval` is a
  code-family sink. Findings here carry the same `deserialization` vector label, so both reports
  use one vocabulary.
- **D-15. Binding forms per language.** A contract applies only when the callee resolves to the
  named library through one of these forms. Each form has a fixture.
  - Python: `import pickle`, `import pickle as p`, `from pickle import loads`,
    `from pickle import loads as l`, and a function-local import.
  - JavaScript: `require('x')` bound to a `const`, destructured `const { load } = require('x')`,
    and the inline `require('x').unserialize(…)`.
  - TypeScript: `import * as yaml from 'js-yaml'`, `import yaml from 'js-yaml'`,
    `import { load } from 'js-yaml'`, `import { load as parse } from 'js-yaml'`, and
    `import s = require('node-serialize')`. A result cast (`yaml.load(x) as T`) does not change
    the record.
  - PHP: the global function `unserialize` called unqualified or as `\unserialize`. A namespace
    that declares or imports its own `unserialize` function, and any `->unserialize()` or
    `::unserialize()` method call, is excluded. `Yaml` resolves through its `use` statement,
    including an alias.

  **Why.** JS and TS share one adapter, so a `.js`-only fixture set would leave the TypeScript
  import forms, which both TypeScript samples use, unproven.
- **D-16. Server execution context only.** A deserializer call in browser code (a client
  component, a browser bundle, an inline script) makes no record in this version, and the
  limitation is documented.
  **Why.** The request origins of D-9 are server inputs, and CWE-502 here means the server builds
  objects from client bytes. js-yaml's full schema on browser-controlled text is client-side code
  execution, which the `code` and XSS families describe with their own browser sources.
  **Rejected.** An `execution_context` field as in `CodeFacts`: it would add a browser question
  set and browser origins for a case no sample has.
- **D-17. Python version source.** PyYAML's version is read only as an exact pin: `==` in a
  `requirements*.txt`, or the locked entry in `poetry.lock`, `Pipfile.lock` or `uv.lock`, nearest
  to the calling file. A range (`PyYAML<7`, as VulnPy declares), `pyproject.toml` or `setup.py`
  alone, or no file is an unknown version.
  **Why.** D-3 needs the version only when the `Loader` is absent or `FullLoader`, and Python has
  no version reader today. Exact pins need no resolver.
  **Rejected.** Treating every loader-less call as `loader_unresolved`: a PyYAML 3.x project with
  a pinned version would stay Review when the library documents the default as unsafe.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md). Build the policy against a stub
judge before any live call. Halt and ask when an existing family's fixture digest changes, when a
contract's capability cannot be backed by the library's own documentation, or when a row needs a
new input origin.

Contract texts cite the library reference: the Python `pickle` warning, the PyYAML loader
documentation and its 5.1 and 6.0 release notes, the `ruamel.yaml` `typ` documentation, the
`jsonpickle` security warning, the PHP `unserialize` manual page, the Symfony Yaml flags reference,
the `node-serialize` and `funcster` READMEs, and the js-yaml 4 migration notes. Review each at
implementation and record the date. The version boundaries in D-3 and D-5 are written from memory
of those references: confirm each against the source before it enters a contract, and halt if one
differs.

## 7. Acceptance criteria

Each criterion is verified by the table-driven tests in the named package
(`go test ./scan/internal/<package> -run Deserialization`).

1. **AC1 (Python, `langpy`).**
   - Positive, each yields `deserialization_candidate` with the request source, the contract and
     `code_execution`: `pickle.loads(request.data)`; `pickle.load(io.BytesIO(x.encode()))`;
     `pickle.load(request.files['f'].stream)`; `pickle.Unpickler(io.BytesIO(x)).load()`; each
     D-15 Python binding form; `base64.b64decode` and `zlib.decompress` before the call;
     `yaml.load(x, Loader=yaml.UnsafeLoader)`; `yaml.load(x, yaml.Loader)` (positional);
     `yaml.unsafe_load(x)`; `YAML(typ='unsafe').load(x)`; `jsonpickle.decode(x)`; a FastAPI
     `UploadFile` body read into `pickle.loads`.
   - No record: `yaml.safe_load(x)`, `yaml.load(x, Loader=yaml.SafeLoader)`, `YAML().load(x)`,
     `YAML(typ='safe').load(x)`, `json.loads(x)`, a shadowed local named `pickle`.
   - Unresolved: a loader variable and a `typ` variable yield `loader_unresolved`.
   - Version: `yaml.load(x)` with `PyYAML==3.13` in `requirements.txt` is `code_execution`; with
     `PyYAML==5.4.1` is `restricted_types`; with `PyYAML==6.0.1` makes no record; with
     `PyYAML<7` or no manifest is `loader_unresolved` with the version gap.
2. **AC2 (PHP, `langphp`).**
   - Positive, each yields a candidate with `object_injection`: `unserialize($_COOKIE['p'])`;
     `unserialize(base64_decode(urldecode($_COOKIE['p'])))`; `\unserialize($_POST['d'])`;
     `unserialize(file_get_contents('php://input'))`;
     `unserialize($d, ['allowed_classes' => true])`;
     `unserialize($d, $opts)` with a non-literal `$opts`;
     `Yaml::parse($_POST['y'], Yaml::PARSE_OBJECT)`.
   - No record: `['allowed_classes' => false]`, positional and as `options:`; `json_decode`;
     `Yaml::parse($_POST['y'])`; `$obj->unserialize($_GET['d'])`; a namespaced project function
     named `unserialize`.
   - Control: a literal class list records the class allow-list control.
   - Evidence: fixture classes with `__destruct` and `__unserialize` appear in the gadget evidence;
     a class with neither does not.
3. **AC3 (JavaScript and TypeScript, `langjs`).** Every case below exists as a `.js` fixture with
   CommonJS bindings and as a `.ts` fixture with ES imports (D-15).
   - Positive, `code_execution`: `unserialize(req.body.x)` from `node-serialize`;
     `unserialize(Buffer.from(req.cookies.profile, 'base64').toString())`;
     `funcster.deepDeserialize(req.body.f)`; `yaml.load(req.body.y)` with js-yaml 3.x in the
     lockfile; `yaml.safeLoad(req.body.y, { schema: yaml.DEFAULT_FULL_SCHEMA })` with 3.x;
     one Next.js route handler reading `await request.text()` into `yaml.load` with 3.x.
   - No record: `yaml.load(…)` with js-yaml 4.x; `yaml.safeLoad(…)`;
     `yaml.load(x, { schema: yaml.JSON_SCHEMA })` with 3.x; `JSON.parse(…)`; `yaml.load` in a
     client component (D-16); `yaml.load` of `fs.readFileSync` content.
   - Review: a missing lockfile with a range in `package.json` yields the version gap; a schema
     variable yields `loader_unresolved`; only `@types/js-yaml` resolvable yields the version gap.
4. **AC4 (controls, all three packages).**
   - Python: a dominating `hmac.compare_digest` check over the same bytes makes the path `guarded`
     with its contract attached. An unkeyed `hashlib.sha256` comparison is recorded as a guard
     whose contract says it is not integrity. An `Unpickler` subclass overriding `find_class`
     records the class allow-list control.
   - JS/TS: a dominating `crypto.timingSafeEqual` over a `createHmac` digest of the same bytes
     makes the path `guarded`. A value from `req.signedCookies` carries the integrity control.
   - PHP: a dominating `hash_equals(hash_hmac(…), $sig)` over the same bytes makes the path
     `guarded`. An `md5($d) === $sum` comparison is recorded as a guard that is not integrity.
5. **AC5 (policy, `judge`).** With a stub judge: a raw path plus `vulnerable` is Confirmed;
   `not_applicable` with a request path is rejected; `protected` without a control is rejected; a
   guarded path plus adequate, complete answers is Protected; an unresolved loader stays Review
   whatever the answers. The table runs once per capability (`code_execution`,
   `object_injection`, `restricted_types`), with one Python, one JS/TS and one PHP record among
   its rows.
6. **AC6 (practice, per language).** A practice finding and not a vulnerability: a Python unsafe
   YAML loader on a literal string; js-yaml 3.x `load` on a literal; `require('node-serialize')`
   used on a constant; `Yaml::parse('…', Yaml::PARSE_OBJECT)`. No finding: `pickle.loads` of a
   constant; `unserialize` of a constant.
7. **AC7 (samples, offline).** VulnPy at its pin has witnessed candidates at
   `trigger/deserialization.py:8`, `:12`, `:17` and `:23`. `TS-DESER-N01` and `JS-DESER-N01` have no
   record. `VFA-DESER-01` has a candidate with an external-source witness, or the recorded
   limitation from OQ-2. DVWA, Node.js Goof and vuln-nextjs gain no deserialization record.
   `SYM-DESER-01` is keyed as blocked on Symfony support and is not counted against this
   deliverable. Pins are clean before and after.
8. **AC8 (isolation).** `TestArchitectureBaseline` passes with new fixture rows only. The recall
   floor holds. `--only-family deserialization` and `--skip-family deserialization` work.
9. **AC9 (live).** After the owner's word: one judged VulnPy scan with
   `--only-family deserialization`, and one of the TypeScript app. The planned request count is
   stated from the offline planner first. Expected: four VulnPy sinks Confirmed and no control a
   finding. Results go to `deserialization-results.md`; the README table changes only from
   `accuracy.py` output. PHP and JS/TS positives have no live evidence in this deliverable; the
   results file says so.
10. **AC10 (docs and gate).** `docs/scan/analysis/deserialization.md` states operations,
    capabilities, controls, exclusions and limits in one table per language. The
    [contributor gate](../../docs/contributing.md#verification) passes.

## 8. Test strategy

- Table-driven adapter tests per language over small synthetic fixtures. Each vulnerable case has
  a safe sibling (safe loader, restricting option, constant operand) and an unresolved sibling
  (loader variable, unknown version, shadowed import).
- JS/TS cases run as one table over paired `.js` and `.ts` fixtures, so a new case adds a row and
  both files.
- Transfers are asserted once per language on one sink. Every other sink shares the operand path,
  so per-sink transfer cases are omitted.
- Stub-judge policy pairs for AC5.
- A selection test proves the family's contracts pass `analysispacks.Select` and that no other
  family's component digest moves.
- Samples verify through `check.py`. No fixture copies sample source, and nothing tests the §4
  exclusions.

## 9. Execution sequence

1. Add the key rows with their current failing status. Record the offline baseline at the
   worktree's base.
2. **Red:** the AC1 `pickle.loads` fixture.
3. Facts, family registration, contracts and questions. Python operations and transfers (AC1).
4. Policy against the stub judge (AC5), then Python controls (AC4) and practice findings (AC6).
5. PHP `unserialize`, Symfony `Yaml::parse`, transfers and controls (AC2, AC4).
6. JS/TS operations with schema and version facts, paired fixtures and controls (AC3, AC4).
7. Python version reader and the loader-less PyYAML cases (D-17, AC1 version rows).
8. Reporting, sink grouping and SARIF. Offline samples (AC7) and isolation (AC8).
9. Docs, gate, then the live runs on the owner's word (AC9, AC10). Draft PR.

Steps 5, 6 and 7 touch disjoint packages and may run in any order once step 4 passes.

```go
// DeserializationFacts records one verified deserializer call.
type DeserializationFacts struct {
	Operation  string        `json:"operation"`
	ContractID string        `json:"contract_id"`
	Capability string        `json:"capability"`       // code_execution | object_injection | restricted_types
	Option     string        `json:"option,omitempty"` // loader, typ, schema, flags or allowed_classes fact
	Version    string        `json:"version,omitempty"`
	Paths      []CommandPath `json:"paths"`
}
```

## 10. Definition of done

- [ ] OQ-1 to OQ-4 answered and logged.
- [ ] AC1–AC10 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] A fresh-context verifier reran two VulnPy rows, both controls, and one PHP and one TypeScript
      fixture.

## 11. Open questions

- **OQ-1. Object-injection status.** Should request-controlled PHP `unserialize` be a Confirmed
  CWE-502 finding with its impact stated as object injection (D-11), or a practice finding unless
  an in-repository gadget class exists? Recommendation: Confirmed, impact named.
- **OQ-2. Raw-socket bytes.** Model `socket.recv` as an external source so `VFA-DESER-01` gets a
  witness, or leave the row Review-expected with a recorded limit? Recommendation: leave it; one
  row does not justify a new origin.
- **OQ-3. Paid budget.** VulnPy will produce about 120 deserialization records before equivalent
  contexts share decisions. Is the standing live check enough, or does the owner want a cap?
- **OQ-4. A JS/TS positive sample.** No local sample has a request-reachable unsafe deserializer
  in JavaScript or TypeScript, so that language has fixture evidence only and no live check.
  Should the owner-maintained `vuln-nextjs` lab gain a `node-serialize` cookie case and a js-yaml
  3.x `load` case? Recommendation: yes, as a separate change to that repository; this deliverable
  does not wait for it.

## 12. Run log protocol

Use the plan's run-log rules. Record scanner SHA, sample pins and clean status, the contract
references with their review date, failing-first evidence, golden deltas, and live run identifiers
with planned and actual request counts.

## 13. Agent implementation prompt

> Work in the `analyzer-unsafe-deserialization` sibling worktree. Read AGENTS.md, the orientation
> contents, this spec and the code-family files it cites. Ask OQ-1 to OQ-4 first. Execute §9 from
> the failing AC1 fixture. Keep samples read-only and offline until the owner authorizes AC9. Stop
> on any §6 halt. Finish with a draft PR into `stage` listing AC1–AC10 evidence.
> Verifier: a fresh-context subagent runs the three adapter test suites and `TestArchitectureBaseline`,
> reruns `VP-DESER-02` and `VP-DESER-03` offline, confirms `TS-DESER-N01` has no record, runs one
> PHP and one TypeScript fixture case, and checks that no other family's digest moved. It reports
> PASS or FAIL in the run log.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Requested by the owner after the Symfony review found an unlisted `unserialize` of a cookie. Written
from a search of every local sample for deserializer calls and from the `code` family's structure.
No code changed.

### 2026-11-21 — Language coverage review

Requested by the owner: does the spec cover Python, JS/TS and PHP evenly. It named all three, but
the depth was uneven. Changes:

- Added the language coverage table (§1) and the one-family invariant (§3).
- **Python.** Added `ruamel.yaml`, `_pickle`, `jsonpickle.loads`, positional and C loaders, the
  loader-less PyYAML version table, and a version source (D-17): the draft required a PyYAML
  version but Python has no version reader. Listed the transfers Python lacks today (D-6).
- **JS/TS.** Added TypeScript binding forms and paired `.js`/`.ts` fixtures (D-15), the js-yaml
  schema names and the `safeLoad` unsafe-schema case (D-5), `funcster.deserialize`, the
  type-package version rule, server-only execution context (D-16), JS/TS integrity controls and
  an AC4 case. Recorded that no sample has a JS/TS positive (OQ-4).
- **PHP.** Added `allowed_classes` argument forms, Symfony `Yaml::parse` with `PARSE_OBJECT`,
  binding rules for the built-in, PHP transfers and integrity control, `__unserialize` and
  further magic methods in the gadget evidence, and an AC4 case.
- Split out-of-scope items by language and added dynamic-dispatch calls.
- Corrected paths for the `scan/` repository layout, the worktree name and the baseline note.
  Symfony support is still unmerged, so `SYM-DESER-01` stays blocked.

No code changed.
