# Unsafe deserialization analyzer (CWE-502)

- **Status** Scanner implementation and offline verification in the feature worktree.
  [Verification results](../evaluation/deserialization-results.md) record the open lab and live checks.
- **Worktree and branch** `analyzer-unsafe-deserialization`, a sibling worktree cut from `stage`.
- **Baseline** The sample table below was measured at `stage` `58e94e7`. The worktree was cut at
  `e608c86`, after the repository moved to `scan/`, `fix/` and `probe/`. Step 1 of §9 re-records
  the baseline at the worktree's own base.
- **Prerequisite** None. The one PHP sample row needs
  [PHP Symfony support](php-symfony-support.md), which is not merged at `e608c86`; that row is
  keyed as blocked and is not part of this deliverable.
- **Delivery** Two draft PRs: this repository into `stage`, and the lab scenarios into
  `zazzcode/vuln-nextjs` `main` (D-21).
- **Paid runs** Authorized by the owner on 2026-11-21 within the limits of D-20.
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

Every supported language gets each of the four facts, its own acceptance criterion and its own
test. JavaScript and TypeScript share one adapter (`langjs`) and one set of contracts, and each has
its own fixtures (D-15).

| | Python | JavaScript and TypeScript | PHP |
|---|---|---|---|
| Operations (D-2) | `pickle` family, PyYAML, `jsonpickle` | `node-serialize`, `funcster`, js-yaml | `unserialize`, Symfony `Yaml::parse` |
| Option fact | PyYAML loader (D-3) | js-yaml schema (D-5) | `allowed_classes`, `PARSE_OBJECT` (D-4) |
| Version fact | PyYAML, only when the loader is absent (D-3, D-17) | js-yaml (D-5) | None |
| Transfers | D-6 | D-6 | D-6 |
| Controls | D-7 | D-7 | D-7 |
| Request origins | Existing Python input facts (D-9) | Existing Node, Next.js, GraphQL and gRPC input facts, server context only (D-9, D-16) | Existing PHP input facts (D-9) |
| Adapter acceptance | AC1 | AC2 | AC3 |
| Offline sample | VulnPy, four sinks (AC7) | vuln-nextjs lab, two scenarios (D-21, AC7) | None until Symfony support merges |
| Live evidence | VulnPy and the Python fixture app (AC9) | The lab and the JS and TS fixture apps (AC9) | The PHP fixture app (AC9) |

### Baseline today

Offline, scanner `58e94e7`, samples at their pins. No sample has a deserialization candidate.

| ID | Sample and location | Operation | Expectation |
|---|---|---|---|
| `VP-DESER-01` | VulnPy `src/vulnpy/trigger/deserialization.py:8` | `pickle.load` on a `BytesIO` of the request value | Positive |
| `VP-DESER-02` | VulnPy `…/deserialization.py:12` | `pickle.loads` | Positive |
| `VP-DESER-03` | VulnPy `…/deserialization.py:17` | `yaml.load(…, Loader=yaml.UnsafeLoader)` | Positive |
| `VP-DESER-04` | VulnPy `…/deserialization.py:23` | `yaml.load_all(…, Loader=yaml.UnsafeLoader)` | Positive |
| `VFA-DESER-01` | Vulnerable Flask App `vulnerable-flask-app.py:97` | `pickle.loads` of bytes from `socket.recv` | No record. The bytes are not request input and no source models them (D-9) |
| `TS-DESER-N01` | Vulnerable TypeScript app `src/server.ts:187` | `yaml.safeLoad`, js-yaml 3.10.0 | Control: no record. The sample's comment calls it vulnerable, but `safeLoad` builds plain data |
| `JS-DESER-N01` | Juice Shop `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90`, `server.ts:140` | `yaml.load` of file content, js-yaml 3.x | Control: no record. The content comes from a file, not the request |
| `JS-DESER-X01` | Juice Shop `routes/fileUpload.ts:114` | `yaml.load(data)` written inside a constant code string run by `vm.runInContext` | Excluded: the call is text, not syntax |
| `SYM-DESER-01` | vuln-symfony `src/Services/UserPref.php:36` | `unserialize` of the `USER_PREF` cookie after `urldecode` and `base64_decode` | Blocked on Symfony entries. Not keyed here; AC3 case `PHP-02` covers the same shape |
| `DRUPAL-DESER-01` | vuln-drupal `modules/custom/vulnerable_auth/src/Controller/AuthController.php:47` | `unserialize` of a method parameter | Deferred to [phase 9](architecture-phase-9-drupal.md). Not keyed here |

VulnPy mounts each trigger under 11 framework adapters: the published report has 139 entries on
`/vulnpy/deserialization/…` routes. The four sinks will therefore appear in roughly 30 contexts
each, as its two command sinks do today.

Every local sample was searched on 2026-11-21. DVWA, Node.js Goof, vuln-nextjs, OopsSec Store,
ThreatByte, vuln-demo-app and Python insecure app have no deserializer call. No sample calls
`node-serialize`, `funcster`, `jsonpickle` or Symfony `Yaml::parse`. That is why the lab gains two
scenarios (D-21) and each language has a scannable fixture app (D-22).

## 2. Required reading

Read these before step 1 of §9. Nothing else is required.

- The upload family, which is the implementation template (D-18):
  `scan/internal/analysis/upload.go`,
  `scan/internal/analysispacks/upload.go`, `scan/internal/judge/upload.go`, and
  `uploadFinding` in `scan/internal/report/code_redirect.go`.
- The code family, which is the adapter template: `scan/internal/langpy/code_redirect.go`,
  `scan/internal/langjs/code_redirect.go` (`recordInterpreter`, `assembleInterpreterClaims`),
  `scan/internal/langjs/code_libraries.go` (library binding checks) and
  `scan/internal/langphp/code_redirect.go` (`codeUse`).
- Shared path rules: `FinishOperandPaths` in `scan/internal/parse/command_completeness.go` and
  `validateInterpreterPaths` in `scan/internal/analysis/interpreter_redirect.go`.
- Selection rules for operand families: `scan/internal/analysispacks/select.go`,
  `families.go` and `interpreterDescriptors` in `code_redirect.go`.
- [Component ownership](../architecture/analysis-packs.md#boundary-and-ownership),
  [claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes)
  and [calibration pairs](../../docs/scan/analysis/calibration.md#regression-pairs).
- JS version resolution: `packageVersion` in `scan/internal/langjs/package_manifest.go` and
  `exactVersion` and `versionLess` in `xss_versions.go`.
- Answer keys: [`check.py`](../evaluation/recall-gap-inventory/check.py),
  `docs/samples/evaluate-python.py`, and `scan/internal/langjs/nextjs_lab_test.go`.
- For D-21 only: the lab's own `AGENTS.md` and `docs/adding-scenarios.md` in its checkout.

## 3. Invariants

- Decoding is a transfer, never a control. `base64`, URL, hex and compression decoding, `.encode()`
  and stream wrappers keep the request origin.
- What a format can do is a contract fact. A model answer that contradicts it is rejected.
- The scanner makes no gadget-chain claim. It does not read `vendor/`, `node_modules/` or installed
  packages, and a finding never states that code execution was shown for an object-injection format.
- A version-dependent behavior needs an exact version read from a manifest or lockfile. An unknown
  version stays Review. The version of a type package (`@types/js-yaml`, `types-PyYAML`) is not the
  library's version.
- A comment or label in the target is not evidence.
- The three languages use one claim kind, one facts record, one question set and one policy. A
  language differs only in its contracts, option facts and transfers.
- Every existing family is unchanged: no existing component identifier, component digest, golden
  file or fixture expectation changes. `TestArchitectureBaseline` changes only by additions. The
  recall floor in `check.py` holds, and no keyed control becomes a finding.
- Samples other than the lab are read-only. The lab changes only as D-21 states.
- Credentials follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls): the key is
  loaded from the worktree's `.env`, never printed and never passed in arguments.

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `scan/internal/analysis/deserialization.go`, `analysis.go`, `interpreter_redirect.go`, tests | New, modified | `DeserializationFacts`, the `Deserialization` field on `CandidateUse`, `CodePaths` |
| `scan/internal/analysispacks/deserialization.go`, `upload.go`, `families.go`, `code_redirect.go`, `select.go`, `descriptors.go`, tests | New, modified | Contracts, questions, protocol, family registration, descriptors, input component identities |
| `scan/internal/judge/deserialization.go`, `policy.go`, `injection.go`, `components.go`, `client.go`, `bundle.go`, `budget.go`, tests | New, modified | Policy, question wiring, facts on the wire |
| `scan/internal/langpy/deserialization.go`, `package_versions.go`, `calls.go`, `code_redirect.go`, tests, `testdata/deserialization/` | New, modified | Python operations, loader facts, transfers, exact-pin version reader (D-17) |
| `scan/internal/langjs/deserialization.go`, `code_redirect.go`, `flow.go`, tests, `testdata/deserialization/` | New, modified | JS and TS operations, schema and version facts, claim assembly |
| `scan/internal/langphp/deserialization.go`, `calls.go`, tests, `testdata/deserialization/` | New, modified | `unserialize` options, `Yaml::parse` flags, transfers, magic-method evidence |
| `scan/internal/report/code_redirect.go`, `findings.go`, `finding_types.go`, `sarif.go`, `guidance.go`, `p5_explain.go`, tests | Modified | Finding, label, SARIF rule for CWE-502, guidance |
| `scan/internal/langjs/nextjs_lab_test.go`, `.zazz/evaluation/recall-gap-inventory/check.py` | Modified | Map `CWE-502` to `deserialization_candidate` |
| `scan/cli/main.go`, `scan/cli/architecture_baseline_test.go`, `scan/cli/testdata/architecture-baseline.json` | Modified | Family name in the flag help; baseline additions only |
| `docs/scan/analysis/deserialization.md` (new), `docs/scan/analysis/README.md`, `docs/scan/detection-capabilities.md`, `docs/scan/detection-capabilities/unsafe-deserialization.md` (new), `docs/scan/python-support.md`, `docs/scan/php-support.md`, `README.md` | New, modified | Rules, supported subset per language, limits |
| `.zazz/evaluation/deserialization-results.md` (new), `recall-gap-inventory/cases.json`, `docs/samples/vulnpy/cases.json`, `docs/samples/vulnerable-flask-app/cases.json`, the VulnPy and TypeScript app guides, `.zazz/project/implementation-plan.md` | New, modified | Key rows, results, capability checklist |
| This contract and its index | Modified | Scope, feature status, and verification links |
| Companion user and project documentation | New, modified | Compatibility capability page, CLI and results guides, Next.js support, project capability and sample indexes, analyzer architecture |
| In the lab checkout `<DEV_ROOT>/zazzcode/vuln-nextjs`: the files D-21 names | New, modified | Two scenarios with safe controls |

### Wiring checklist

`operandFamily` gains `"deserialization"`. Then every non-test site that names
`file_upload_candidate`, `.Upload`, `UploadProtocol` or `"upload"` gets a deserialization sibling
or a deliberate skip. Find them with:

```bash
grep -rn 'file_upload_candidate\|\.Upload\b\|UploadProtocol\|"upload"' --include='*.go' scan | grep -v _test.go
```

The sites that need a sibling, as of `e608c86`:

- `analysis/interpreter_redirect.go` `CodePaths`.
- `analysispacks/families.go`: `Families`, `familyProtocol`, `familyContract`, `contractIDs`.
- `analysispacks/code_redirect.go`: `interpreterQuestions`, `InterpreterChoices`, and the tail of
  `interpreterDescriptors` (D-18 names the input components and the missing browser entry).
- `analysispacks/descriptors.go`: `interpreterDescriptors("deserialization")`.
- `analysispacks/select.go`: the Node input case list and the PHP input switch.
- `judge/policy.go` `applyPolicy`, `judge/injection.go`, `judge/components.go`
  `interpreterComponentQuestions`, `judge/client.go`, `judge/bundle.go`, `judge/budget.go`.
- `report/findings.go`, `report/code_redirect.go`, `report/finding_types.go`, `report/sarif.go`,
  `report/guidance.go`, `report/p5_explain.go`.
- `cli/main.go`: add `deserialization` to the `--skip-family` help text.

The path-family sites (`analysispacks/path.go`, `parse/upload_claims.go`) need no sibling.

### Out of scope

All languages:

- XML external entities (deferred by the owner) and prototype pollution through `JSON.parse` and
  merge, which has its own family.
- Gadget-chain discovery and dependency advisories (Audit).
- Java, .NET and Ruby deserializers.
- Library mode. Scanning a deserializer's own source is the npm library scan (D-14).
- New input sources. A value no adapter models as a source makes no record (D-9).
- Model-free practice findings (D-12).
- Calls reached through a callable string or dynamic dispatch: `array_map('unserialize', …)`,
  `call_user_func('unserialize', …)`, `getattr(pickle, name)`, `require(name)` and dynamic
  `import()`. No adapter resolves these for any family today.

Python:

- Loads addressed by a file path, and their stream forms: `joblib.load`, `pandas.read_pickle`,
  `numpy.load`, `torch.load` and `shelve.open`. They need a file-content origin model first.
- `marshal`. It does not build objects of data-chosen classes.
- `ruamel.yaml`. Its documentation does not state what `typ='unsafe'` can build, so no contract
  can cite it.
- Framework settings that select a pickle serializer (Django `PickleSerializer` sessions, Celery
  `accept_content`). These are settings, not calls with a data operand.

JavaScript and TypeScript:

- Browser execution context (D-16).
- `serialize-to-js`, `cryo` and other deserializers with no sample.
- `serialize-javascript`. It has no deserializer; its output is run with `eval`, which the `code`
  family owns.
- `jsonwebtoken.verify` and `cookie-parser` signed cookies as integrity controls. They verify a
  different value from the one deserialized and need their own source modeling.

PHP:

- `phar://` metadata. It needs a file-content origin model first.
- Extension deserializers: `igbinary_unserialize`, `msgpack_unpack`, `yaml_parse`,
  `session_decode` and `wddx_deserialize`. Their behavior depends on installed extensions and
  `php.ini`, which the scanner does not read.
- `Symfony\Component\Yaml\Parser` instances, `Yaml::parseFile` and the Symfony Serializer
  component.

## 5. Decisions

- **D-1. A separate family.** `deserialization` is registered next to `code`, with its own facts,
  questions and policy, and reuses the operand-path record (`CommandPath`).
  **Why.** The operand is data, not source text, and the controls differ: a safe loader, a class
  allow-list and an integrity check have no meaning for `eval`.
  **Rejected.** A second claim kind inside `code`: its questions ask about code operands and its
  contracts say "interprets argument 0 as code".
- **D-2. Verified operations and what each can do.** A contract applies only when the callee
  resolves to the named library through a D-15 binding form. Shadowed or reassigned bindings are
  excluded. Python contract identifiers start with `python-` and PHP ones with `php-`, because
  `select.go` enforces those prefixes for operand families.

  | Contract | Language | Operations | Capability | Operand |
  |---|---|---|---|---|
  | `python-pickle-v1` | Python | `load`, `loads` and `Unpickler(…).load` of `pickle`, `_pickle`, `cPickle`, `dill` and `cloudpickle` | `code_execution` | Argument 0, or the `Unpickler` constructor's argument 0 |
  | `python-yaml-v1` | Python | PyYAML `load`, `load_all`, `unsafe_load`, `unsafe_load_all`, `full_load`, `full_load_all` | By loader (D-3) | Argument 0 or `stream=` |
  | `python-jsonpickle-v1` | Python | `jsonpickle.decode` | `code_execution` | Argument 0 or `string=` |
  | `node-serialize-v1` | JS/TS | `unserialize` of `node-serialize`; `deepDeserialize` of `funcster` | `code_execution` | Argument 0 |
  | `js-yaml-v1` | JS/TS | js-yaml `load`, `loadAll`; `safeLoad`, `safeLoadAll` only with an explicit `schema` option | By version and schema (D-5) | Argument 0 |
  | `php-unserialize-v1` | PHP | The built-in `unserialize` | `object_injection`, or no record by option (D-4) | Argument 0 |
  | `php-symfony-yaml-v1` | PHP | Static `Symfony\Component\Yaml\Yaml::parse` | `object_injection` with `PARSE_OBJECT`, else no record (D-4) | Argument 0 |

  `jsonpickle.decode` is `code_execution` whatever its `safe` argument: the library's documentation
  says `safe=True` does not make an untrusted string safe to load.

  Data-only operations make no record and need no code:
  - Python: `json.loads`, `yaml.safe_load`, `yaml.safe_load_all`, `ast.literal_eval`.
  - JS/TS: `JSON.parse`, js-yaml `safeLoad` and `safeLoadAll` without a `schema` option, the
    `yaml` npm package's `parse`, `v8.deserialize`, `structuredClone`.
  - PHP: `json_decode`.
- **D-3. PyYAML loader facts.** The loader is the `Loader=` keyword or the second positional
  argument. Loader names resolve through the `yaml` import (`yaml.SafeLoader`, or
  `from yaml import SafeLoader`).

  | Loader | Result |
  |---|---|
  | `SafeLoader`, `CSafeLoader`, `BaseLoader`, `CBaseLoader` | No record |
  | `UnsafeLoader`, `CUnsafeLoader`, `Loader`, `CLoader`; or the functions `unsafe_load`, `unsafe_load_all` | `code_execution` |
  | `FullLoader`, `CFullLoader`; or the functions `full_load`, `full_load_all` | `restricted_types` |
  | Anything else: a variable, a parameter, a project-defined class, a call | `unresolved` with option gap `loader_unresolved` |
  | No loader on `load` or `load_all`, PyYAML version below 5.1 | `code_execution` |
  | No loader, version from 5.1 and below 6.0 | `restricted_types` |
  | No loader, version 6.0 or later | No record: the call raises `TypeError` |
  | No loader, version unknown (D-17) | `unresolved` with option gap `version_unknown` |

  Sources, checked 2026-11-21: the PyYAML `CHANGES` file (6.0 "always require `Loader` arg",
  5.4 moves arbitrary Python tags to `UnsafeLoader`) and the PyYAML wiki page on the `yaml.load`
  deprecation (from 5.1 the default is `FullLoader`).
- **D-4. PHP options.**
  - `unserialize` reads its options from the second positional argument or the named argument
    `options:`. The value is an array literal, or an immutable local or constant initialized with
    one.

    | `allowed_classes` | Result |
    |---|---|
    | `false` | No record |
    | An array literal of strings or `Foo::class` | `object_injection`, with a `class_allow_list` control on every path (D-7) |
    | Missing, `true`, or the options value is not a literal | `object_injection`, no control |

  - `Yaml::parse` reads its flags from the second positional argument or `flags:`.

    | Flags | Result |
    |---|---|
    | Missing, or literal constants without `Yaml::PARSE_OBJECT` | No record |
    | Literal constants including `Yaml::PARSE_OBJECT`, alone or joined with a bitwise or | `object_injection` |
    | Not a literal | `unresolved` with option gap `loader_unresolved` |

  - PHP has no version fact.
- **D-5. js-yaml facts.** The version is `packageVersion(file, "js-yaml")`, accepted only when
  `exactVersion` parses it.

  | Call | Version | Result |
  |---|---|---|
  | `load`, `loadAll`, no `schema` option | Below 4.0.0 | `code_execution` |
  | `load`, `loadAll`, no `schema` option | 4.0.0 or later | No record |
  | Any, `schema: yaml.DEFAULT_FULL_SCHEMA` | Below 4.0.0 | `code_execution` |
  | Any, `schema:` one of `DEFAULT_SAFE_SCHEMA`, `CORE_SCHEMA`, `JSON_SCHEMA`, `FAILSAFE_SCHEMA` | Below 4.0.0 | No record |
  | Any, `schema:` one of `DEFAULT_SCHEMA`, `CORE_SCHEMA`, `JSON_SCHEMA`, `FAILSAFE_SCHEMA` | 4.0.0 or later | No record |
  | Any, any other `schema` value | Any known version | `unresolved`, option gap `loader_unresolved` |
  | `load`, `loadAll`, or any call with a `schema` option | Unknown | `unresolved`, option gap `version_unknown` |

  A schema extended with the `js-yaml-js-types` package falls in the "any other" row. Source,
  checked 2026-11-21: the js-yaml `CHANGELOG.md` entry for 4.0.0 (`safe*` functions removed,
  `load` safe by default, unsafe tags moved to `js-yaml-js-types`).
- **D-6. Transfers.** These keep the operand's origin. Each adapter first checks whether its flow
  already carries the value through the call for the code or command family, and adds only what
  is missing, in its own new file. An existing transfer is reused, never redefined.

  | Language | Transfers |
  |---|---|
  | Python | `.encode()`, `.decode()`, `.read()`, `.getvalue()`, `bytes()`, `str()`; `io.BytesIO` and `io.StringIO` construction; `base64.b64decode`, `urlsafe_b64decode`, `b32decode`, `b16decode`; `binascii.unhexlify`, `a2b_base64`; `bytes.fromhex`; `zlib.decompress`, `gzip.decompress`, `bz2.decompress`, `lzma.decompress`; the existing `urllib.parse` decoders |
  | JS/TS | `Buffer.from(x)` and `Buffer.from(x, encoding)`, `.toString()`, `String(x)`, `atob`, `decodeURIComponent`, `decodeURI`, `unescape`, `zlib.inflateSync`, `gunzipSync`, `unzipSync`, `brotliDecompressSync`, and TypeScript casts |
  | PHP | `base64_decode`, `urldecode`, `rawurldecode`, `hex2bin`, `gzuncompress`, `gzinflate`, `gzdecode`, `stripslashes`, `trim`, a `(string)` cast |

  A stream operand (`pickle.load(stream)`) is the stream's content. One field of a parsed request
  body keeps the body's origin.
- **D-7. Controls.** Path protection follows the shared rule in `FinishOperandPaths`: a path is
  `guarded` when a dominating or enclosing condition mentions one of its dependency names, `unknown`
  when a blocker touches it, else `raw`. Python and JS/TS collect guards as their code family
  does. PHP uses the `branch_precondition` and `branch_false_precondition` evidence in the flow's
  context whose text names an operand variable, as `langphp/upload.go` does.

  The family then classifies each recorded guard into `DeserializationFacts.Controls` by the
  calls in the guard's text, resolved through imports where the language has them. The first
  matching row wins.

  | Kind | Python | JS/TS | PHP |
  |---|---|---|---|
  | `integrity_check` | `hmac.compare_digest`, `hmac.new`, `hmac.digest`; `itsdangerous` `unsign` or `loads`; `django.core.signing` `loads` or `unsign` | `crypto.createHmac`, or `crypto.timingSafeEqual` | `hash_hmac`, `hash_equals`, `sodium_crypto_auth_verify` |
  | `unkeyed_hash` | Any `hashlib` call | `crypto.createHash` | `md5`, `sha1`, `hash`, `crc32` |
  | `format_check` | Every other guard | Every other guard | Every other guard |

  Two controls are not guards and are added to every path with the path set to `guarded`:
  - `class_allow_list`, PHP: the `allowed_classes` array literal (D-4). The control's context
    evidence is the options argument.
  - `class_allow_list`, Python: the callee is a class defined in the scanned project whose base
    resolves to `pickle.Unpickler` and which defines `find_class`. The control's context evidence
    is that method. A subclass without `find_class` is a plain `python-pickle-v1` operation.

  JS/TS has no class allow-list: `node-serialize` and `funcster` take no restricting option.

  The scanner never judges whether a control is adequate. The model does (D-8), and the policy
  accepts a "protected" answer only when a control of the matching kind is recorded (D-10).
- **D-8. Questions** (`deserialization-components-v1`), in this order. The names are unique across
  families because `questionChoices` resolves choices by name; `type_restriction` already belongs
  to the upload family and is not reused.

  | Question | Choices |
  |---|---|
  | `deserialization_exposure` | `vulnerable`, `protected`, `not_applicable`, `unknown` |
  | `integrity_control` | `none`, `verified_before_decode`, `present_inadequate`, `unknown` |
  | `class_restriction` | `none`, `adequate`, `inadequate`, `unknown` |
  | `protection_coverage` | `complete`, `incomplete`, `unknown` |

  Instructions, one sentence each, written in `analysispacks/deserialization.go`:
  - `deserialization_exposure`: do request-controlled bytes reach the data operand of the verified
    deserializer; `use.deserialization.capability` states what the format can do and is not to be
    re-judged.
  - `integrity_control`: is a keyed verification of the same bytes enforced before the call;
    `use.deserialization.controls` lists each recorded control by kind; an unkeyed hash, an
    encoding or a format check is not integrity.
  - `class_restriction`: does an allow-list limit the classes the data can name to ones with no
    dangerous behavior; a missing list is `none`.
  - `protection_coverage`: is the protection enforced on every path; missing flow is `unknown`.
- **D-9. Origins.** The family consumes the sources each adapter already publishes and adds none.
  - Python: Flask, RESTX and FastAPI sources, and the framework adapters VulnPy mounts.
  - JS/TS: Node HTTP, Express and the other modeled server frameworks, Next.js API routes, route
    handlers, server actions and `getServerSideProps`, GraphQL resolver arguments and gRPC
    messages.
  - PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` content, the modeled `$_SERVER`
    keys and `php://input`. `$_SESSION` stays a storage container.

  Rules, the same as the code family's:
  - An operand with no dependency (a literal, a file read, `socket.recv`) makes no record. That
    is why `VFA-DESER-01` has none.
  - A record is made when the operand has at least one dependency of any source kind.
  - Only a dependency whose source kind is `input_source` is a request origin. A record with no
    request-origin dependency (a stored value, a remote response body) gets the gap
    `deserialization_origin_unresolved` and stays Review.
  - A stored origin follows the adapter's existing stored-origin blockers unchanged.
- **D-10. Policy.** `applyDeserializationPolicy` in `judge/deserialization.go` starts from
  `needs_evidence` and `uncertain`, and applies these rules in order. The first that matches
  decides. Gap kinds are prefixed `deserialization_`.

  | # | Condition | Outcome |
  |---|---|---|
  | 1 | The assessment's question version is not `deserialization-components-v1` | `needs_evidence`, gap `protocol_missing` |
  | 2 | Facts, completeness, contract or paths missing; the contract differs from `use.APIModel.ID`; `Validate` fails; a required evidence role is empty | `needs_evidence`, gap `claim_missing`, `facts_invalid` or `evidence_missing` |
  | 3 | No dependency is a request origin (D-9) | `needs_evidence`, gap `origin_unresolved` |
  | 4 | An answer contradicts the facts: `not_applicable` while a `raw` request-origin path exists; `protected` while no path has a control; `verified_before_decode` while no `integrity_check` control is recorded; `adequate` while no `class_allow_list` control is recorded; `complete` while a path is `unknown` | `needs_evidence`, gap `answers_inconsistent` |
  | 5 | Capability is `unresolved` or `restricted_types` | `needs_evidence`, gap `capability_unresolved`, with the option gap in the detail |
  | 6 | A completeness blocker remains | `needs_evidence`, with the blockers |
  | 7 | Every path is `guarded`; exposure is `protected`; coverage is `complete`; and `integrity_control` is `verified_before_decode` or `class_restriction` is `adequate` | `protected_for_claim`, `sufficient` |
  | 8 | Exposure is `vulnerable`; at least one request-origin path is `raw`; `integrity_control` is `none` or `present_inadequate`; `class_restriction` is `none` or `inadequate` | `confirmed_vulnerability`, `insufficient` |
  | 9 | Anything else | `needs_evidence`, reason "The answers do not establish a complete vulnerable or protected path." |

  A guarded path is never Confirmed, whatever the model answers, as in the code family. Rule 8
  can therefore only fire for `code_execution` and `object_injection` records.
- **D-11. The finding names its impact.** The finding type is `unsafe-deserialization`, label
  "Unsafe deserialization", CWE-502. For `code_execution` the summary says "code execution by
  format design". For `object_injection` it says "object injection: effect depends on the classes
  available" and never says code execution.

  For `php-unserialize-v1` records the PHP adapter adds evidence under the completeness role
  `deserialization_magic_class`: the declaration line of each class in the scanned project that
  declares `__wakeup`, `__unserialize`, `__destruct`, `__toString`, `__call`, `__get`, `__set` or
  `__invoke`, or implements `Serializable`, sorted by file then line, at most 20. The role is not
  required. A request-controlled `unserialize` is Confirmed with or without such a class.
  **Why.** The weakness is deserializing untrusted bytes into objects. Stating code execution for
  PHP would claim an exploit the scanner did not show; withholding the finding would hide a
  serious defect.
- **D-12. No model-free practice findings.** A deserializer call with no dependency makes no
  record of any kind.
  **Why.** Practice observations exist only in the Next.js adapter today. Python and PHP have no
  channel for them, and building one is a separate deliverable.
  **Rejected.** The draft's practice rule for unsafe YAML loaders and `node-serialize` on
  constant input.
- **D-13. Reporting.** Records at one sink group through the existing `groupSinks` in
  `report/grouping.go`, with no change to it, so VulnPy's adapter fan-out reads as four defects
  with their contexts.
- **D-14. Relation to the npm library RCE scan.** The container-root npm proposal treats
  deserialization as a vector label on code and pollution candidates and builds no deserialization
  analyzer for library mode. That stands. This family covers an application calling a
  deserializer whose source is not scanned (`node_modules`, `vendor`, the standard library), where
  only a contract can say what the call does.
- **D-15. Binding forms per language.** Each form has a fixture case.
  - Python: `import pickle`, `import pickle as p`, `from pickle import loads`,
    `from pickle import loads as l`, and a function-local import.
  - JavaScript: `const s = require('x')`, `const { unserialize } = require('x')`, and the inline
    `require('x').unserialize(…)`.
  - TypeScript: `import * as yaml from 'js-yaml'`, `import yaml from 'js-yaml'`,
    `import { load } from 'js-yaml'`, `import { load as parse } from 'js-yaml'`, and
    `import s = require('node-serialize')`. A result cast (`yaml.load(x) as T`) changes nothing.
  - PHP: the global function called as `unserialize` or `\unserialize`. A call inside a namespace
    that declares or imports its own `unserialize` function, and any `->unserialize()` or
    `::unserialize()` method call, is excluded. `Yaml` resolves through the file's `use` map in
    `langphp/class_index.go`, including an alias, or its fully qualified name.

  **Why.** JS and TS share one adapter, so a `.js`-only fixture set would leave the TypeScript
  import forms, which both TypeScript samples use, unproven.
- **D-16. Server execution context only.** `Entries` is `entry.http`, `entry.graphql` and
  `entry.grpc`. A call in browser code makes no record: in `langjs` the family returns before
  recording when the flow is a client flow (`f.client != nil`).
  **Why.** The request origins of D-9 are server inputs, and CWE-502 here means the server builds
  objects from client bytes.
  **Rejected.** An execution-context field as in `CodeFacts`: it would add browser origins and a
  browser entry component for a case no sample has.
- **D-17. Python version source.** `langpy/package_versions.go` returns PyYAML's version only
  from an exact pin, looking in the calling file's directory and then each parent up to the scan
  root, and stopping at the first directory that has any of these files:
  - `requirements*.txt`: a line `PyYAML==X.Y[.Z]`, ignoring case, `-`/`_` differences, extras,
    environment markers and trailing comments.
  - `poetry.lock` or `uv.lock`: the `version = "…"` line of the `[[package]]` block whose `name`
    is `pyyaml`, ignoring case.

  Anything else is unknown: a range (`PyYAML<7`, as VulnPy declares), `>=`, `~=`, a
  `pyproject.toml` or `setup.py` alone, two different pins in that directory, or no file. Files
  are read with a 1 MiB limit and never followed through a symbolic link.
  **Why.** D-3 needs the version only when the loader is absent, and Python has no version
  reader today. Exact pins need no resolver.
- **D-18. A fourth operand family.** The family is built the way the upload family is.
  - Registration: `Name` `deserialization`, `Label` "Unsafe deserialization", `Kinds`
    `deserialization_candidate`, the four languages, `Entries` per D-16, `RequiresAPI`,
    `PythonHTTPOnly` and `PHPHTTPOnly` true, `Pack` `pack.deserialization`, `Claim`
    `claim.deserialization`, `Evidence` `evidence.deserialization`, `PolicyOwner`
    `internal/judge/deserialization.go`. The CLI name is `deserialization`.
  - Completeness: `ClaimKind` `deserialization`; required roles `input_source`, `sink_binding`,
    `invoked_callable`, `control_flow` and `deserialization_operand`.
  - Paths: operand slot `data`, validated by `validateInterpreterPaths(paths, "data", …)`.
  - Input components are family-specific copies, so no existing component changes:
    `source.node-input-deserialization-v1`, `source.python-input-deserialization-v1` and
    `source.php-input-deserialization-v1`. `select.go` selects them for this family.
    `phpInputComponent`'s own applicability list is not edited.
  - `interpreterDescriptors` returns before the browser entry component for this family, as it
    does for upload.
  - Contract reference: `https://cwe.mitre.org/data/definitions/502.html`. Each contract's
    semantics text states the operations, the capability, and that decoding and unkeyed hashes
    are not protection.
  **Why.** The upload family is the newest operand family and already solved every wiring step.
  **Rejected.** A standalone family like `command`: it would duplicate descriptor and selection
  code the operand families share.
- **D-19. Facts record.** §9 holds the Go skeleton. `Validate` rejects an empty operation or
  contract, a capability outside the four values, an option gap without capability `unresolved`
  or the reverse, a control kind outside the four kinds, a control context index out of range,
  and paths that fail `validateInterpreterPaths`.
- **D-20. Paid runs are authorized.** The owner authorized, on 2026-11-21, judged scans that
  confirm this implementation, without a further request, within these limits:
  - Provider and model: `--judge openai --judge-model gpt-6-luna` with `JUDGE_RPM=4500` and
    `JUDGE_TPM=1800000`. No other provider or model, and no fallback.
  - Every run uses `--only-family deserialization`, the default judge limit and `--trace-dir`.
  - Targets: VulnPy, the lab checkout on its scenario branch, and the three fixture apps of D-22.
  - Before each run the agent records the planned request count: the number of
    `deserialization_candidate` uses in that target's offline report.
  - Budget: 800 judged requests in total across all targets and reruns. A target is rerun only
    after a code change that addresses a recorded mismatch, at most twice.
  - No run starts before AC1–AC8 pass offline.
  - If the key is missing or the provider reports an account failure, the agent records that,
    skips AC9, and still opens the draft PRs with AC9 marked not run.
  **Why.** Offline tests prove the evidence and the policy. Only a judged run proves the
  questions and contracts lead the model to the expected answers.
- **D-21. Lab scenarios.** The owner allows new routes in the `zazzcode/vuln-nextjs` lab. The
  agent works in the existing checkout `<DEV_ROOT>/zazzcode/vuln-nextjs` on a new branch
  `deserialization-scenarios` cut from `main`, follows the lab's `AGENTS.md` and
  `docs/adding-scenarios.md` in full (catalog entry, documentation, unit and HTTP tests,
  regenerated ground truth, audit snapshot), and opens a draft PR into the lab's `main`. It does
  not merge it.

  | ID | Unsafe route | Safe control | Flaw |
  |---|---|---|---|
  | `DESER-001` | `pages/api/deserialization/unsafe/profile.js` | `pages/api/deserialization/safe/profile.js` | `node-serialize` `unserialize` of the base64-decoded `profile` cookie. The control parses the same decoded text with `JSON.parse` |
  | `DESER-002` | `pages/api/deserialization/unsafe/config.js` | `pages/api/deserialization/safe/config.js` | js-yaml `load` of the `yaml` body field. The control calls `safeLoad` on the same text |

  Both rows are `cwe` `CWE-502`, `scanner` `SAST`, `runtime` `server`. Dependencies are pinned
  exactly: `node-serialize` `0.0.4` and `js-yaml` `3.14.1`. Payloads use the lab's harmless
  markers only. If the lab's catalog test restricts ID prefixes, add `DESER-` there in the same
  change.

  In this repository, `labFamilies` in `nextjs_lab_test.go` and `LAB_FAMILIES` in `check.py` gain
  `CWE-502` mapped to `deserialization_candidate`. The lab's existing `SCA-001` row is also
  CWE-502 but has `scanner` `SCA`, which both readers already skip.

  The results file records the lab branch commit. Re-pinning the lab in the sample catalog waits
  for the owner to merge the lab PR and is not part of this deliverable.
  **Why.** No local sample has a request-reachable unsafe deserializer in JavaScript or
  TypeScript.
- **D-22. Fixture apps.** Each adapter's `testdata/deserialization/` directory is one scannable
  project: a Flask app for Python, an Express app in `js/` and the same app in `ts/` for
  `langjs`, and plain PHP files, one case per file, for PHP. Version cases live in subdirectories
  that carry their own manifest or lockfile. The adapter tests scan these directories, and AC9
  scans the same directories with a judge. Each case is marked in source by a comment holding
  only its case ID (`# PY-01`, `// JS-04`, `// PHP-02`), which tests use to find the line.
  **Why.** One set of files serves the offline tests and the live check, and gives PHP and
  TypeScript live evidence that no sample provides.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md). The agent works unattended and does
not stop to ask. Where a common rule says to halt and ask, apply the rule below instead, and write
what happened in the run log and the PR description.

1. **Another family moves.** If any existing test, golden file or component digest changes, the
   change that caused it is wrong. Revert it and reach the goal through family-specific code or
   a family-specific component copy. Never update another family's expectation.
2. **A listed case cannot pass without changing shared code.** If an AC case fails because an
   input source, guard shape or call form is not modeled for any family, do not extend the shared
   mechanism. Replace the case with the nearest shape the code family's own fixtures use, keep
   the case ID, and list the substitution under "Limits" in `docs/scan/analysis/deserialization.md`.
   At most three substitutions per language; a fourth means the adapter work is wrong and must be
   redone.
3. **A library fact differs.** D-3 and D-5 were checked on 2026-11-21. Contract text must not say
   more than those tables. Do not add an operation, option or version boundary that is not in §5.
4. **Scope.** Do not add a contract, question, source, flag or file outside §4. Do not edit a
   sample other than the lab.
5. **Order.** Build the policy against a stub judge before any live call. Format only changed Go
   files.
6. **Commits.** Commit after each step of §9 with the repository's bracketed scope labels. Verify
   path, branch and `git config user.name` first, as AGENTS.md requires.

## 7. Acceptance criteria

Every adapter criterion is a table-driven test over the fixture app of D-22. A row passes when the
record at the case's line matches every stated column: record or none, contract, capability,
option gap, and the protection of the request path. "None" means no `deserialization_candidate`
at that line.

### AC1 — Python

Test `TestDeserializationPython` in `scan/internal/langpy`:
`go test ./scan/internal/langpy -run TestDeserializationPython -count=1`.

| Case | Source shape | Contract | Capability | Path |
|---|---|---|---|---|
| `PY-01` | `pickle.loads(request.data)` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-02` | `pickle.load(io.BytesIO(request.form['p'].encode()))` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-03` | `pickle.Unpickler(io.BytesIO(request.data)).load()` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-04` | `pickle.loads(base64.b64decode(request.cookies.get('p')))` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-05` | `pickle.loads(zlib.decompress(request.data))` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-06` | `pickle.loads(request.files['f'].read())` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-07a`–`d` | `PY-01` through each other D-15 Python binding form | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-08a`–`c` | `loads(request.data)` of `_pickle`, `dill`, `cloudpickle` | `python-pickle-v1` | `code_execution` | `raw` |
| `PY-09` | `yaml.load(x, Loader=yaml.UnsafeLoader)` | `python-yaml-v1` | `code_execution` | `raw` |
| `PY-10` | `yaml.load(x, yaml.Loader)` | `python-yaml-v1` | `code_execution` | `raw` |
| `PY-11a`–`b` | `yaml.unsafe_load(x)`; `yaml.load_all(x, Loader=yaml.UnsafeLoader)` | `python-yaml-v1` | `code_execution` | `raw` |
| `PY-12` | `yaml.full_load(x)` | `python-yaml-v1` | `restricted_types` | `raw` |
| `PY-13` | `jsonpickle.decode(x)` | `python-jsonpickle-v1` | `code_execution` | `raw` |
| `PY-N1` | `yaml.safe_load(x)` | None | | |
| `PY-N2` | `yaml.load(x, Loader=yaml.SafeLoader)` | None | | |
| `PY-N3` | `json.loads(x)` | None | | |
| `PY-N4` | `pickle.loads(x)` where `pickle` is a local variable, not the module | None | | |
| `PY-N5` | `pickle.loads(b"…")` on a literal | None | | |
| `PY-U1` | `yaml.load(x, Loader=loader)`, `loader` a function parameter | `python-yaml-v1` | `unresolved`, `loader_unresolved` | `raw` |
| `PY-V1` | `yaml.load(x)`, `requirements.txt` has `PyYAML==3.13` | `python-yaml-v1` | `code_execution`, version `3.13` | `raw` |
| `PY-V2` | `yaml.load(x)`, `PyYAML==5.4.1` | `python-yaml-v1` | `restricted_types`, version `5.4.1` | `raw` |
| `PY-V3` | `yaml.load(x)`, `PyYAML==6.0.1` | None | | |
| `PY-V4` | `yaml.load(x)`, `PyYAML<7` | `python-yaml-v1` | `unresolved`, `version_unknown` | `raw` |
| `PY-V5` | `yaml.load(x)`, no manifest | `python-yaml-v1` | `unresolved`, `version_unknown` | `raw` |
| `PY-V6` | `yaml.load(x)`, `poetry.lock` has `pyyaml` `3.13` | `python-yaml-v1` | `code_execution`, version `3.13` | `raw` |
| `PY-C1` | `PY-01` after `if not hmac.compare_digest(hmac.new(KEY, data, 'sha256').hexdigest(), sig): abort(403)` | `python-pickle-v1` | `code_execution` | `guarded`, control `integrity_check` |
| `PY-C2` | `PY-01` after `if hashlib.sha256(data).hexdigest() != digest: abort(403)` | `python-pickle-v1` | `code_execution` | `guarded`, control `unkeyed_hash` |
| `PY-C3` | `Restricted(io.BytesIO(request.data)).load()`, `Restricted` subclasses `pickle.Unpickler` and defines `find_class` | `python-pickle-v1` | `code_execution` | `guarded`, control `class_allow_list` |
| `PY-C4` | `PY-01` after `if not data.startswith(b'\x80'): abort(400)` | `python-pickle-v1` | `code_execution` | `guarded`, control `format_check` |

Every record also has the request source as `input_source`, `sink_binding` evidence at the callee,
and a completeness record with `ClaimKind` `deserialization` and no blocker.

`TestPythonPackageVersion` in the same package covers D-17 alone: each accepted line form, each
rejected form, nearest-directory precedence and two conflicting pins.

### AC2 — JavaScript and TypeScript

Test `TestDeserializationJS` in `scan/internal/langjs`:
`go test ./scan/internal/langjs -run TestDeserializationJS -count=1`. The table runs every case
twice: against `js/` with CommonJS bindings and against `ts/` with the D-15 TypeScript import
forms. A case passes only when both pass. Version cases live in `v3/` (lockfile resolves
`js-yaml` `3.14.1`), `v4/` (`4.1.0`), `range/` (`"js-yaml": "^3.14.0"`, no lockfile) and `types/`
(only `@types/js-yaml` declared) under each of `js/` and `ts/`.

| Case | Source shape | Contract | Capability | Path |
|---|---|---|---|---|
| `JS-01` | `serialize.unserialize(req.body.x)`, `node-serialize` | `node-serialize-v1` | `code_execution` | `raw` |
| `JS-02` | `unserialize(Buffer.from(req.cookies.profile, 'base64').toString())`, destructured or named binding | `node-serialize-v1` | `code_execution` | `raw` |
| `JS-03` | `funcster.deepDeserialize(req.body.f)` | `node-serialize-v1` | `code_execution` | `raw` |
| `JS-04` | `v3/`: `yaml.load(req.body.y)` | `js-yaml-v1` | `code_execution`, version `3.14.1` | `raw` |
| `JS-05` | `v3/`: `yaml.safeLoad(req.body.y, { schema: yaml.DEFAULT_FULL_SCHEMA })` | `js-yaml-v1` | `code_execution` | `raw` |
| `JS-06` | `v3/`: `yaml.loadAll(req.body.y)` | `js-yaml-v1` | `code_execution` | `raw` |
| `JS-07` | `JS-01` through the inline `require` form (`js/`) and `import s = require(…)` (`ts/`) | `node-serialize-v1` | `code_execution` | `raw` |
| `JS-N1` | `v4/`: `yaml.load(req.body.y)` | None | | |
| `JS-N2` | `v3/`: `yaml.safeLoad(req.body.y)` | None | | |
| `JS-N3` | `v3/`: `yaml.load(req.body.y, { schema: yaml.JSON_SCHEMA })` | None | | |
| `JS-N4` | `JSON.parse(req.body.x)` | None | | |
| `JS-N5` | `v3/`: `yaml.load(fs.readFileSync('./config.yml', 'utf8'))` | None | | |
| `JS-N6` | `unserialize(req.body.x)` where `unserialize` is a function defined in the same file | None | | |
| `JS-U1` | `range/`: `yaml.load(req.body.y)` | `js-yaml-v1` | `unresolved`, `version_unknown` | `raw` |
| `JS-U2` | `v3/`: `yaml.load(req.body.y, { schema })`, `schema` a function parameter | `js-yaml-v1` | `unresolved`, `loader_unresolved` | `raw` |
| `JS-U3` | `types/`: `yaml.load(req.body.y)` | `js-yaml-v1` | `unresolved`, `version_unknown` | `raw` |
| `JS-C1` | `JS-01` after a rejecting `if` whose condition calls `crypto.timingSafeEqual` on a `crypto.createHmac('sha256', KEY).update(x).digest()` | `node-serialize-v1` | `code_execution` | `guarded`, control `integrity_check` |
| `JS-C2` | `JS-01` after a rejecting `if` comparing `crypto.createHash('md5').update(x).digest('hex')` | `node-serialize-v1` | `code_execution` | `guarded`, control `unkeyed_hash` |

`JS-B1` (D-16) is separate from the paired table: one client-flow fixture, built like the code
family's existing browser-context fixture, calls `yaml.load` on a browser source with js-yaml
3.x resolvable and yields no `deserialization_candidate`.

### AC3 — PHP

Test `TestDeserializationPHP` in `scan/internal/langphp`:
`go test ./scan/internal/langphp -run TestDeserializationPHP -count=1`.

| Case | Source shape | Contract | Capability | Path |
|---|---|---|---|---|
| `PHP-01` | `unserialize($_COOKIE['p'])` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-02` | `unserialize(base64_decode(urldecode($_COOKIE['p'])))` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-03` | `\unserialize($_POST['d'])` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-04` | `unserialize(file_get_contents('php://input'))` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-05` | `unserialize($_GET['d'], ['allowed_classes' => true])` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-06` | `unserialize($_GET['d'], $opts)`, `$opts` a function parameter | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-07` | `unserialize(gzuncompress(hex2bin($_POST['d'])))` | `php-unserialize-v1` | `object_injection` | `raw` |
| `PHP-08` | `Yaml::parse($_POST['y'], Yaml::PARSE_OBJECT)` with `use Symfony\Component\Yaml\Yaml;` | `php-symfony-yaml-v1` | `object_injection` | `raw` |
| `PHP-09` | `PHP-08` with a second flag joined by a bitwise or, and `Yaml` imported under an alias | `php-symfony-yaml-v1` | `object_injection` | `raw` |
| `PHP-N1` | `unserialize($_GET['d'], ['allowed_classes' => false])` | None | | |
| `PHP-N2` | `unserialize($_GET['d'], options: ['allowed_classes' => false])` | None | | |
| `PHP-N3` | `$opts = ['allowed_classes' => false]; unserialize($_GET['d'], $opts)`, `$opts` never reassigned | None | | |
| `PHP-N4` | `json_decode($_POST['d'])` | None | | |
| `PHP-N5` | `Yaml::parse($_POST['y'])` | None | | |
| `PHP-N6` | `$store->unserialize($_GET['d'])` | None | | |
| `PHP-N7` | `unserialize($_GET['d'])` inside a namespace that declares its own `unserialize` function | None | | |
| `PHP-N8` | `unserialize('a:0:{}')` | None | | |
| `PHP-U1` | `Yaml::parse($_POST['y'], $flags)`, `$flags` from `$_GET` | `php-symfony-yaml-v1` | `unresolved`, `loader_unresolved` | `raw` |
| `PHP-C1` | `PHP-01` inside `if (hash_equals(hash_hmac('sha256', $d, KEY), $sig)) { … }` | `php-unserialize-v1` | `object_injection` | `guarded`, control `integrity_check` |
| `PHP-C2` | `PHP-01` after `if (!hash_equals(hash_hmac('sha256', $d, KEY), $sig)) { exit; }` | `php-unserialize-v1` | `object_injection` | `guarded`, control `integrity_check` |
| `PHP-C3` | `PHP-01` inside `if (md5($d) === $sum) { … }` | `php-unserialize-v1` | `object_injection` | `guarded`, control `unkeyed_hash` |
| `PHP-C4` | `unserialize($_POST['d'], ['allowed_classes' => [Prefs::class, 'Theme']])` | `php-unserialize-v1` | `object_injection` | `guarded`, control `class_allow_list` |
| `PHP-E1` | `PHP-01` in a project with classes `Logger` (`__destruct`), `Token` (`__unserialize`) and `Plain` (neither) | `php-unserialize-v1` | `object_injection` | `raw`; `deserialization_magic_class` lists `Logger` and `Token`, not `Plain` |

Every record also has the request source as `input_source` and a completeness record with
`ClaimKind` `deserialization`.

### AC4 — Facts, family and selection

- `TestDeserializationFacts` in `scan/internal/analysis`: `Validate` accepts one valid record per
  capability and rejects each invalid form D-19 lists.
- `TestDeserializationSelection` in `scan/internal/analysispacks`: one Python, one JavaScript, one
  TypeScript and one PHP record each pass `Select` with the family-specific input component of
  D-18; a `python-` contract on a PHP record and a `php-` contract on a JavaScript record are
  rejected; a browser entry is rejected.
- The existing family digest test passes with no existing digest changed.

### AC5 — Policy

`TestDeserializationPolicy` in `scan/internal/judge`, with a stub judge. Answers are listed as
exposure, integrity, class restriction, coverage.

| Case | Record | Answers | Outcome |
|---|---|---|---|
| `P-01` | `PY-01` | `vulnerable`, `none`, `none`, `incomplete` | `confirmed_vulnerability` |
| `P-02` | `JS-04` | `vulnerable`, `none`, `none`, `incomplete` | `confirmed_vulnerability` |
| `P-03` | `PHP-01` | `vulnerable`, `none`, `none`, `incomplete` | `confirmed_vulnerability` |
| `P-04` | `PY-01` | `not_applicable`, `none`, `none`, `unknown` | `needs_evidence`, `answers_inconsistent` |
| `P-05` | `PHP-01` | `protected`, `verified_before_decode`, `none`, `complete` | `needs_evidence`, `answers_inconsistent` |
| `P-06` | `PY-C1` | `protected`, `verified_before_decode`, `none`, `complete` | `protected_for_claim` |
| `P-07` | `PHP-C4` | `protected`, `none`, `adequate`, `complete` | `protected_for_claim` |
| `P-08` | `PY-C2` | `protected`, `verified_before_decode`, `none`, `complete` | `needs_evidence`, `answers_inconsistent` |
| `P-09` | `JS-C1` | `vulnerable`, `none`, `none`, `incomplete` | `needs_evidence` (a guarded path is never Confirmed) |
| `P-10` | `PY-U1` | `vulnerable`, `none`, `none`, `incomplete` | `needs_evidence`, `capability_unresolved` |
| `P-11` | `PY-12` | `vulnerable`, `none`, `none`, `incomplete` | `needs_evidence`, `capability_unresolved` |
| `P-12` | `PY-01` with its only dependency changed to a `storage_source` | `vulnerable`, `none`, `none`, `incomplete` | `needs_evidence`, `origin_unresolved` |
| `P-13` | `PY-01` with question version `code-components-v2` | any | `needs_evidence`, `protocol_missing` |

### AC6 — Report

`TestDeserializationFinding` in `scan/internal/report`:

- A Confirmed `PY-01` record yields a finding of type `unsafe-deserialization`, CWE-502, whose
  summary contains "code execution by format design".
- A Confirmed `PHP-01` record yields the same type whose summary contains "object injection" and
  does not contain "code execution".
- The SARIF output has a rule for the type with CWE-502.
- A `needs_evidence` record is reported as Review, not as a finding.

### AC7 — Samples, offline

- VulnPy at its pin: `docs/samples/vulnpy/cases.json` gains `VP-DESER-01` to `-04`, kind
  `deserialization_candidate`, `expect` `candidate`, at `src/vulnpy/trigger/deserialization.py`
  lines 8, 12, 17 and 23, and all four pass. The four sinks form four sink groups.
- Vulnerable Flask App: `docs/samples/vulnerable-flask-app/cases.json` gains `VFA-DESER-01` with
  `expect` `absent` at line 97, and it passes.
- `recall-gap-inventory/cases.json` gains `TS-DESER-N01` and `JS-DESER-N01` as `no_record` and
  `JS-DESER-X01` as `excluded`, shaped like the existing rows of those kinds. All pass.
- The lab on its `deserialization-scenarios` branch: `TestNextJSVulnLab` with
  `ZAZZLES_VULN_NEXTJS` set passes, and `check.py --lab` classifies `DESER-001` and `DESER-002`
  as found and neither safe control as a raw finding. The lab's own checks in
  `docs/adding-scenarios.md` §8 pass.
- DVWA, Node.js Goof, Juice Shop and the TypeScript app gain no `deserialization_candidate`.
- Every sample checkout except the lab is clean at its pin before and after.

### AC8 — Isolation

- `go build ./... && go vet ./... && go test ./... -count=1` pass.
- `TestArchitectureBaseline` passes; `architecture-baseline.json` differs from the base only by
  additions.
- The recall floor in `check.py` holds against offline reports of every keyed sample.
- An offline scan with `--analyze --json` of the Python fixture app lists
  `deserialization_candidate` uses. `--only-family deserialization` and
  `--skip-family deserialization` are accepted with a judge, and an unknown family name is still
  rejected.

### AC9 — Live, within D-20

One judged run per target. Expected outcomes by record:

| Target | Expected |
|---|---|
| VulnPy | Every context of the four sinks is Confirmed, or shares the decision of an equivalent context that is. No other record is a finding |
| Lab, scenario branch | `DESER-001` and `DESER-002` unsafe routes Confirmed. Neither safe control is a finding |
| Python fixture app | `PY-01` to `PY-11`, `PY-13`, `PY-V1` and `PY-V6` Confirmed. `PY-12`, `PY-U1`, `PY-V2`, `PY-V4`, `PY-V5` Review. `PY-C1` to `PY-C4` not Confirmed |
| JS and TS fixture apps | `JS-01` to `JS-07` Confirmed in both. `JS-U1` to `JS-U3` Review. `JS-C1`, `JS-C2` not Confirmed |
| PHP fixture app | `PHP-01` to `PHP-09` Confirmed, each summary saying object injection. `PHP-U1` Review. `PHP-C1` to `PHP-C4` not Confirmed |

The Review and not-Confirmed rows are fixed by the policy and must hold. A Confirmed row that
comes back Review is a mismatch: read the saved trace, and fix the evidence, contract text or
question instruction if one of them misled the model, then rerun within D-20. A mismatch that
remains after two reruns is recorded as a result, not hidden. `PY-C1` and `PHP-C4` coming back
Protected is the expected good outcome and is recorded, not required.

`.zazz/evaluation/deserialization-results.md` records, per run: scanner commit, target commit,
planned and actual request counts, the outcome of every row above, and the total against the
D-20 budget. The README accuracy table changes only from `accuracy.py` output.

### AC10 — Docs and gate

- `docs/scan/analysis/deserialization.md` has one table per language of operations, capabilities,
  option and version facts, transfers and controls, then exclusions and limits, including any
  rule-2 substitution.
- `docs/scan/detection-capabilities/unsafe-deserialization.md` and the capability index list the
  family for the three languages, and the sentence in `docs/scan/detection-capabilities.md` that
  lists deserialization as not covered is corrected.
- The language guidance components that `interpreterDescriptors` emits for the family, and
  `report/guidance.go`, carry the family's guidance.
- The [contributor gate](../../docs/contributing.md#verification) passes.

## 8. Test strategy

- One table-driven adapter test per language over its fixture app. Each vulnerable case has a safe
  sibling and an unresolved sibling in the same table, so the tables in AC1–AC3 are the full list.
- JS/TS runs one table over paired `js/` and `ts/` projects, so a new case adds one row and two
  files.
- Transfers are asserted once per language on one sink (`PY-02`, `PY-04`, `PY-05`, `JS-02`,
  `PHP-02`, `PHP-07`). Every other sink shares the operand path, so per-sink transfer cases are
  omitted. The remaining transfers of D-6 are covered by one table-driven unit test per adapter
  that checks each listed call keeps its argument's dependency.
- The policy is tested with a stub judge only (AC5). The live run is the single check of model
  behavior (AC9).
- Samples verify through `check.py` and the lab test. No fixture copies sample source, and
  nothing tests the §4 exclusions.
- Fixtures contain no real secret: keys are the literal `KEY` constant `"fixture-key"`.

## 9. Execution sequence

1. Verify the worktree. Add the AC7 key rows; confirm they fail. Record the offline baseline of
   every keyed sample at the worktree's base in the run log.
2. **Red:** the `PY-01` fixture and its test row.
3. Facts (D-19), family registration and wiring (D-18, §4 checklist), contracts and questions.
   `PY-01` goes green. AC4.
4. Policy against the stub judge with hand-built records (AC5).
5. Python: remaining operations, loader facts, transfers and controls (AC1 without the `PY-V`
   rows).
6. Python version reader and the `PY-V` rows (D-17).
7. PHP: `unserialize`, `Yaml::parse`, transfers, controls and magic-method evidence (AC3).
8. JS/TS: operations, schema and version facts, paired fixtures and controls (AC2).
9. Report, SARIF and guidance (AC6). Replace the hand-built records of step 4 with fixture
   records.
10. Lab scenarios on their branch (D-21). Offline samples (AC7) and isolation (AC8).
11. Docs and gate (AC10).
12. Live runs (AC9, D-20). Results file.
13. Draft PR into `stage`, and the lab's draft PR, each listing AC evidence and any rule-2
    substitution. Do not merge either.

Steps 5 to 8 touch disjoint packages. If they are delegated, each subagent owns one language
package and shares this checkout.

```go
// DeserializationFacts records one verified deserializer call.
type DeserializationFacts struct {
	Operation  string `json:"operation"`
	ContractID string `json:"contract_id"`
	// Capability is code_execution, object_injection, restricted_types or unresolved.
	Capability string `json:"capability"`
	// Option is the option the capability was read from, as source text:
	// a loader, a schema, flags or an allowed_classes value.
	Option string `json:"option,omitempty"`
	// OptionGap is loader_unresolved or version_unknown, set only with
	// capability unresolved.
	OptionGap string `json:"option_gap,omitempty"`
	// Version is the exact library version a version-dependent capability used.
	Version  string                   `json:"version,omitempty"`
	Controls []DeserializationControl `json:"controls,omitempty"`
	// Paths cover every dependency with operand "data".
	Paths []CommandPath `json:"paths"`
}

// DeserializationControl is one recorded control. Context indexes the use's
// context evidence. Kind is integrity_check, unkeyed_hash, class_allow_list
// or format_check.
type DeserializationControl struct {
	Kind    string `json:"kind"`
	Context int    `json:"context"`
}
```

## 10. Definition of done

- [ ] AC1–AC8 and AC10 pass, with command output in the run log.
- [ ] AC9 ran within the D-20 budget and its results are recorded, or the run log states the
      missing key or account failure that prevented it.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] Every rule-2 substitution is listed in the docs limits and the PR description.
- [ ] A fresh-context verifier subagent ran the checks in §13 and reported PASS.
- [ ] Both draft PRs are open and neither is merged.

## 11. Resolved questions

Nothing is open. The draft's questions were decided as follows.

| Question | Decision | Decided by |
|---|---|---|
| Is request-controlled PHP `unserialize` a Confirmed finding or a practice finding? | Confirmed, with the impact stated as object injection (D-11) | Draft recommendation, adopted 2026-11-21 |
| Should `socket.recv` become a source so `VFA-DESER-01` has a witness? | No. The row is keyed as no record (D-9) | Draft recommendation, adopted 2026-11-21 |
| Is the standing live check enough, or is a cap wanted? | Paid runs are authorized by the spec within the D-20 limits | Owner, 2026-11-21 |
| Should the lab gain JS/TS scenarios? | Yes, two scenarios in this deliverable (D-21) | Owner, 2026-11-21 |
| Should browser-side calls make a record? | No (D-16) | Decided in review, 2026-11-21 |
| Are model-free practice findings in scope? | No (D-12) | Decided in review, 2026-11-21 |

## 12. Run log protocol

Use the plan's run-log rules. Record scanner commit, sample pins and clean status, the lab branch
commit, failing-first evidence for step 2, the command and result for each AC, golden deltas,
every rule-2 substitution, and for each live run the planned and actual request counts and the
running total against the D-20 budget.

## 13. Agent implementation prompt

> Work in the `analyzer-unsafe-deserialization` sibling worktree. Read AGENTS.md, the orientation
> contents, this spec and the files in §2. Ask nothing: every question is decided in §5 and §11,
> and §6 says what to do when something does not fit. Execute §9 in order from the failing `PY-01`
> fixture, committing after each step. Keep every sample except the lab read-only. Run the live
> checks of AC9 only after AC1–AC8 pass, within D-20. Finish with two draft PRs listing the
> evidence for each criterion, and merge neither.
> Verifier: a fresh-context subagent runs `go build ./... && go vet ./... && go test ./... -count=1`,
> the four named adapter and policy tests, and `check.py` on fresh offline reports of VulnPy, the
> TypeScript app and the lab branch. It confirms that `VP-DESER-01` to `-04` pass, that
> `TS-DESER-N01` has no record, that one `ts/` case and one PHP case have the record their table
> row states, and that no file outside §4 changed. It reports PASS or FAIL in the run log.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Requested by the owner after the Symfony review found an unlisted `unserialize` of a cookie. Written
from a search of every local sample for deserializer calls and from the `code` family's structure.
No code changed.

### 2026-11-21 — Language coverage review

Requested by the owner: does the spec cover Python, JS/TS and PHP evenly. Added the language
coverage table, per-language operations, option and version facts, transfers, controls, binding
forms and acceptance cases, a Python version source, and corrected paths for the `scan/` layout.

### 2026-11-21 — Unattended-implementation review

Requested by the owner: remove gaps, inconsistencies and open questions so an agent can implement
unattended; give each language sound acceptance criteria and tests; authorize paid runs; add lab
routes. Checked against the code at `e608c86` and against library documentation.

Corrections to the earlier text:

- **Open questions closed** (§11). The implementation prompt no longer asks anything first.
- **Halts replaced** by the unattended rules in §6.
- **Implementation path fixed.** The family is a fourth operand family built like upload (D-18),
  with a wiring checklist (§4). The earlier text named files the family does not touch
  (`contracts.go`, `questions.go`, `findings.go` in `analysis`, the `guidelines` package) and
  gave no registration values.
- **Question name collision.** `type_restriction` already belongs to the upload family and choices
  resolve by name; the question is now `class_restriction` (D-8).
- **Component isolation.** Editing the shared PHP input component would change other families'
  digests; the family uses its own copies (D-18).
- **Controls made mechanical.** Path protection follows the shared guard rule and controls are
  classified by a fixed table (D-7). The earlier "dominates the sink on the same bytes" had no
  defined test, and PHP had no stated way to record a guard.
- **Policy made a rule table** (D-10) with one stub-judge case per rule (AC5).
- **Origins reconciled.** The earlier text both promised an external-source witness for socket
  bytes and recommended leaving the row alone. Socket bytes make no record (D-9).
- **Practice findings removed** (D-12): no channel exists for them outside the Next.js adapter.
- **Undocumented operations removed:** `ruamel.yaml`, `jsonpickle.loads` and
  `funcster.deserialize`. Removed `jsonwebtoken.verify` and signed cookies as controls.
- **Library facts verified** for PyYAML and js-yaml and written as tables (D-3, D-5).
- **Acceptance rewritten** as case tables with identifiers for each language (AC1–AC3), plus
  facts and selection (AC4), policy (AC5), report (AC6), samples (AC7), isolation (AC8), live
  (AC9) and docs (AC10), each naming its test.
- **Paid runs authorized** by the owner within D-20, with a request budget and expected outcomes.
- **Lab scenarios added** (D-21) and **fixture apps** made scannable so PHP and TypeScript have
  live evidence (D-22).

No code changed.
