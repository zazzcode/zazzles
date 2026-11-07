# VulnPy detection guide and comparison checklist

[Sample reports](../../docs/samples/vulnpy/README.md) ·
[Expected cases](../../docs/samples/vulnpy/cases.json) ·
[ThreatByte guide](threatbyte-detection-guide.md) ·
[FastAPI answer guide](python-insecure-app-detection-guide.md)

## Purpose

Use this living guide to expand Zazzles coverage without changing expected answers to match current
output. The SQL Injection, Input Validation, Sensitive Data Logging and XSS Analyzers have bounded
implementations. The Command Injection Analyzer's source-reviewed expectations are recorded below;
its implementation and full judged acceptance remain pending. Other trigger families remain planned. A supported vulnerability family does
not imply support for every framework, callback, dynamic registration or library pattern.

Reviewed source: [Contrast-Security-OSS/vulnpy](https://github.com/Contrast-Security-OSS/vulnpy),
MIT, revision `b81885e58283a3449b578d20c20557aff637e5ea`. README describes a vulnerable function
library with framework adapters, not just one fixed app. The examples cover Flask, FastAPI, Django,
Falcon, Pyramid, Bottle, WSGI, Quart and aiohttp variants. The README also announces that the project
is no longer maintained. Source, README and tests were read without installing or executing the app.

## SQL injection: three required positive cases

`src/vulnpy/trigger/sqli.py` contains three variants. `_db_reset` establishes an actual in-memory
sqlite3 connection; `_execute` supplies its cursor to a nested callback. The public trigger function
captures user_input and the callback formats it into SQL before execution. The wrapper catches
exceptions and returns an error string; catching errors does not repair query construction.

| Case | Source construction and sink | Expected answer |
| --- | --- | --- |
| VP-SQL-EXECUTE | do_sqlite3_execute → format at 36 → execute at 37 | SQL-injection positive; first inserted value becomes SQL text |
| VP-SQL-EXECUTEMANY | do_sqlite3_executemany → format at 47 → executemany at 48 | SQL-injection positive; the parameter operand binds a different value, not the interpolated first value |
| VP-SQL-EXECUTESCRIPT | do_sqlite3_executescript → format at 58 → executescript at 59 | SQL-injection positive; executable script contains request text and is not value-bound |

The map in `trigger/util.py` discovers trigger functions using imports/introspection; get_trigger
selects the named function. Framework view factories call it with request input. For Flask, input
comes from the User-Input header, query parameter or form via `_get_user_input`; for FastAPI, it is
the query parameter of a dynamically constructed view. SQL trigger names become paths such as
`/vulnpy/sqli/sqlite3-execute`, with Flask allowing GET/POST and optional trailing slash.

`tests/trigger/test_sqli.py` supplies concrete row-manipulation expectations for all three variants,
including a quote-containing invalid input. Those source tests are stronger expected-behavior
evidence than the mere word “sqli” in a filename. They were inspected, not executed in the target.

- [x] Resolve generated registration and imported trigger selection without executing project code.
- [x] Retain the input captured by the nested callback and the cursor passed by `_execute`.
- [x] Keep the SQL-text value separate from executemany's bound value.
- [x] Do not label constant schema initialization or SELECT_ALL as user-controlled SQL.
- [x] Add protected parameterized counterparts in scanner fixtures/remediation copies.

## XSS: required positive paths

| Case | Source trace | Expected answer |
| --- | --- | --- |
| VP-XSS-FLASK | _get_user_input → generated xss/raw view → concatenation at flask/blueprint.py:55 → returned HTML at 57 | Reflected XSS |
| VP-XSS-FASTAPI | user_input query parameter → generated xss/raw view → concatenation at fastapi/vulnerable.py:42 → HTMLResponse at 44 | Reflected XSS |
| VP-XSS-JINJA | apps/flask_app.py query input at 20 → template.render at 19 → apps/templates/jinja/xss.html | Raw template-output XSS; the environment has no autoescape setting and the template explicitly uses safe |

`trigger/xss.py:do_raw` returns an empty string; it is not the actual HTML sink. The vulnerable
markup is assembled by the framework adapter. The framework tests assert that input appears in
that output, but their ordinary marker is not itself a browser exploit test.

- [x] Follow the actual HTML response/renderer rather than inventing a sink in do_raw.
- [x] Resolve factory parameters name/trigger before declaring a raw branch feasible.
- [ ] Model the Environment/get_template/render binding and the concrete template trust bypass.
- [x] Keep raw versus escaped text counterparts and unknown custom configuration controls.
- [ ] Extend the same review to other framework adapters as their extraction support is implemented.

## Command injection: source-reviewed acceptance cases

**Reviewed 2026-11-07 at the pinned revision above.** This is an independent expected-results
reference for the **Command Injection Analyzer**; the delivered scan results are in the [acceptance results](command-injection-results.md). Originally written before implementation, it is not a claim that Zazzles detects
these cases. Source, templates and tests were inspected without imports, installation, test execution
or vulnerable command execution. [Source hashes](vulnpy-command-injection-sources.json) bind this
review to the original files. Paths and line numbers below are relative to the VulnPy checkout.

### Core shell-execution defects

| Case | Source-backed sink | Expected result |
| --- | --- | --- |
| VP-CMDI-OS-SYSTEM | `src/vulnpy/trigger/cmdi.py:5–6`: `do_os_system(command)` passes its parameter directly to imported `os.system` | Command-injection positive when an external request supplies `command`; it is shell text, not a separate data operand |
| VP-CMDI-SUBPROCESS-POPEN | `src/vulnpy/trigger/cmdi.py:9–13`: `do_subprocess_popen(command)` passes its parameter to imported `subprocess.Popen`, with `shell=True` at line11 | Command-injection positive on the request path; PIPE/STDOUT and `communicate()` change output handling, not shell syntax protection |

`src/vulnpy/templates/fragments/cmdi.frag.html:1–30` explicitly documents both examples and supplies
forms for `/vulnpy/cmdi/os-system/` and `/vulnpy/cmdi/subprocess-popen/`. The generated
`src/vulnpy/templates/cmdi.html:40–69` contains those forms too. The form's example shell syntax
is documentation evidence; it MUST NOT be submitted to a running target during this evaluation.

`tests/trigger/test_cmdi.py:5–30` expects command execution/status or stdout for the two wrappers.
`tests/trigger/base_test.py:29–39` actually calls the selected trigger in the upstream suite; therefore
these tests were read, not run. They establish intended semantics, not complete request reachability.
`src/vulnpy/trigger/__init__.py` supplies a constant demo input for tests; that constant MUST NOT
replace the actual request source in the scanner's trace.

### Generated request paths to both core sinks

`src/vulnpy/trigger/util.py:29–46` derives trigger names from exported `do_*` functions;
lines49–64 map `os-system`/`subprocess-popen` back to the actual imported functions.
Every adapter row below exposes both core cases. A shell sink reported without its entry/input and
invocation transfer is not complete coverage. Preserve each framework/method/registration context;
these are repeated exposures of two shared sink defects, not two new defects per endpoint.

| Adapter and source | Request source → invocation | Registration / method evidence |
| --- | --- | --- |
| Flask `src/vulnpy/flask/blueprint.py` | Header `User-Input` takes precedence at 9–11; GET query or other-method form input at 13–15 → generated closure at 44–50 | Blueprint prefix `/vulnpy`; `/{name}/{trigger}/` at 24–25 and add_url_rule at 59–70; GET/POST, strict_slashes=False |
| FastAPI `src/vulnpy/fastapi/vulnerable.py` | `_view(user_input: str)` query binding at 32–37 → selected trigger | `/vulnpy/{name}/{trigger}` at 17–18; GET decorator at 32; generated calls at 52–55; annotation does not sanitize shell syntax |
| Quart `src/vulnpy/quart/blueprint.py` | Header `User_Input` at 9–11, else query at 13 → async view at 42–48 | Prefix `/vulnpy`; path at 22–23; GET/POST registration at 57–68; unlike Flask, the fallback is query input for both methods |
| Django sync `src/vulnpy/django/vulnerable.py` | GET query / otherwise form at 12–15 → view at 25–31 | Regex `^vulnpy/{name}/{trigger}/?$` at 49–50; compat_url registration at 64–77; GET/POST tested |
| Django ASGI `src/vulnpy/django/vulnerable_asgi.py` | Awaited source helper at 14–34 → async view at 44–50; Django<4 GET fallback decodes `META[HTTP_QUERY_STRING]` | Regex at 68–69; compat_url at 83–96; ordinary GET query and POST paths plus version-specific fallback remain distinct |
| Falcon sync `src/vulnpy/falcon/vulnerable.py` | Base `on_get` reads `req.get_param` at 30–40 → subclass `trigger` at 64–72 | Source-generated base class at 77–84 and resource instances at 89–96; GET; trailing-slash stripping at 106 |
| Falcon ASGI `src/vulnpy/falcon/vulnerable_asgi.py` | Async base `on_get` at 30–40 → subclass `trigger` at 64–72 | Matching source-generated class/instance registrations at 77–96; GET; distinct ASGI adapter identity |
| Bottle `src/vulnpy/bottle/vulnerable_routes.py` | GET query / otherwise form at 6–9 → closure at 29–35 | `/vulnpy/{name}/{trigger}` at 25–26; app.route GET/POST at 54–60 |
| Pyramid `src/vulnpy/pyramid/vulnerable_routes.py` | GET query / otherwise form at 7–10 → closure at 40–46 | Path at 19–20; add_route/add_view at 66–90, including explicit trailing-slash variant; GET/POST tested |
| aiohttp `src/vulnpy/aiohttp/vulnerable_routes.py` | `request.rel_url.query` at 6–7 → async closure at 18–24 | Path at 42–43; web.get registrations at 62–72 for both slash forms |
| WSGI `src/vulnpy/wsgi/app.py` | `parse_qs(environ[QUERY_STRING])` at 52–57 → vulnerable_app at 18–24 | PATH_INFO split/selection at 60–100; use query input, not an invented POST-body source; GET request is exercised by upstream tests |

App registrations/mounts are in `apps/{flask_app,fastapi_app,quart_app,django_app,django_asgi_app,
falcon_app,falcon_asgi_app,bottle_app,pyramid_app,aiohttp_app,wsgi_app}.py`. The Flask two-app example
also registers the blueprint separately on `app1` and `app2`; its `/app1` and `/app2`
DispatcherMiddleware mount exists inside the `VULNPY_USE_CONTRAST` condition. Report that condition
rather than inventing unconditional mounted endpoints. `apps/wsgi_two_apps.py` creates two app
instances/servers; keep invocation identity without inventing a new URL prefix or port at analysis time.

`tests/__init__.py` parameterizes trigger names. Corresponding tests under
`tests/{flask,fastapi,quart,django,falcon,bottle,pyramid,aiohttp,wsgi}/` establish request shapes;
Django/Falcon have separate ASGI test modules. Those tests cover successful responses and, in
Falcon, exception-catching behavior. A successful response or caught execution error does not make
the command input safe. Source spelling matters: Flask reads `User-Input`, while Quart reads
`User_Input`; do not infer equivalent header sources from a test marker alone.

### Additional app-specific witnesses

| Case | Entry and source trace | Expected result and preconditions |
| --- | --- | --- |
| VP-CMDI-FASTAPI-LOOP | `apps/fastapi_app.py:37–43`: GET `/cmdi`, query `user_input` → `"echo " + user_input + ...` → `os.system(cmd)` inside range(10) | Positive shell construction; the finite loop and sleeps do not sanitize input; one source sink, not ten defects |
| VP-CMDI-FASTAPI-UPLOAD | `apps/fastapi_app.py:30–33`: POST `/files/upload`, UploadFile.read → first20 bytes → imported do_os_system → core sink at cmdi.py:6 | Positive upload-to-command path under POSIX bytes command semantics; verify bytes handling against the operation contract; slicing is not shell protection |
| VP-CMDI-QUART-UPLOAD | `apps/quart_app.py:17–25`: POST `/files/upload`, awaited request.files → file.read → first20 bytes → do_os_system → cmdi.py:6 | Positive path; catching ValueError after invocation does not prevent execution |
| VP-CMDI-FALCON-UPLOAD | `apps/falcon_app.py:22–29`, registration at82: POST `/file-upload`, req._params[upload].file.read → first10 bytes → str → echo concatenation → os.system | Conditional on multipart input being supplied; the hash at26 is a separate sibling value and does not protect the command; review bytes-repr shell context rather than crediting str as an escape |
| VP-CMDI-FALCON-THREAD | `apps/falcon_app.py:70–74`, registration at83: GET `/thread`, query user_input → Thread(target=thread_function, args=(user_input,)).start → cmd at63 → os.system at64 | Conditional positive: contrast imports must succeed; guard at45–61 can return/exit before the sink. Preserve a feasible sink-reaching configuration and thread transfer; do not claim unconditional execution |

Together these are **five distinct shell sink source locations**: two in `trigger/cmdi.py`, one in
`apps/fastapi_app.py`, and two in `apps/falcon_app.py`. The seven named cases above distinguish
shared trigger defects from additional entry/transfer witnesses; route/method/mount counts are
separate and MUST NOT be presented as unique source-defect counts. Tests and template examples
are supporting evidence, not additional production sinks.

### Negative/protection controls and acceptance

- `/vulnpy/cmdi/` is a category/demo page, not a call to both command triggers. WSGI explicitly
  returns no trigger for that path; Falcon's root class trigger is a no-op.
- `catch_exception`, redirects, diagnostic prints, string annotations, truncation and stdout capture
  do not establish shell protection. Missing input may avoid a particular invocation but does not
  protect supplied command input on another supported path.
- No protected argv counterpart was identified among these command examples. Add fixed-executable,
  enforced finite-allowlist, shell-disabled counterparts and unresolved-option controls in scanner
  fixtures; do not modify the pinned app or invent a protected source case.
- Final acceptance of the command analyzer requires the full pinned VulnPy checkout, including the
  generated adapter and app-specific paths above. Unsupported framework/loop/upload/thread transfer
  remains a failed positive coverage case until repaired; Review or a warning is not a pass.
- Before live judging, expand these expectations into a machine-readable entry/method/sink matrix
  with source hashes and explicit conditional-path assumptions. Keep it outside scanner/model inputs.
  Compare both unique sink coverage and per-context coverage; never shrink the expected set to match
  scanner output. Preserve the existing SQL/XSS historical `cases.json` without rewriting its labels.

No new Zazzles, Semgrep or Bearer scan was run for this source-review addition. Existing comparator
results remain historical. Direct import/call/configuration evidence establishes the two core shell
APIs independently of comparator agreement. Future detection/paid-evaluation evidence is governed by the
[command analyzer acceptance contract](../specifications/command-injection.md#8-test-strategy-and-independent-references),
with implementation results to be recorded separately; no such results are claimed by this review.

## Validation and logger-leak controls

The arbitrary user_input fields have no general business-format requirement established by their
names. Query protection and output encoding are the primary concrete constraints in these examples.
Do not prescribe arbitrary alphanumeric or length restrictions as an invented field-policy finding.
Derive any future field constraints from actual route contracts and enforcing implementation.

Constant diagnostic prints in example routes and trigger lookup errors do not automatically expose
password/email content. A path that logs such content needs independent source/classification and
emission evidence. No confirmed PII logger-leak answer is invented here merely to fill that family.

- [x] Keep missing business policy as Review, separately from concrete SQL/XSS defects.
- [ ] Require actual sensitive content and logger binding before promoting a leak.
- [ ] Test password/email leaks and protected logging controls in separate scanner fixtures.

## Historical baseline and known coverage work

Baselines used the same clean target revision and pinned local rules without credentials or model
calls. Zazzles ran on the original read-only checkout; comparison engines parsed copies of tracked
files. Raw artifacts are under `_test-findings/vulnpy/` and normalized results under the sample link.
Tool output scopes/exclusions, rule hashes, exit codes and source hashes are retained.

| Tool | Result | Meaning |
| --- | --- | --- |
| Zazzles | 11 static route entries, 6 unassessed records, 4 explicit registration/path warnings | Generated trigger routes remain unsupported; one separate Jinja output candidate is unresolved |
| Semgrep CE 1.183.0 | 8 results; no scan errors | Autoescape configuration warning plus hash, deserialization, shell and container findings; no three SQL trigger findings |
| Bearer e3753de, rules 82c335f | 21 results; workers completed | Command/code execution, deserialization, XML, traversal, weak randomness/hash; no three SQL trigger findings |

The first Bearer attempt returned zero after sandbox-blocked worker sockets. That report is invalid
and retained only as failed history. The successful second run, with local worker sockets allowed,
is the baseline. No comparison-rule packs were downloaded for this addition.

The six source-positive cases are retained as **known misses**, not changed into negatives. Four
additional checks require explicit warnings for generated FastAPI paths and Flask add_url_rule
registrations. The case evaluator reports six misses and four coverage-control passes and exits
nonzero. The original three-app 29-case checks remain separate. A framework/model limitation is
coverage work within existing families, not evidence the app is safe.

- [ ] Add bounded, source-backed factory/registration/dispatch/callback support in future hardening.
- [ ] Upgrade the Jinja Environment/template binding so the candidate becomes a supported raw claim.
- [ ] Recalibrate only once necessary static evidence exists; model confidence cannot fill these gaps.
- [ ] Record tool disagreements per source case; 8 versus 21 is not an accuracy ranking.

## Future vulnerability-family branches

Beyond the command-injection examples reviewed above, trigger modules cover deserialization, weak hashing/randomness, parameter
pollution, traversal, ReDoS, SSRF, unsafe code execution, XXE and XPath injection. Preserve these as
future answer-key work. The comparison tools' broader results can guide source review, but do not
replace an independent expected result and protected counterpart for each new class.

- [ ] For each future family, review the actual operation, input contract, tests and framework path.
- [ ] Keep sink-level defects distinct from the many framework/method instances exposing them.
- [ ] Preserve target source integrity and avoid running its deliberately unsafe trigger functions.

## D5 confirmation and remaining gaps

The [source reference's confirmed-findings table](../../docs/samples/vulnpy/reference.md#findings-confirmed-by-scan-and-code-inspection--d5)
records the five SQL/raw-XSS source cases recovered by the full 2026-11-04 scan and then checked
against actual code. Main-app acceptance covers 12 method/route contexts; separate mounted instances
produce 28 contextual vulnerability findings across the full checkout. These are static source
confirmations, not runtime exploit executions. The 827 model assessments completed successfully;
model choices without necessary source/policy evidence remain Review.

Upstream supplies deliberately vulnerable functions and behavioral tests, rather than a formal
expected-findings manifest. The SQLite tests establish concrete input/row behavior and framework
XSS tests establish input inclusion; source review supplies the security reasoning. Evaluation labels
remain outside scanner/model inputs. Historical saved findings, raw answers, hashes and case labels
are unchanged. `VP-XSS-JINJA`, other framework adapters and additional families remain separate work.
Use the [D5 results](common-entry-dispatch-results.md) for checks, artifacts and supported-subset limits.
