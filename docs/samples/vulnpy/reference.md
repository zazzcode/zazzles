# VulnPy source reference

The [living detection guide](../../../.zazz/evaluation/vulnpy-detection-guide.md) owns trace rationale,
expected classifications, protected controls to add and future-family work. [Source hashes](source-hashes.json)
bind this reviewed reference to the application revision. Labels are evaluation-only inputs.

The SQL answer key is supported by actual format-to-sqlite operations and tests, not filenames:
execute at `src/vulnpy/trigger/sqli.py:37`, executemany at 48 and executescript at 59. Input is captured
by nested callbacks and interpolated before the database call. Executemany binds a separate value;
it does not protect its already-formatted SQL text.

Reflected XSS is in generated Flask/FastAPI views returning raw HTML, not in the empty do_raw trigger.
A separate Jinja environment/template path exists in `apps/flask_app.py` and its template uses safe.
The published historical baseline has six current-family source-positive misses and four warning
controls. Its [case evaluator](../evaluate-python.py), case labels and saved reports retain those
results; the later evidence below does not rewrite that history.

## Findings confirmed by scan and code inspection — D5

Reviewed on 2026-11-04 against the same pinned revision. The full source-only scan used OpenAI
Decisions `gpt-6-luna`, followed by inspection of the actual registrations, request reads, selected
functions, callback/cursor bindings and operation operands. These are source-supported static
vulnerability confirmations, not executed exploits or independent human-review certification.
VulnPy's README does not supply a formal per-route vulnerability manifest; these expectations are
derived from its source and tests, not inferred from model agreement or trigger names.

| Case | Generated exposure | Source inspection confirming the flaw | Scan result |
| --- | --- | --- | --- |
| VP-SQL-EXECUTE | `/vulnpy/sqli/sqlite3-execute` | Captured request input is formatted into executable SQL at `trigger/sqli.py:36` and passed to the verified SQLite cursor's `execute` at line 37. | Confirmed in Flask GET/POST and FastAPI GET contexts. |
| VP-SQL-EXECUTEMANY | `/vulnpy/sqli/sqlite3-executemany` | The formatted first value enters SQL text at lines 47–48. The separate parameter operand binds a different value and does not repair the interpolated SQL. | Confirmed in Flask GET/POST and FastAPI GET contexts. |
| VP-SQL-EXECUTESCRIPT | `/vulnpy/sqli/sqlite3-executescript` | Request text is formatted into the script at lines 58–59; `executescript` executes that text without value binding. | Confirmed in Flask GET/POST and FastAPI GET contexts. |
| VP-XSS-FLASK | `/vulnpy/xss/raw/`, GET/POST | `_get_user_input` supplies header/query/form input. The resolved `name == "xss"` / `trigger == "raw"` branch concatenates it into HTML at `flask/blueprint.py:55`, returned at line 57 without encoding. | Confirmed in both methods. |
| VP-XSS-FASTAPI | `/vulnpy/xss/raw`, GET | The generated handler's query parameter is concatenated into HTML at `fastapi/vulnerable.py:42` and wrapped by `HTMLResponse` at line 44 without encoding. | Confirmed in GET. |

All paths in the source column are under `src/vulnpy/`. Flask declares the SQL routes with trailing
slashes and `strict_slashes=False`; the stem spelling above identifies their matching family.
Flask retains the `User-Input` header's precedence, then GET query or POST form alternatives.
FastAPI binds the actual `user_input` query parameter. SQL witnesses retain the selected trigger,
its captured input, `_execute`'s callback parameter, `_db_reset`'s connection and the derived cursor.
Constant setup statements and `SELECT_ALL` are not counted as request-derived SQL defects.
`trigger/xss.py:do_raw` returns an empty string and is not a rendering sink.

The main Flask/FastAPI apps account for 12 required route/method contexts. The separate Flask
`app1`/`app2` mounts add independently identified exposures, producing 28 contextual findings in the
full scan: 21 SQL and 7 raw-XSS. These are five source locations, not 28 distinct vulnerabilities.
All 827 candidate assessments completed; 799 records remain evidence-limited, including the deferred
Jinja path and observations without an established business-validation policy.

`VP-XSS-JINJA` remains a source-positive coverage gap: its Environment/template binding is separate
from these generated raw responses. Other frameworks and vulnerability families are not established
by this D5 result. The original six-positive-miss/four-warning baseline and `cases.json` remain intact.
Detailed commands, limits, pipeline checks and provenance are recorded in the
[D5 implementation results](../../../.zazz/evaluation/common-entry-dispatch-results.md).


## Current source-anchor and coverage corrections

The current pinned source resolves `apps/flask_app.py:18` through the Environment loader
at lines 10–11 to `apps/templates/jinja/xss.html`. The render call at app line 19 passes
request input, while the actual unescaped output is `{{ user_input | safe }}` at template
line 30. The case inventory now anchors that same positive to its output sink, preserving
the earlier call location as provenance. This raw-output path was already recognized in
the pre-refactor published report; the older “Jinja gap” narrative above is historical.

The four generator-registration controls at FastAPI lines 24/32 and Flask lines 33/61
retain their source locations. Their criterion is explicit coverage disposition: either
a source-backed registration with matching entry, resolved callable dispatch and invocation,
or the specified unresolved-registration warning. They must not pass when both are absent.
The earlier gap-only assertions are preserved in `previous_expect`; resolved finite
registrations must not be made to emit fabricated warnings to satisfy historical checks.

All six positive-source checks and four registration-disposition checks pass on the current
complete source snapshot. Expected positive classifications remain unchanged; no case was
removed or reclassified as safe to fit model output.
