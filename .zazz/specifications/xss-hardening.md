# XSS hardening: report every known XSS as confirmed

## Capability and scope

Improve the XSS Analyzer so every independently documented XSS in Juice Shop,
vulnerable-typescript-app, nodejs-goof, VulnPy and vuln-demo-app reports as a completed
`confirmed_vulnerability` (red), not Review, without promoting source-reviewed negatives.
Work happens in the `xss-hardening` worktree. Sample applications stay read-only.

The [matrix](../evaluation/xss-hardening/matrix.json) owns the required cases and controls;
[evaluate.py](../evaluation/xss-hardening/evaluate.py) checks a report set against it. Labels come from the
[Juice Shop](../../docs/samples/juice-shop/xss-answer-key.md), [Goof](../../docs/samples/nodejs-goof/xss-answer-key.md) and
[TypeScript](../../docs/samples/vulnerable-typescript-app/xss-answer-key.md) keys, the
[VulnPy guide](../evaluation/vulnpy-detection-guide.md) and the new
[vuln-demo-app guide](../evaluation/vuln-demo-app-detection-guide.md).

## Authorization

The user authorized paid OpenAI Decisions `gpt-6-luna` scans of all five applications with
`--skip-family input-validation`, repeated as needed for this loop. Every run sets an explicit
`--judge-limit`. There is no provider or model fallback.

A later user request added sql.js SQL injection for vuln-demo-app to this worktree. It is offline only:
that request did not extend the paid authorization above.

## Invariants

- Add semantics, never sample-specific conditions. Every new link needs source evidence: a verified
  binding, an actual write and read, or a named versioned contract. Field-name equality alone is not a link.
- Do not edit a label to fit output. `JS-XSS-08` stays Review because its key leaves attacker control of
  the configured file unresolved.
- An unsafe supported path is a witness; unknown siblings stay in the evidence and never protect it.
- Model answers cannot fill a missing source fact. Green still requires protection on every modeled path.

## Hardening slices

1. **Server HTML construction:** per-value output context through template strings and local wrappers, one
   record per context, HTML established through helper returns, inline response callbacks.
2. **SQL-backed storage:** sql.js bound writes and literal reads through local query helpers; Sequelize raw
   `SELECT` table reads; row iteration results.
3. **Model semantics:** Sequelize attribute setters on writes; finale-rest resources as write and read
   endpoints; versioned sanitize-html contract (before 1.4.3, CVE-2016-1000237); tag-stripping regex replacements.
4. **Angular links:** service response projection, `for…of` aliases, trusted fields rendered through template
   iteration variables and gallery `args`, dialog data, verified JWT claims back to signed model fields.
5. **Python:** HTML responses for aiohttp, Django, Pyramid, Bottle, Quart, Falcon and WSGI; Jinja environments.

## Acceptance

- `evaluate.py` exits 0 on fresh paid scans of all five applications.
- Every other confirmed XSS is source-reviewed as a true positive or fixed as a false positive.
- Each slice has an offline test that fails without it. `go test ./...`, `go vet ./...` and changed-file
  formatting pass. Target checkouts stay clean at their pins.
- Results go to [xss-hardening-results.md](../evaluation/xss-hardening-results.md), and the public
  [XSS guide](../../docs/analysis/xss.md) matches implemented behavior.
