# vuln-demo-app: source-reviewed XSS and SQL reference

[XSS hardening contract](../specifications/xss-hardening.md) · [Matrix](xss-hardening/matrix.json)

Reviewed 2026-11-07 at `d27b35bdd2d599f1f79dace71d5272215df04423`; `server.js` SHA-256 `ff4f61acd1037140c697af68ceb223c70f432583e4d2c23d79f852f066a11a31`.
Labels come from reading `server.js` and the README, before any hardening scan result. The application
was not installed or executed, so these are static source confirmations, not runtime exploits.

`res.send` of a string is `text/html` under Express. `layout(title, body)` (`server.js:66`) interpolates
`body` unescaped, so it adds no protection. Nothing in this application encodes or sanitizes output.

## Confirmed vulnerabilities (required red)

| Case | Type | Source → sink | Why |
|---|---|---|---|
| `DEMO-XSS-01` | Reflected (README) | `GET /greet`: `req.query.name` (`:178`) → `<h1>Hello, ${name}!</h1>` → `layout` → `res.send` (`:180`) | HTML text, no encoding. The `|| "Guest"` default is not protection. |
| `DEMO-XSS-02` | Stored (README) | `POST /notes`: `req.body.title/body` (`:206`) → bound `INSERT INTO notes` (`:208`) → `GET /notes` `SELECT` (`:185`) → `${n.title}`, `${n.body}` (`:187`) → `res.send` (`:190`) | Parameter binding prevents SQL injection only; the stored text is still rendered raw. |
| `DEMO-XSS-03` | Stored, **not in README** | Same writes as 02 → `GET /search` `SELECT ... FROM notes` (`:156`) → `${n.title}`, `${n.body}` (`:163`) → `res.send` (`:166`) | Second raw rendering of the same stored fields. |
| `DEMO-XSS-04` | Reflected, **not in README** | `GET /search`: `req.query.q` (`:150`) → `value="${q}"` (`:169`) → `res.send` (`:166`) | Quoted attribute with no encoding; a double quote leaves the attribute. |
| `DEMO-XSS-05` | Reflected, **not in README** | `POST /fetch`: `req.body.url` (`:226`) → `<h1>Response from ${url}</h1>` (`:237`) → `res.send` (`:236`) inside the `http.get` end callback | Raw HTML text. The value must parse as a URL for `http.get` to succeed, which does not exclude markup in its path or query. |

## Qualified: real exposure, not required red

| Case | Flow | Disposition |
|---|---|---|
| `DEMO-XSS-Q01` | `err.message` in `<pre>` at `:144`, `:158` | The SQL is built from request text and SQLite error messages can quote the offending token, so this is a plausible reflection. It depends on engine error text the source does not show. Review or no record is acceptable. |
| `DEMO-XSS-Q02` | `err.message` at `:245` | Network error text can include the host. Same disposition. |
| `DEMO-XSS-Q03` | `${user.name/role/email}` at `:131` | The columns have no request write, but `POST /login` is SQL-injectable, so a `UNION` could supply the row. That is a chain from the SQL injection, not a stored path. Review. |

## Not vulnerable (must not be red)

| Case | Flow | Why |
|---|---|---|
| `DEMO-XSS-N01` | `${data.replace(/</g, "&lt;")}` in `<pre>` at `:238` | The remote body has `<` replaced in an HTML text context, so no tag can open. |
| `DEMO-XSS-N02` | `GET /admin/users` table at `:280` | The `users` columns are only written by literal seed SQL. Raw rendering is poor practice, but no request write exists. A stacked-query chain through `DELETE /admin/users/:id` is a SQL injection claim. |
| `DEMO-XSS-N03` | `GET /api/users/:id`, `GET /api/notes/:id`, `/internal/config` | `res.json` output is not an HTML sink. |
| `DEMO-XSS-N04` | `GET /`, `/login`, `/fetch`, failed-login page | Constant HTML with no source. |

## SQL injection (reviewed 2026-11-07, before implementation)

`db` is a sql.js `Database`. `db.prepare`, `db.run` and `db.exec` take executable SQL text as their first
argument, and `db.run` executes every statement in that text. `queryAll(sql)` passes its parameter to
`db.prepare`, and `queryOne` calls `queryAll`. None of the routes below validates or converts its input.

| Case | Entry | Source → sink | Why |
|---|---|---|---|
| `DEMO-SQL-01` | `POST /login` (README) | `email`, `password` → template (`:126`) → `queryOne` → `db.prepare` (`:46`) | Quoted interpolation; a quote changes the statement. |
| `DEMO-SQL-02` | `GET /search` (README) | `req.query.q` → `LIKE '%${q}%'` (`:156`) → `queryAll` → `db.prepare` (`:46`) | Same, inside a `LIKE` string. |
| `DEMO-SQL-03` | `GET /api/users/:id` | `req.params.id` → unquoted `WHERE id = ...` (`:254`) → `db.prepare` (`:46`) | Route parameter is a string; unquoted numeric position. |
| `DEMO-SQL-04` | `GET /api/notes/:id` | `req.params.id` → unquoted `WHERE id = ...` (`:264`) → `db.prepare` (`:46`) | Same. |
| `DEMO-SQL-05` | `DELETE /admin/users/:id` | `req.params.id` → `db.run` (`:291`) | Same, and `db.run` runs stacked statements. |

| Control | Why it is not SQL injection |
|---|---|
| `DEMO-SQL-N01`, `POST /notes` (`:208`) | Literal SQL with `?` placeholders; `title` and `body` are bound values. |
| `DEMO-SQL-N02`, `GET /notes`, `GET /admin/users`, seed SQL | Literal SQL with no request data. |

Other README categories (SSRF, IDOR, missing admin authorization) are out of scope here.
