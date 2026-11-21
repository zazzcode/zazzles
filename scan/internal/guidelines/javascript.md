id: javascript
version: 5
languages: javascript, typescript

# JavaScript and TypeScript analysis guidelines

TypeScript types are not runtime validation. The same rules apply to `.js`, `.jsx`, `.ts`, and `.tsx`.

## Posture

Report a confirmed injection and weak or poor practice. An agent can harden both cheaply. Do not treat a finding as out of scope only because exploitability is unproven.

## Validation

Restrict each field as far as its business requirement allows. A missing check is insufficient. A check that only shows the value is a string, a number, or shorter than a limit is insufficient when a tighter check would still be valid input. Middleware counts only when its body shows the check. A function name, a comment, or a call whose body is not shown is not validation.

## Free text

Comments, messages, descriptions, reviews, feedback, notes, and similar fields may contain any character. Do not require an allow-list for them. The injection control is the sink.

## Sinks

Do not build a query, update, or insert by concatenation, template interpolation, or a `$where` string. Bind the value with the driver's parameter API. A bound value is sufficient protection for statement structure even when validation is weak. A type or length check does not make an interpolated statement safe. Logging a SQL-looking string is not a query. `Array.find` is not a NoSQL query.

## Logging

Do not write credentials or personal data into logs. A credential is a password, token, API key, session cookie, `Authorization` header value, or one-time code; personal data identifies or describes a person. Log a non-revealing fact instead: presence, length, whether a value matched, or a non-reversible identifier. Log an allowlist of fields, never a whole request body, query, or header set. Do not send credentials in URL query strings: request logging such as morgan's predefined formats records the full URL. A logger counts only when its binding is shown; a local object named `logger` is not a logger. Redaction counts only when its effect is shown and it runs before the emission. Constant messages, startup banners, ports, and server-side error stacks without sensitive request data are not leaks.

## Do not claim

Do not invent a guard, a binding, or a branch that the evidence does not show. Unknown middleware and unknown custom checks stay uncertain.

## Evidence and human-readable results

Keep input validation separate from SQL and NoSQL operation protection. Describe what the code does,
which field or argument is involved, which checks were observed, and what remains unverified.
A query-pattern match is not a confirmed injection. An ORM search value containing interpolation is
not necessarily executable SQL; establish the library behavior before claiming injection.
A NoSQL document accepting a value is not automatically operator injection; inspect its slot, type,
permitted keys, and driver behavior. A numeric conversion or character filter must be assessed on the
actual path, not dismissed by name. No validator identified in a bounded slice does not establish that
all paths lack validation. Use NoSQL as one word. Report uncertainty explicitly rather than presenting
an internal “candidate” label as the human explanation.

## Cross-site scripting

Judge one source-to-rendering flow in its actual browser context. Raw HTML construction is poor
practice when untrusted data reaches it without appropriate encoding or effective sanitization.
HTML entity encoding protects HTML text and quoted non-active attributes; it does not establish
safe JavaScript, URL schemes, event-handler content, unquoted attributes or template source code.
Use escaped templates and text APIs for plain content. Rich HTML requires a verified maintained
sanitizer before every sink. Imported library identity, actual version, options and ordering matter;
a sanitizer name or an obsolete sanitize option alone does not establish protection. A cookie value is request input the client sends, like a query or form field: a raw cookie value rendered into markup is a supported source path. Whether an attacker can set another user's cookie is a delivery question the scanner does not establish; it alone does not make exposure unknown.

Stored claims require matching write/read storage identity and field evidence. API JSON alone is
not an HTML rendering sink. Browser sources and DOM/framework sinks require their own entry and
binding evidence; Angular's default sanitization is distinct from an explicit trust bypass.
Use xss-use-v1 questions for output context, encoding adequacy, sanitizer effectiveness, all-path
protection and exposure. Missing/contradictory evidence stays Review. A red static XSS result requires
complete evidence and consistent XSS-specific answers; a database-injection judgment is insufficient.
