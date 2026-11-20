id: python
version: 3
languages: python

# Python analysis guidelines

These analysis guidelines apply to Python route, SQL, logging, rendering and outbound evidence.

## Posture

Report a confirmed injection and weak or poor practice. An agent can harden both cheaply. Unproven exploitability does not remove the finding.

## Validation

Restrict each field as far as its business requirement allows. A missing check alone does not establish a business requirement or a validation defect. Assess required presence, type, format, range and other constraints only when the supplied code or explicit scan check establishes that policy. Unknown business requirements stay uncertain. A type or length check does not replace sink-specific protection. A name, a comment, or an unshown helper is not validation.

## Free text

Comments, messages, descriptions, reviews, feedback, and notes may contain any character. Do not require an allow-list. The injection control is the sink.

## Sinks

Do not build SQL or NoSQL text with f-strings, `%` formatting, `+`, or `format`. Pass values as DB-API parameters. A parameter is sufficient protection for statement structure even when validation is weak. A type or length check does not make a formatted statement safe.

## Do not claim

Do not invent a guard, a parameter binding, or a branch that the evidence does not show.

## Rendering

Flask string returns are HTML unless an explicit response contract says otherwise. JSON is not an
HTML sink. Jinja autoescaping protects substituted variables in supported contexts; it does not
escape input that was interpolated into template source before compilation. Safe/Markup bypasses
and disabled autoescape need separate analysis. HTML escaping does not establish script/URL safety. A cookie value is request input the client sends, like a query or form field: a raw cookie value rendered into markup is a supported source path. Whether an attacker can set another user's cookie is a delivery question the scanner does not establish; it alone does not make exposure unknown.

## Logging

Identify actual credential or personal-data content, its source and logger binding. A password/email
field name is a hint, not proof. A source-backed literal email or verified database field can also
be a personal-data source. Whole containers and unknown transformations remain uncertain. Length,
presence and comparison facts do not expose content; do not infer remote log retention/exposure.
