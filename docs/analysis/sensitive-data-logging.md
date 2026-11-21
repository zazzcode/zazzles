# Sensitive-data logging analysis

A sensitive-data leak requires source evidence identifying a sensitive value (credential or personal
data) and its revealing transfer into a verified log call. Whole-container logging alone is an
observed operation for Review, not an established leak. Evidence MUST distinguish the logging fact
from missing data classification; field names remain hints until their meaning is established.

[Analysis index](README.md) · [Input validation](input-validation.md) · [Calibration](calibration.md) · [Coverage and known gaps](../detection-capabilities/sensitive-data-logging.md)

## What the claim means

A sensitive-data logging finding says that a verified logging operation writes the *content* of a
credential, token, or personal-data value into log output. Logs are copied, retained, and read by
people and systems that should not receive those values. The claim is about one emission and one
value. It is not a judgment of logging in general; useful operational logs should stay.

## Evidence before judgment

Analysis MUST identify the logger binding, the argument that carries the value, the value's source,
the transfers between them, and any reduction or redaction on that path before the call.
Logger-binding evidence retains the original callee text, hash and byte span. Descriptions such as
“global console” do not replace the source excerpt; model projections use the standard comment masking.

- **Binding, not name.** `console.log` counts only when `console` is the global console. A logger
  counts when its binding is created by a supported logging library. A local object named `logger`
  is not a logger. Unsupported libraries remain outside current coverage rather than guessed.
- **Data class, not variable name.** HTTP semantics establish some classes: the `Authorization` and
  `Cookie` request headers carry credentials. A request field key such as `password`, `token`, or
  `email` is a strong hint that still needs judgment. A local variable name alone is never evidence.
- **Content versus derived facts.** Logging a value's length, whether two values matched, or whether
  it is present does not expose its content. Logging any part of the value does.
- **Ordering.** Redaction counts only if it happens before the emission on every path.
- **Unknown transformations.** A call whose effect is not modeled (for example a custom `mask()`
  helper) stays Inconclusive. It is neither assumed to redact nor assumed to leak.

## Rules

- Constant messages, startup banners, documentation URLs, ports, and versions are not leaks.
- A request value without a sensitive-data hint is not a sensitive-data logging claim. Logging
  arbitrary input may raise other concerns (for example log injection), assessed separately.
- Logging a whole request body, query, or header set can include credentials; it needs review
  against what the route actually receives.
- A query string containing credentials is recorded by request-line access logs whose format includes
  the URL (all of morgan's predefined formats do). Evidence that a query field is a credential comes
  from where the route sends it: storing it in a credential attribute or comparing it with a stored
  credential. The route design (credentials in a URL) and the logging both need attention.
- An error stack written to server logs is ordinary operations. Exposing it in an HTTP response is
  a different issue (information disclosure), not this claim.

## Outcomes

- **Finding / soft orange:** a protocol credential's content reaches a verified logger with no
  unresolved transformation. Remove it or log a non-revealing fact instead.
- **Review / soft blue:** a field-name or whole-container hint, or an unresolved transformation.
  Confirm what the value contains and whether redaction applies before changing behavior.
- **Protected / soft green:** only non-revealing derived facts of the hinted value are logged.
- **Finding / soft orange (access log):** request logging registered before the route records the
  URL, and a query field has credential destination evidence. Review if registration is conditional.
- **Finding / soft red:** the logging judgment (data class, content, redaction, exposure) is
  consistent, the logger binding and request source are present, and the answers do not contradict
  the scanner's own non-content facts.

## Judgment questions

When semantic assessment runs, each logging record is asked four questions with fixed choices: the
data class (credential, personal data, other), whether content is exposed, whether effective
redaction runs first, and the overall exposure. A field name alone is a hint, not proof; a mask or
redact function whose body is not shown is Inconclusive. Answers that disagree with each other do
not produce a definitive result.

## Controls

Keep paired cases: authorization header logged versus its presence logged; password logged versus its
length; morgan registered before versus after the route, with and without `:url`; a query field stored
as a password versus an ordinary query field; global versus shadowed `console`; real versus fake logger object; constant versus request
message; masked by an unresolved helper versus unmasked. Positive detection is insufficient when the
paired control is also flagged. See [calibration](calibration.md) for evaluation rules.

## Library contracts

[Node.js console](https://nodejs.org/api/console.html) writes to stdout/stderr.
[winston](https://github.com/winstonjs/winston#creating-your-own-logger) loggers are created with
`createLogger`. [morgan](https://github.com/expressjs/morgan#predefined-formats) predefined formats
include the request URL with its query string.

## Python sources and bindings

The [Python adapter](../python-support.md) supports unshadowed print, imported logging methods and
logging.getLogger objects. Request credentials and personal-data hints retain their exact fields;
whole sessions remain Review. Source-backed literal email and verified database-field/result reads
can also produce logging candidates. Email syntax alone does not establish that a constant address
is private or identifies a person, so literal-address sensitivity remains a blocker. A whole result set does not establish which sensitive fields
it contains. These source kinds are eligible for the same logging questions; a model still must
establish data class, content and lack of effective redaction consistently. Length, presence and
comparison facts are separate from content. Arbitrary request logging is not automatically a PII leak.
