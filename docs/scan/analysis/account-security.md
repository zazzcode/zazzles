# Account security

Zazzles emits three kinds in the `account` family: `account_enumeration_candidate`,
`recovery_delivery_candidate` and `password_hash_candidate`. A judged scan uses protocol
`account-components-v2`, which asks each kind its own questions. Contracts:
`api.symfony-mailer-v1`, `api.php-mail-v1`, `api.php-password-digest-v1`. Enumeration has
no operation contract.

## Rules

- A response is compared with the other response, never with a list of phrases. The
  scanner records the two branches and does not read meaning into the text.
- A password is established by a census `credential` field, a password-hasher class or
  security configuration. A variable named `$password` establishes nothing in a Symfony
  project.
- Mail content is a delivery sink for the recovery claim only. It is not an XSS, header or
  request sink.
- A request value used as an array can name many recipients. A check of one element
  covers only that element.

## Questions and status

| Kind | Question | Answers |
| --- | --- | --- |
| Enumeration | `response_difference` | `distinguishable`, `indistinguishable`, `unknown` |
| Enumeration | `existence_disclosure` | `discloses`, `does_not_disclose`, `unknown` |
| Recovery | `recipient_control` | `request_controlled`, `account_bound`, `unknown` |
| Recovery | `validation_coverage` | `none`, `partial`, `complete`, `unknown` |
| Recovery | `secret_quality` | `adequate`, `weak`, `unknown` |
| Hashing | `password_input` | `password`, `not_password`, `unknown` |
| Hashing | `hash_strength` | `fast_digest`, `adaptive`, `unknown` |

Enumeration is confirmed for `distinguishable` and `discloses`, protected for
`indistinguishable` or `does_not_disclose`. `indistinguishable` contradicts recorded lists
that differ in status or redirect target. `response_unresolved` and the entry-access gaps
block it.

Recovery is confirmed for `request_controlled` with coverage `none` or `partial`, or for
`weak`; protected for `complete` with `adequate`. `complete` contradicts
`recipient_validated` `partial` or `none`, `adequate` contradicts `secret_strength` `weak`
and a known `secret_bits` below 64, `weak` contradicts `secret_strength` `csprng`, and
`account_bound` contradicts a request-value recipient. 64 is the OWASP session-identifier
entropy minimum. Unknown bits add no contradiction.

Hashing is confirmed for `password` and `fast_digest`, protected for `not_password`.
`adaptive` contradicts one call of a fast digest. `password_digest_unmodeled` blocks it.

## Fact codes

| Fact | Values |
| --- | --- |
| `enumeration.lookup` | class, method, criteria fields, lookup and branch evidence |
| `enumeration.found`, `enumeration.not_found` | response lists: `flash`, `body`, `status`, `redirect`, `template`, `exception`, `response_unresolved` |
| `recovery.secret_strength` | `csprng`, `weak` |
| `recovery.secret_bits` | an integer or one decimal place, or `unknown` |
| `recovery.recipient_origin` | `request_value`, `stored_field` |
| `recovery.recipient_validated` | `full`, `partial`, `none` |
| `recovery.recipient_count` | `one`, `request_controlled` |
| `recovery.shape_uses` | the checked element and the array use |
| `recovery.stored_field` | storage key; census role `recovery_secret` when a `secret_check` compares it |
| `password_hash.basis` | `credential_field`, `hasher_class`, `configuration`, `sql_credential_column` |
| `password_hash.algorithm`, `salted`, `iterated` | the digest; `yes` or `no` |

## Bounds

Responses are read straight-line on each side until the action returns; a nested
condition is not entered. Hasher-class and configuration records belong to the entry of
the firewall's `form_login` or `json_login` check path, or to the project's first entry
when no check path resolves. Plain PHP reads literal SQL text; a `SELECT` that compares a
column written from a password hash or digest is a login and records no enumeration.
Timing, rate limits, token lifetime, Notifier and Messenger mail, `crypt` and
`hash_pbkdf2` parameters and password policy are out of scope.
