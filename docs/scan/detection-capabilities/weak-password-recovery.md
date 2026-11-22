# Weak password recovery

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/account-security.md) · [CWE-640](https://cwe.mitre.org/data/definitions/640.html) · [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html)

Code Scan reports a generated recovery secret that is mailed to a recipient the request
controls beyond what a check covered, or a guessable secret behind a stored-field check.
The scanner records the secret source, the stored field, the mail recipient and its
origin, and the checks that tied the recipient to the account. Select the family with
`--only-family account`.

A confirmed record is `weak-password-recovery`.

## What is reported

| Recipient origin | `recipient_validated` | Reported |
| --- | --- | --- |
| A stored field of the looked-up account | — | No record. This is the correct shape |
| The scalar request value that was the lookup criterion | `full` | Yes |
| A request value used as an array (iterated, spread, passed to an `array` parameter) while the lookup read one element | `partial`, with both use sites | Yes |
| A request value with no lookup on the path | `none` | Yes |
| The stored address, with a weak secret compared by a `secret_check` | `full` | Yes |

| Secret source | `secret_strength` |
| --- | --- |
| `random_bytes`, `random_int`, `openssl_random_pseudo_bytes`, `Uuid::v4`, `ByteString::fromRandom`, `TokenGeneratorInterface::generateToken` | `csprng` |
| `uniqid`, `mt_rand`, `rand`, `lcg_value`, `microtime`, `time` | `weak` |
| A value computed from one of them, such as `bin2hex`, `base64_encode`, `md5`, `sha1`, `hash` or a string function | The source's strength |

Mail sinks are Symfony Mailer (`to`, `addTo`, `cc`, `addCc`, `bcc`, `addBcc` recipients;
`html`, `text`, `subject`, `context` content; `MailerInterface::send` and
`TransportInterface::send`) and PHP `mail()`. A secret passed through
`UrlGeneratorInterface::generate` or `generateUrl` keeps its provenance.

## Recorded and decidable

The secret and its strength, the stored field (census role `recovery_secret` when a
`secret_check` compares it), the recipient and content operands, the recipient's origin,
`recipient_validated`, `recipient_count` and the use sites.

## Recorded in Review

No gap is specific to this claim. A mail sent through a client that is not modeled makes no
record.

## Not recorded

A mail with no generated secret in its content. Host-header poisoning of an absolute
link, token lifetime and token reuse. Symfony Notifier, Messenger-dispatched mail and
third-party mail SDKs. Mail content is not a rendering, header-injection or request sink.

## Remediation

Mail the secret only to the address stored for the account, generate it with
`random_bytes`, and accept a scalar identifier from the request, not an array.
