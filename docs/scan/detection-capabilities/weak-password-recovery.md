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

| Secret source | `secret_strength` | `secret_bits` |
| --- | --- | --- |
| `random_bytes(n)`, `openssl_random_pseudo_bytes(n)` | `csprng` | `8n` when `n` is a literal, otherwise `unknown` |
| `random_int(a, b)` | `csprng` | `log2(b - a + 1)`, rounded down to one decimal, when both bounds are literals |
| `Uuid::v4` | `csprng` | `122` |
| `ByteString::fromRandom(len[, alphabet])` | `csprng` | `len * log2(alphabet size)`, default alphabet size 62, when the arguments are literals |
| `TokenGeneratorInterface::generateToken` | `csprng` | `unknown` |
| `uniqid`, `mt_rand`, `rand`, `lcg_value`, `microtime`, `time` | `weak` | `unknown` |

`bin2hex` and `base64_encode` keep the bits. `md5` and `sha1` cap them at 128 and 160.
`hash` and `hash_hmac` with a literal `sha256`, `sha384` or `sha512` cap them at 256, 384
or 512; any other literal algorithm leaves the bits as they are. `substr` with a literal
length over a `bin2hex` or `base64_encode` value caps them at `len*4` or `len*6`.
Concatenating two secrets adds the counts. A secret joined with a non-secret keeps its
count. Any other call leaves the bits `unknown` unless the secret is returned unchanged.
The source's strength is kept through all of these.

Mail sinks are Symfony Mailer (`to`, `addTo`, `cc`, `addCc`, `bcc`, `addBcc` recipients;
`html`, `text`, `subject`, `context` content; `MailerInterface::send` and
`TransportInterface::send`) and PHP `mail()`. A secret passed through
`UrlGeneratorInterface::generate` or `generateUrl` keeps its provenance.

## Recorded and decidable

The secret, its strength and `secret_bits`, the stored field (census role `recovery_secret` when a
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
