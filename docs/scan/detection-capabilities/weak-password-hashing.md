# Weak password hashing

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/account-security.md) · [CWE-916](https://cwe.mitre.org/data/definitions/916.html)

Code Scan reports a password stored as one fast digest. A password is established by
evidence, never by a variable name. Select the family with `--only-family account`.

A confirmed record is `weak-password-hash`.

## What is reported

| Basis | Reported when |
| --- | --- |
| `credential_field` | `md5`, `sha1`, `crc32`, or `hash`/`hash_hmac` with a literal algorithm is written to a census `credential` field |
| `hasher_class` | A class implementing `PasswordHasherInterface` or `LegacyPasswordHasherInterface` returns such a digest from `hash()` |
| `configuration` | `security.password_hashers` selects `md5`, `sha1`, `sha256`, `sha512` or `plaintext`, or an `id` naming a `hasher_class` record. The record is at the configuration line |
| `sql_credential_column` | Plain PHP: a digest of a request value reaches a SQL column that a `SELECT` compares |

The algorithm, `salted` (a concatenation with another non-literal value) and `iterated`
(`no` for one call) are recorded. A salt does not make a fast digest adaptive.

## Recorded and decidable

The digest, its algorithm, the basis and its evidence, and the census field.

## Recorded in Review

| Gap | Why it is in Review |
| --- | --- |
| `password_digest_unmodeled` | `crypt` or `hash_pbkdf2`: their parameters are not modeled |

## Not recorded

`password_hash`, `sodium_crypto_pwhash_str`, `UserPasswordHasherInterface::hashPassword`
and a hasher from the factory, which establish a credential field instead. A digest used
as a file name or a cache key. `md5_file`. A hasher class or configuration line in a
project with no entry point. Password policy, `crypt` salt formats, `hash_pbkdf2`
parameter adequacy and pepper handling.

## Remediation

Hash passwords with `password_hash` or a Symfony password hasher with `algorithm: auto`,
and rehash stored digests when each user next signs in.
