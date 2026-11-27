# VulnerableSymfony (PHP, Symfony) sample

[All samples](../README.md) · [HTML](https://zazzcode.github.io/zazzles/vuln-symfony/findings.html) · [JSON](findings.json) ·
[SARIF](findings.sarif) · [Provenance](metadata.json) ·
[Detection guide](../../../.zazz/evaluation/vuln-symfony-detection-guide.md) ·
[Results](../../../.zazz/evaluation/symfony-results.md)

[VulnerableSymfony](https://github.com/Secureaks/VulnerableSymfony) is a deliberately
vulnerable blog built by Secureaks on Symfony 6.4, Doctrine ORM and Twig. Its README lists 21
defects. This report is a static scan of the source. It is not a runtime test.

## Licence of the source excerpts

The report quotes lines of the application's source as evidence. That source is the work of
Secureaks and is licensed under
[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). The excerpts in
`findings.html`, `findings.json` and `findings.sarif` stay under that licence: give credit,
do not use them commercially, and share adaptations under the same terms. The full text is in
[UPSTREAM-LICENSE.txt](UPSTREAM-LICENSE.txt). The excerpts are unchanged apart from the
scanner's selection of lines. Secureaks does not endorse this project or this report.

## Current report (2026-11-27, Google Gemini)

A full scan of revision `086f81f` with scanner `81d4731` (`stage` through PR #56) and Google
Gemini `gemini-decision-1` produced 84 records across 34 entries. The report presents
**55 Confirmed, 1 practice finding, 25 Protected and 3 Review**. [Run record](../../../.zazz/evaluation/gemini-sample-runs-20261127.md#vulnerablesymfony)

- **Answer key:** all 30 required positives are found: 29 Confirmed and one stored XSS in
  `templates/blog/post.html.twig:37` (`SYM-XSS-03`) as a practice finding. No control is a finding.
- **New finding:** `config/packages/security.yaml:5` selects the MD5 password hasher. It is real
  and the same weakness as the keyed `SYM-HASH-01`, reported at its configuration.
- **Review:** three records, one stored XSS, one path traversal and one deserialization record
  that lack evidence the claim needs. The previous report had seven.
- **Usage:** 84 completed assessments, 355,480 input tokens, zero failures.

| Finding type | Confirmed | Protected | Review |
|---|---:|---:|---:|
| SQL injection | 2 | 1 | 0 |
| Cross-site scripting (reflected, stored, DOM) | 5, and 1 practice | 15 | 1 |
| Command injection | 3 | 0 | 0 |
| Path traversal | 4 | 0 | 1 |
| Template injection | 1 | 0 | 0 |
| Unrestricted upload | 1 | 0 | 0 |
| Server-side request forgery | 3 | 0 | 0 |
| Unsafe deserialization | 11 | 0 | 1 |
| Input validation | 2 | 1 | 0 |
| Information exposure | 1 | 0 | 0 |
| Mass assignment | 1 | 0 | 0 |
| Missing authorization | 6 | 9 | 0 |
| Address-based access | 3 | 0 | 0 |
| Account enumeration | 3 | 0 | 0 |
| Weak password recovery | 1 | 0 | 0 |
| Weak password hash | 6 | 0 | 0 |
| Insecure configuration | 4 | 0 | 0 |

A record can carry more than one type, so the columns add up to more than the record counts.

## Previous report (2026-11-23, gpt-6-luna)

A full scan of revision `086f81f` with scanner `8d97b93` and OpenAI `gpt-6-luna` produced 84
records across 34 entries. The report presents **55 Confirmed, 22 Protected and 7 Review**.

- **Answer key:** all 30 required positives are Confirmed, and no control is a finding.
- **README coverage:** 20 of the 21 listed defects have a Confirmed finding. The remaining
  one, missing access control on `/user/delete/{user}`, is not in the source at this
  revision. The delete action sits under the admin access rule and is reported as Protected.
  The [closing table](../../../.zazz/evaluation/symfony-results.md#closing-table--sample-readme-21-entries)
  maps each entry to its finding.
- **Beyond the README:** disabled CSRF protection and a session cookie readable by scripts
  in `config/packages/framework.yaml` are Confirmed.
- **Usage:** 84 requests, 335,720 input tokens, zero failures.

| Finding type | Confirmed | Protected | Review |
|---|---:|---:|---:|
| SQL injection | 2 | 1 | 0 |
| Cross-site scripting (reflected, stored, DOM) | 6 | 11 | 5 |
| Command injection | 3 | 0 | 0 |
| Path traversal | 4 | 0 | 1 |
| Template injection | 1 | 0 | 0 |
| Unrestricted upload | 1 | 0 | 0 |
| Server-side request forgery | 3 | 0 | 0 |
| Unsafe deserialization | 11 | 0 | 1 |
| Input validation | 2 | 1 | 0 |
| Information exposure | 1 | 0 | 0 |
| Mass assignment | 1 | 0 | 0 |
| Missing authorization | 6 | 9 | 0 |
| Address-based access | 3 | 0 | 0 |
| Account enumeration | 3 | 0 | 0 |
| Weak password recovery | 1 | 0 | 0 |
| Weak password hash | 5 | 1 | 0 |
| Insecure configuration | 4 | 0 | 0 |

A record can carry more than one type, so the columns add up to more than the record counts.

## What the report does not cover

- Committed secrets in `.env` and other files are outside the scanner's scope. The scanner
  reads only `APP_ENV` and `APP_DEBUG` from an environment file, and no other value from it
  is in this report.
- Voters, custom authenticators, Symfony Form types and serializer groups are not modeled.
- The seven Review records are five stored XSS, one path traversal and one deserialization
  record that lack evidence the claim needs. Each one states its gap.

See [Symfony coverage](../../scan/detection-capabilities/symfony.md) for the full list.
