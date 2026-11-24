# Zazzles Code Scan compared with Semgrep CE, Bearer and zizmor

**2026-11-24.** A short summary. The full tables, with every known vulnerability as a row and
every false positive listed, are in the
[scanner comparison](docs/scan/scanner-comparison.md). How the numbers were produced is in the
[run record](.zazz/evaluation/comparison-results.md).

## Result

Four intentionally vulnerable applications, scored against their known vulnerabilities.

| | Code Scan | Bearer CLI | Semgrep CE |
|---|---:|---:|---:|
| Known vulnerabilities found, of 96 | 92 | 33 | 19 |
| False positives on known-safe code | 3 | 21, and two noisy rules | 7 |

| Application | Known | Code Scan | Bearer | Semgrep CE |
|---|---:|---:|---:|---:|
| OWASP Juice Shop (TypeScript, Express, Angular) | 42 | 38 | 15 | 10 |
| vuln-nextjs (Next.js) | 13 | 13 | 7 | 2 |
| DVWA (PHP) | 11 | 11 | 6 | 5 |
| vuln-symfony (PHP, Symfony) | 30 | 30 | 5 | 2 |

zizmor audits GitHub Actions workflow files. It reported 140 findings in the three applications
that have workflows. Code Scan does not read workflow files, so that is coverage it lacks, not
a head-to-head result.

## Where Code Scan is ahead

- **Flows across files and through storage.** The other two found 6 of 18 XSS cases between
  them; most of the rest pass through a database or from backend to frontend.
- **Access rules.** Neither other scanner found any of the 22 missing-authorization,
  mass-assignment, account-enumeration or NoSQL cases.
- **Noise.** Bearer reported 675 results on Juice Shop, 541 of them from two rules that are
  almost all false or in test files. Code Scan reported 45 confirmed findings there.

## Where Code Scan is behind

- **Three Juice Shop vulnerabilities left in Review** that Semgrep CE or Bearer finds: the
  profile-image SSRF, the `eval` in the profile page, and the null-byte file read.
- **Committed secrets.** Both other scanners found the hardcoded JWT key. Code Scan has no
  analyzer for it.
- **Reads of another user's record.** Viewing another user's basket is not reported.
- **Three false positives:** liking a review, a `.well-known` directory listing, and
  vuln-nextjs's safe redirect control.
- **GitHub Actions workflows** are not read.

## Read the numbers with these in mind

- The answer keys were written for Code Scan's own evaluation and favor the classes it
  analyzes. Only the Juice Shop key was widened with what the other scanners surfaced, and all
  four of Code Scan's misses appeared there.
- The DVWA key covers its low security level only. About 190 results of the other scanners on
  DVWA and vuln-symfony were counted as unreviewed, not as false positives.
- Semgrep CE analyzes one file at a time; its cross-file engine is a paid product and was not
  run. Bearer Pro was not run.
- These are development reference applications. This is not a general accuracy claim.

## What changed to get here

Branch 1 of the hardening lane extended five existing analyzers (information exposure, mass
assignment, missing authorization, account security, insecure configuration) to Express
applications in JavaScript and TypeScript, and built the missing upload producer. Juice Shop
went from 22 confirmed findings to 45. No analyzer was added.

## Next improvements to the existing analyzers

Specified in
[hardening 3](.zazz/specifications/juiceshop-nextjs-hardening-3.md). No new analyzer.

1. Close the three Juice Shop misses.
2. Resolve the handler and middleware forms that keep path and query records in Review.
3. Report reads of a record another user owns.
4. Remove the three false positives.
