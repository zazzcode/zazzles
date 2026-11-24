# Zazzles Code Scan compared with Semgrep CE, Bearer and zizmor

**2026-11-24.** A short summary. The full tables, with every known vulnerability as a row and
every false positive listed, are in the
[scanner comparison](docs/scan/scanner-comparison.md). How the numbers were produced is in the
[run record](.zazz/evaluation/comparison-results.md).

## Result

Four intentionally vulnerable applications, scored against their known vulnerabilities.

| | Code Scan | Bearer CLI | Semgrep CE |
|---|---:|---:|---:|
| Known vulnerabilities found, of 97 | 95 | 33 | 19 |
| False positives on known-safe code | 4 | 21, and two noisy rules | 7 |

| Application | Known | Code Scan | Bearer | Semgrep CE |
|---|---:|---:|---:|---:|
| OWASP Juice Shop (TypeScript, Express, Angular) | 43 | 41 | 15 | 10 |
| vuln-nextjs (Next.js) | 13 | 13 | 7 | 2 |
| DVWA (PHP) | 11 | 11 | 6 | 5 |
| vuln-symfony (PHP, Symfony) | 30 | 30 | 5 | 2 |

zizmor audits GitHub Actions workflow files. It reported 140 findings in the three applications
that have workflows. Code Scan does not read workflow files, so that is coverage it lacks, not
a head-to-head result.

## Where Code Scan is ahead

- **Flows across files and through storage.** The other two found 6 of 18 XSS cases between
  them; most of the rest pass through a database or from backend to frontend.
- **Access rules.** Neither other scanner found any of the 23 missing-authorization,
  mass-assignment, account-enumeration or NoSQL cases.
- **Noise.** Bearer reported 675 results on Juice Shop, 541 of them from two rules that are
  almost all false or in test files. Code Scan reported 50 confirmed findings there.

## Where Code Scan is behind

- **One Juice Shop row left in Review** that Semgrep CE or Bearer reports: the null-byte file
  read, which on source review is a file-type allow-list bypass and not a path traversal. The
  profile-image SSRF is reported as a practice finding rather than a confirmed one.
- **Committed secrets.** Both other scanners found the hardcoded JWT key. Code Scan has no
  analyzer for it.
- **Four false positives:** two records of liking a review, a `.well-known` directory listing,
  and vuln-nextjs's redirect control. The redirect control is counted as its lab labels it,
  although its guard admits `/\host`. A fifth, a generated delete that an explicit handler
  answers first, was fixed after the judged run and is no longer recorded.
- **GitHub Actions workflows** are not read.

## Read the numbers with these in mind

- The answer keys were written for Code Scan's own evaluation and favor the classes it
  analyzes. Only the Juice Shop key was widened with what the other scanners surfaced, and all
  of Code Scan's misses appeared there.
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

[Hardening 3](.zazz/specifications/juiceshop-nextjs-hardening-3.md) then improved the existing
analyzers again, with no new analyzer:

- A read of a record another user owns is reported. The basket read is Confirmed.
- The profile-image SSRF is sent to the model and reported as a practice finding.
- An update record says whether it writes a request value, and a directory-listing record says
  what the directory holds.

It did not reach four of its goals. Each is recorded with its evidence and the decision it
needs in the [results](.zazz/evaluation/juiceshop-hardening-results.md#hardening-3):

1. The `eval` in the profile page stayed in Review under the code policy. The owner then
   decided that the model's answer settles whether a condition on the path restricts the
   operand; with that change the row is Confirmed.
2. The null-byte file read stays in Review. On source review it cannot leave its directory; what
   it defeats is a file-type allow-list.
3. The like-counter and `.well-known` false positives remain, and a second like record appeared.
4. vuln-nextjs's redirect control is still reported. Its guard is bypassable by `/\host`.
