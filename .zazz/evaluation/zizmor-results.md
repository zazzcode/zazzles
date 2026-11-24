# zizmor results on four samples

**2026-11-24.** First run of [zizmor](https://docs.zizmor.sh/) on the four comparison samples.
This document records what the tool reported.

zizmor audits GitHub Actions workflows. Zazzles Code Scan reads application source and excludes
`.github/`, so the two tools do not look at the same files. Nothing below is a miss or a match
for Code Scan. It is coverage Code Scan does not have.

## Tool and rules

| Item | Value |
|---|---|
| zizmor | 1.33.1, Homebrew bottle. The source checkout at `<DEV_ROOT>/scanners/zizmor` (`22b14419`) was not built; no Rust toolchain is installed |
| Rules | zizmor's built-in audits. It loads no external rule pack and none was configured |
| Persona | `regular`, the default. The `pedantic` and `auditor` audits did not run |
| Mode | `--offline`. Audits that query the GitHub API (known-vulnerable actions, impostor commits, reference confusion and similar) did not run |
| Configuration | None. No sample has a `zizmor.yml` |

## Runs

Raw output is under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<sample>/zizmor-20261124-1/`
(`results.json`, `results.sarif`, `results.plain`). Exit status 14 is zizmor's status for
"findings up to high severity". Each sample's tracked files were unchanged after the run.

| Sample | Revision | Workflow files | Findings | High | Medium | Low | Informational | Exit |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| OWASP Juice Shop | `f189f52` | 15 (findings in 14) | 108 | 28 | 58 | 20 | 2 | 14 |
| DVWA | `a1978a2` | 5 | 28 | 15 | 8 | 5 | 0 | 14 |
| vuln-nextjs | `f5d47de` | 1 | 4 | 2 | 2 | 0 | 0 | 14 |
| vuln-symfony | `086f81f` | 0 | — | — | — | — | — | 3 |

vuln-symfony has no `.github/workflows` directory. zizmor stopped with "no inputs collected".

## Findings by audit

| Audit | Severity | Juice Shop | DVWA | vuln-nextjs |
|---|---|---:|---:|---:|
| [`excessive-permissions`](https://docs.zizmor.sh/audits/#excessive-permissions) | Medium | 31 | 7 | 1 |
| [`artipacked`](https://docs.zizmor.sh/audits/#artipacked) (checkout keeps credentials) | Medium or Low | 27 | 5 | 1 |
| `adhoc-packages` | Low | 19 | 0 | 0 |
| [`unpinned-uses`](https://docs.zizmor.sh/audits/#unpinned-uses) | High | 7 | 13 | 2 |
| [`cache-poisoning`](https://docs.zizmor.sh/audits/#cache-poisoning) | High | 10 | 0 | 0 |
| [`template-injection`](https://docs.zizmor.sh/audits/#template-injection) | High | 9 | 2 | 0 |
| [`dangerous-triggers`](https://docs.zizmor.sh/audits/#dangerous-triggers) | High | 2 | 0 | 0 |
| `superfluous-actions` | Informational | 2 | 0 | 0 |
| `archived-uses` | Medium | 1 | 0 | 0 |
| `overprovisioned-secrets` | Medium | 0 | 1 | 0 |

Juice Shop's findings concentrate in `ci.yml` (47) and `release.yml` (15).

## Limits of this record

- No finding has been reviewed against the workflow source.
- Offline mode leaves out every audit that needs the GitHub API, so these counts are a floor
  for what zizmor reports online.
- These are workflow defects of the samples' own repositories. They say nothing about the
  vulnerable application code the samples exist to demonstrate.
