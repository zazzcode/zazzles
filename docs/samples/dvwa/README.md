# DVWA (PHP) sample

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json.gz) ·
[SARIF](findings.sarif.gz) · [Provenance](metadata.json) ·
[Detection guide](../../../.zazz/evaluation/dvwa-detection-guide.md) ·
[Results](../../../.zazz/evaluation/php-support-results.md)

## Current report (published 2026-11-17)

Fresh full-tree static analysis of [DVWA](https://github.com/digininja/DVWA) at revision
`a1978a2` (full pin in metadata) with the plain-PHP adapter: server-mapped file entries,
superglobal input facts, include dispatch, and the SQL/command/XSS/path/code/redirect families.
The reference checkout stayed clean during this evaluation.

- 174 entries, 296 analysis records: **107 Confirmed, 39 Review (30 needs-evidence, 9 stored-XSS
  practice), 150 practice, 9 Protected**.
- 292 completed OpenAI `gpt-6-luna` assessments within the 300-request cap (2,417,921 input
  tokens); 4 shared-render-sink stored-XSS records exceed the 64KB request wire limit and stay
  needs_review with byte accounting retained. No provider failures.
- Every cataloged required positive of the
  [detection guide](../../../.zazz/evaluation/dvwa-detection-guide.md) is Confirmed — sqli,
  sqli_blind, brute, csrf, exec, xss_r, xss_s (INSERT construction), fi, open_redirect and the
  view_help eval — and no record whose dependency sources are exclusively impossible-level is red.
  Impossible-level controls are sibling paths inside dispatch-merged records with their own
  recorded protections, plus standalone Protected/Review outcomes (upload basename control,
  PDO prepare/bind, escapeshellarg).
- The final run `run-1226915911` replayed 292/292 exactly offline.

Publication replaces only the JSON root with the public sample label and exports HTML/SARIF
offline; the complete JSON/SARIF are stored gzip to stay below hosting file-size limits.
Metadata records the original JSON hash and assessment usage. No target execution; static source
judgments, not runtime exploit confirmation or exhaustive recall. Follow the
[sample reference policy](../reference-policy.md) before reusing these reports.

## Living expectations and limits

The source of truth is the pinned DVWA revision; re-review changed modules and re-pin the guide
before publishing new results. Bounded, honestly-reported limits in this run: cross-entry
`$_SESSION` write ordering and the `bac_log` `NOW()` column keep three stored reads
origin-unresolved (Review); the four wire-limited stored-XSS render records; captcha's UPDATE
interpolates `md5`-hashed and session-sourced operands (candidate, not a raw request→SQL path);
upload's destination is basename-guarded at every level (Protected/Review, not Confirmed).
See [PHP support](../../php-support.md) for the adapter's full bounds.
