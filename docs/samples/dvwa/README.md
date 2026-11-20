# DVWA (PHP) sample

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json.gz) ·
[SARIF](findings.sarif.gz) · [Provenance](metadata.json) ·
[Detection guide](../../../.zazz/evaluation/dvwa-detection-guide.md) ·
[Results](../../../.zazz/evaluation/command-bypass-support-results.md) ·
[PHP evaluation](../../../.zazz/evaluation/php-support-results.md)

## Current report (2026-11-20, command bypass support)

A full static scan of DVWA revision `a1978a2` with scanner `ea8640a` and OpenAI `gpt-6-luna`
produced 247 records across 174 entries. The report presents 144 Confirmed, 39 practice findings,
46 Review (34 needs-review and 12 needs-evidence), and 18 Protected.

- **Answer key:** all 11 keyed positives are Confirmed, and no protected control is a finding.
- **PC-CMD-02 is Protected.** The four records for `vulnerabilities/exec/source/impossible.php`
  (lines 22 and 26, two entries) were one Confirmed and three Review in the previous report. The
  path now cites the `is_numeric` check and states the characters it accepts, and the question
  asks for command text of the request's choosing. Each record keeps a `Hardening:` note: the
  check still admits a line break.
- **Nothing else moved.** The other 243 records have the same status as the previous report. Only
  the 17 command records have a new request.
- **Usage:** 190 assessments from 187 requests, three shared across equivalent contexts,
  1,645,909 input tokens, zero failures. 57 records stay in Review without a request because
  their blockers have no model-resolvable question. All 190 assessments replayed exactly offline.

The evidence is in the
[command bypass support results](../../../.zazz/evaluation/command-bypass-support-results.md#paid-dvwa-run).

## Previous report (2026-11-20, pre-merge for PR #33)

A full static scan of DVWA revision `a1978a2` with scanner `ebf366a` and OpenAI
`gpt-6-luna` produced 247 records across 174 entries. The report presents 145 Confirmed,
39 practice findings, 49 Review (34 needs-review and 15 needs-evidence), and 14 Protected.

The judge completed 190 assessments from 187 requests, including three assessments shared
across equivalent contexts. The scanner kept 57 records in Review because their blockers
have no model-resolvable question. Provider usage was 1,644,037 input tokens with zero
failures. All 190 assessments replayed exactly offline.

All 11 keyed positives were Confirmed. One protected control, PC-CMD-02 at
`vulnerabilities/exec/source/impossible.php:26`, was a false positive against the key.
The results and release decision are in the [PR evaluation](../../../.zazz/evaluation/judge-request-size-reduction-results.md#pre-merge-dvwa-scan).

## Previous report (2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 174 entries, 240 analysis records: **120 Confirmed, 102 Review, 15 Protected, 2 practice, 1 not applicable**.
- 169 requests, 172 completed assessments (3 shared by equivalent entry contexts), 1,751,729 input tokens. No provider failures. 61 records are not sent because their scanner blocker has no question the model could answer.
- **Answer key:** 9 of 10 expected positives found, 1 Review; no keyed control is a finding.
- **One model-resolved finding:** the medium-level file inclusion `vulnerabilities/fi/index.php:36`. The model cited the chain `$_GET['page']` → two `str_replace` calls → `include`, which the scanner verified. Source review confirms it: `....//` becomes `../`, and absolute paths pass.
- The upload page (`upload/source/low.php`) stays Review: `basename()` blocks path traversal, and its real flaw (any file type) is outside our analyzers.
- No Confirmed record comes only from impossible-level code. The earlier false positive `brute/source/impossible.php:90` (a bound PDO `execute()`) is now Protected: the record carries its prepared SQL text.
- 7 shared-render stored-XSS records exceed the 64KB request limit and stay Review without a request.

## Previous report (published 2026-11-17)

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
before publishing new results. Limits recorded in the 2026-11-17 run: cross-entry
`$_SESSION` write ordering and the `bac_log` `NOW()` column keep three stored reads
origin-unresolved (Review); the four wire-limited stored-XSS render records; captcha's UPDATE
interpolates `md5`-hashed and session-sourced operands (candidate, not a raw request→SQL path);
upload's destination is basename-guarded at every level (Protected/Review, not Confirmed).
See [PHP support](../../php-support.md) for the adapter's full bounds.
