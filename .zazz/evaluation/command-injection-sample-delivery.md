# Command Injection Analyzer: final samples and documentation delivery

This is the artifact-delivery requirement linked by the
[implementation contract](../specifications/command-injection.md), not a claim of completed scans.

## Four full evaluated apps

Juice Shop, VulnPy, nodejs-goof and vulnerable-typescript-app each require a final full judged scan
using the final scanner source and the selected OpenAI Decisions gpt-6-luna model. Retain the
independent source references and classification controls from the contract. The TypeScript
[expected-vulnerability guide](vulnerable-typescript-app-detection-guide.md) identifies exact source
locations; only its command-positive case expands this analyzer's mandatory positive set.

## Twelve reports and GitHub samples

- Deliver findings.html, findings.json and findings.sarif for each app: twelve final review artifacts.
- Curate the final source-consistent canonical JSON into
  `docs/samples/{juice-shop,vulnpy,nodejs-goof,vulnerable-typescript-app}/findings.json`.
  Preserve the previous reports as versioned run artifacts or Git history; do not overwrite raw runs.
- Use the implemented scanner and existing offline refresh workflow:

```bash
python3 docs/samples/refresh.py --scan <FINAL_SCAN_BINARY> \
  --sample juice-shop --sample vulnpy --sample nodejs-goof --sample vulnerable-typescript-app
```

- The refresh writes matching canonical HTML and SARIF without new model calls. Verify that public
  JSON/HTML/SARIF statuses, source locations and counts match the final live reports after deliberate
  root normalization. It is not a substitute for the required new judged scans.
- Update each sample README/metadata with the actual pin, scanner/source digest, evaluation mode,
  model/protocol, date, scope, outcome counts, artifact links and coverage limits. Retain licenses and
  attribution. Do not publish provider credentials, unrelated real secrets, private home paths or raw sensitive transport diagnostics.
- Update root README's sample table, `docs/samples/README.md` and `docs/samples/index.html` for all
  four apps, including VulnPy. Descriptions must summarize the refreshed results, including command
  findings where actually detected; never promise that every expected family is implemented.
- Commit/push these curated artifacts with the implementation feature branch under the user's
  request for updated GitHub samples. Existing human PR/merge rules still apply. GitHub Pages copies
  update through the existing stage deployment after human integration; do not claim that pushing a
  feature branch refreshed the hosted Pages site or merge integration to publish it.

## Final implemented-state documentation gate

Before implementation is declared ready for merge, update the root README, `.zazz/architecture.md`,
`.zazz/architecture/analysis-packs.md`, `.zazz/project.md`, `.zazz/project/01-functionality.md`,
`.zazz/project/implementation-plan.md`, `docs/technical-approach.md`, public command-analysis guide,
and agent orientation to describe the delivered Command Injection Analyzer and its actual tested
limits. Remove stale “next planned capability”, “implementation pending” and “next new analyzer”
statements about it from current-state sections/indexes; preserve dated historical records and
locked predecessor specifications. Mark the command checklist complete only with acceptance
evidence, and make Harden XSS analyzers the next unfinished analyzer task in the established order.

The implementation completion report must link the twelve final reports and the GitHub-ready
sample files, reference the actual commit/push, summarize expected versus detected command cases,
and distinguish remaining unrelated analyzer coverage limits. Test JSON parsing, HTML rendering,
SARIF mappings, scoped document links and the diff; run the contributor checks required by the
implementation contract. No placeholders or stale sample descriptions may pass this gate.
