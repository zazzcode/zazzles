# zazzles documentation

`zazzles` helps developers and coding agents harden application code from source-backed security
results. Start with a local JavaScript, TypeScript or Python application, produce JSON/HTML/SARIF reports, and
review vulnerabilities, poor practice, unresolved questions, and sufficient protection separately.
The scanner is under active development with bounded analysis; see the limits in the running guide.
These guides cover the current **Scan** capability, including its supported validation and
construction-practice findings. The [project goals](../README.md#project-goals-scan-inspect-audit-and-fix)
also include planned **Inspect** assessments, dependency **Audit** and agent-driven **Fix**.
Inspect will keep engineering standards and maintainability concerns distinct from security claims.
These goals do not imply separate implemented commands today.
They are intended to run independently, in any order, with optional agent workflows combining them.
Fix can start from an existing report or a user-specified issue. Each capability retains its own
required inputs and verification.

The agent-first objective is practical: **fix established problems correctly**, including poor
practice that deserves refactoring without proof of an exploit. Keep the evidence, business policy,
and intended behavior visible so an agent can apply and verify an appropriate change.

## Table of contents

| Guide | What you will learn |
|---|---|
| [Sample reports](samples/README.md) | Juice Shop and TypeScript reports; Node.js Goof evaluation setup and Bearer baseline runbook |
| [Technical approach](technical-approach.md) | Hybrid analysis, embedded component organization, SAST comparisons and evidence limits |
| [Philosophy](philosophy.md) | Remediation-first decisions, supported findings, uncertainty, and preserving protection |
| [Getting started](getting-started.md) | Go/C prerequisites, compilation, `.env.sample`, and environment loading |
| [Running scans](running-scans.md) | CLI modes, route scope, report folders, JSON/HTML/SARIF, and current limitations |
| [Interpreting results](interpreting-results.md) | Findings, Review, Protected, Categories, counts, and agent remediation |
| [Detection capabilities](detection-capabilities.md) | Families, languages and frameworks covered, recognized protections, generic vs adapter-specific rules |
| [Analysis rules and guidelines](analysis/README.md) | Source evidence, SQL/NoSQL judgment, input validation, and calibration |
| [Category glossary](glossary.md) | SQL/NoSQL, validation, outbound requests, and planned categories |
| [Decision-model setup](decision-models.md) | Required core assessment with Luna, credentials, bounded requests and failures |
| [CI/CD artifacts](ci.md) | Saving and consuming reports in build pipelines |
| [Semgrep CE cheat sheet](semgrep-ce-cheat-sheet.md) | Running Semgrep Community Edition locally as a comparison scanner |
| [Contributing](contributing.md) | Development checks, feature branches, review, and documentation ownership |

## First steps

[Compile scan](getting-started.md#compile), [configure required model assessment](decision-models.md),
[run a scan](running-scans.md#run), then open the
printed HTML file and expand a route. Agents can read the matching JSON for source evidence and
remediation context. The files are snapshots; regenerate views after changing the JSON or renderer.

This root `docs/` directory is for users and contributors. `.zazz/` contains internal engineering
design, project planning, evaluation records, implementation contracts, and SDLC standards.

[Python analysis and limits](python-support.md) describes the Flask, RESTX, FastAPI and sqlite3 adapter.

[Next.js analysis](nextjs-support.md) describes the App Router, Server Action and page entries added to
the TypeScript/Node.js analysis, what a scan is expected to find, and the framework practice checks.
