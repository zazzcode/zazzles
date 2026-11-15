# Zazzles

**Scan and inspect your application or microservice code, then make it secure and reliable.**

Zazzles reviews application and microservice code for two kinds of problems:

- **Security vulnerabilities** in your own source code and in the libraries your project depends on.
- **Poor practice** that weakens security, reliability or functionality. Examples are missing or weak
  input validation, unsafe query and command construction, and sensitive data written to logs. These
  are worth fixing even when no one has shown an exploit.

Every result points at the exact line of source. It explains the protection that is already there and
says what to change. Coding agents can then make small, focused repairs that keep the application's
intended behavior, check their own work, and hand a pull request to a person to review.

Many scanners show where a problem is and the path an input takes to reach it. Zazzles adds a
**decision model** that judges what the code actually does, and a scanner that checks the model's work:

- **The model is the judge.** For each sensitive operation it answers specific questions. Can a request
  value do harm here? Is the guard or validation already in place adequate? Those answers decide
  whether a result is a vulnerability or is protected.
- **The scanner is the referee.** It supplies the evidence and checks each answer before it counts:
  - An answer that contradicts the source is rejected. An example is "not applicable" when a request
    value plainly reaches the operation.
  - A vulnerability needs complete evidence for that path. Unresolved gaps on the path keep the
    result in Review.
  - Protection needs a control that covers every path the request value can take. A confident answer
    never fills a missing fact.
- **Some poor practice needs no model.** Rules over the source establish certain problems directly.
  A SQL query built by string concatenation is one. It is reported without anyone proving an exploit.
- **Not knowing is a result.** Anything unresolved is marked **Review**. A clean report is never
  presented as proof that code is safe.

Every result keeps its evidence trail:

- where the input enters the application,
- the path the value takes to a sensitive operation,
- the checks it passes along the way, and
- anything the scanner could not resolve.

[Get started](#quick-start) · [What exists today](#what-exists-today) · [Explore sample reports](#saved-results) ·
[Understand results](#interpret-results) · [Roadmap](.zazz/project/implementation-plan.md) ·
[Contributor guide](docs/contributing.md)

<a id="project-goals-scan-inspect-audit-and-fix"></a>
<a id="project-goals-scan-audit-and-fix"></a>
<a id="project-goals-scan-quality-audit-and-fix"></a>

## The vision: Scan, Inspect, Audit and Fix

| Capability | What it does | Status |
|---|---|---|
| **Scan** | Finds security vulnerabilities in your code and judges whether existing protection is adequate | Available for supported JavaScript, TypeScript and Python |
| **Inspect** | Reviews code for poor practice in validation, query and command construction, logging and reliability | Partly available: practice checks ship inside Scan; a distinct Inspect workflow is planned |
| **Audit** | Finds known vulnerabilities in your dependencies and guides upgrades, using ecosystem tools such as `npm audit` and `pip-audit`, with SBOM artifacts | Planned |
| **Fix** | Provides agent skills and automation so coding agents can read findings and deficiencies, repair the code, upgrade libraries, verify the changes and prepare a pull request for review | Planned |

The capabilities can be used alone or together, on demand or on a schedule. Fix can start from a saved
report or from an issue you describe.

Two principles shape the results:

- **Name the real problem.** An unsafe query *construction* is reported as that. It is not quietly
  promoted to a confirmed injection.
- **Keep serious risks visible.** Security problems should be easy to prioritize and not buried under
  routine quality notes.

The [philosophy](docs/philosophy.md) explains how fixes should preserve behavior and existing
protection. The [implementation plan](.zazz/project/implementation-plan.md) holds the detailed roadmap
and delivery status.

<a id="what-exists-today"></a>
<a id="scan-current-implementation"></a>
<a id="entry-use-cases-and-delivery-status"></a>

## What exists today

Today Zazzles is a command-line scanner for **JavaScript, TypeScript and Python** applications.

- It reads source only. It does not run your app or install its dependencies.
- It covers the frameworks and operations it models. Anything else is reported as unresolved,
  not silently skipped.

**The decision model**

- Judges whether each finding is a real vulnerability and whether existing protection is adequate
- OpenAI Luna is the primary model; Google Gemini is optional
- One model is used for a whole scan, with no automatic fallback
- A request cap and optional rate limits keep runs predictable
- Equivalent contexts share one decision to save calls

**Security checks**

- SQL injection
- NoSQL injection (MongoDB-style databases)
- Cross-site scripting (XSS): server-rendered, stored, and browser/DOM
- Command injection
- Path traversal and unsafe file/archive use: Node `fs` reads/writes (including `open`, `copyFile`,
  and `rename`), Zip Slip when extracting uploaded archives, Python `FileResponse` / upload
  filenames, `shutil` copy/move, and `tarfile.extractall` (with explicit filter/runtime facts)
- Server-side request forgery (SSRF) when a verified `fetch`, `axios`, Node `http`/`https`, or
  Python HTTP client call takes its destination from the request; other outbound calls are grouped
  observations for review

**Good-practice checks**

- Input validation
- Safe construction of queries and other destination calls
- Sensitive data written to logs

**How it finds problems**

- Finds entry points: web routes (including each stage of an Express middleware chain), browser
  events, GraphQL and gRPC
- Follows request input to the sensitive operation it reaches, including URL fields
  (`path` / `url` / `originalUrl`) and verified upload filename or file content on Node apps
- Notices the checks on the way, such as `if` guards and allow-lists. In JavaScript and TypeScript it
  follows each side of an `if`/`else` separately, so a check on one branch never protects another
- Reads each library's version for the part of a monorepo being analyzed
- Sends compact, source-backed evidence to the model and lists anything it had to leave out
- Checks each model answer against the source facts and the evidence supplied before it counts
- Can replay a saved decision offline to reproduce a result

**Reports**

- HTML to read, JSON for tools and coding agents, SARIF for security platforms
- Saved even when part of the assessment could not be completed

**How we measure efficacy**

The useful metric is not “every bug in every sample app.” It is: for each analyzer we ship, do we
confirm the source-reviewed required positives on pinned vulnerable apps, and keep known protected
or inconclusive cases in Review/Protected instead of inventing reds?

On the current Node sample rebuild (Juice Shop, Node.js Goof, Vulnerable TypeScript app, and
vuln-demo-app), that in-scope catch is complete for the families above: the cataloged XSS, SQL,
NoSQL, command, path/Zip Slip, logging, and SSRF required positives are confirmed. Cases the answer
keys mark as Review stay Review (for example Juice Shop subtitle XSS). Defects outside those
analyzers—authentication, IDOR, `eval`/code injection, open redirect, secrets, cookie flags, and
most Juice Shop challenge categories—are **not covered** yet; a clean row there is not a pass.

Details and per-app expected-vs-actual tables live in
[vulnerable sample applications](.zazz/project/vulnerable-sample-apps.md). Sample HTML reports are
snapshots of those runs, not a claim of whole-application security.

**Not yet available:** dependency auditing, a separate Inspect report, automated fixes and scheduled runs.
The [capability checklist](.zazz/project/implementation-plan.md#supported-capability-checklist) records
exactly which languages, frameworks and operations each analyzer supports, with its limits.

## How it works

Zazzles locates supported application entry points, follows input values to sensitive operations,
and collects the relevant source, transformations, and guards. The decision model assesses specific
security questions using that evidence. The scanner checks evidence completeness and consistency
before classifying a result.

```mermaid
flowchart LR
    A[Application source] --> B[Trace inputs and controls]
    B --> C[Assess with Luna Decisions]
    C --> D[Validate evidence]
    D --> E[HTML, JSON and SARIF reports]
```

The target application does not need to run. A finding includes the operation and supporting code;
a protection result applies to the stated claim and analyzed paths. Missing evidence remains a
review task. The [technical approach](docs/technical-approach.md) explains the analysis and its limits.

<a id="setup"></a>

## Quick start

### 1. Build the scanner

Install **Go 1.27.2 or newer** and a **C compiler** for the Tree-sitter bindings. On macOS, install
Apple's command-line tools with `xcode-select --install` if needed. On Linux, use your distribution's
C development toolchain. Check `go version` and `cc --version` before building.

The current development branch is `stage`:

```bash
git clone --branch stage https://github.com/zazzcode/zazzles.git
cd zazzles
go build -o bin/scan ./cmd/scan
./bin/scan --list /absolute/path/to/your/app
```

The first build downloads Go modules. Zazzles reads an existing local target checkout; it does not
install its dependencies, start its server, or modify its source. See the
[setup guide](docs/getting-started.md) for more detail.

### 2. Configure OpenAI Luna Decisions

For a new setup, copy the configuration sample:

```bash
cp .env.sample .env
```

If `.env` already exists, edit it in place instead of replacing it. Set these values locally:

```dotenv
JUDGE_DECISION_MODEL=gpt-6-luna
OPENAI_API_KEY=your-api-key
```

Keep `.env` private and Git-ignored. Load your trusted file in bash or zsh:

```bash
set -a
. ./.env
set +a
```

The scanner reads process environment variables; it does not load `.env` automatically. OpenAI Luna
is the primary model used for development and calibration. Manage spending in your API account;
no local pricing or rate configuration is needed.

#### Optional: use Google Gemini Decisions instead

Use one model per scan. To use Google Gemini:

1. Create an API key in [Google AI Studio](https://aistudio.google.com/api-keys).
2. In your `.env`, set the key and select the Gemini model. Keep only one `JUDGE_DECISION_MODEL`
   line in the file.

   ```dotenv
   JUDGE_DECISION_MODEL=gemini-decision-1
   GEMINI_API_KEY=your-gemini-api-key
   ```

3. Load the file in a fresh shell so an earlier OpenAI value is not left behind, then scan with the
   matching provider:

   ```bash
   ./bin/scan --analyze --judge gemini --judge-limit 10 \
     --output-dir "$HOME/zazzles-findings" /absolute/path/to/your/app
   ```

The provider you pass to `--judge` must match the model in `JUDGE_DECISION_MODEL`. Zazzles never falls
back to another provider automatically. The [decision-model guide](docs/decision-models.md) covers
these options, plus RPM/TPM pacing and the Jev adapter.

<a id="run"></a>

### 3. Scan and open the report

```bash
./bin/scan --analyze --judge openai --judge-limit 10 \
  --output-dir "$HOME/zazzles-findings" /absolute/path/to/your/app
```

`--judge` enables model requests and transmits bounded source evidence. `--judge-limit` caps
assessment requests for the run; the default is 10. A small cap is useful for an initial scan and
may leave work unassessed. For a focused scan, add `--entry <registration-file>` and
`--route <exact-route-pattern>`, or select a family with `--only-family command`.

The command prints a fresh results folder containing:

| File | Use |
|---|---|
| `findings.html` | Open in a browser to review findings, source evidence, and remediation |
| `findings.json` | Full evidence and assessment records for inspection and coding agents |
| `findings.sarif` | SARIF 2.1.0 output for security-tool integrations |

Open the printed `findings.html` path. On macOS, use `open /path/to/run/findings.html`; on other
systems, open the file through your browser or file manager. Each run gets a new folder.

Reports are retained when an assessment is incomplete. **Exit 0** means the requested operation
completed, **exit 1** indicates an execution or assessment failure/incompleteness, and **exit 2**
indicates invalid arguments. Finding counts do not determine the exit code. Read the report's
assessment reasons when a request cap, unsupported outbound assessment, or provider error leaves
work incomplete.

For evidence inspection without model calls:

```bash
./bin/scan --analyze --output-dir "$HOME/zazzles-findings" /absolute/path/to/your/app
```

This leaves model assessments unrun. Saved HTML/SARIF exports also work offline. The
[running guide](docs/running-scans.md) covers entry selection, filters, exports, and CI usage.

## Interpret results

Expand an entry in the HTML report to inspect the finding location, code, assessment, unresolved
facts, and recommended changes. Category labels describe the analysis area; they are not verdicts.

| Result | Meaning |
|---|---|
| **Findings** | Source-supported vulnerabilities or established poor practice that warrants correction |
| **Review** | Unassessed or unresolved behavior needing investigation; it is not a confirmed vulnerability |
| **Protected** | Evidence and assessment support protection for the named operation and scope |

Counts describe individual records and entry contexts, not necessarily unique defects. One shared
handler can appear under several routes. Equivalent contexts may reuse a decision while retaining
separate findings and explicit provenance; differing inputs and controls stay separate.

A completed scan does not certify an application as secure. Read
[interpreting results](docs/interpreting-results.md) for statuses, evidence, and counting rules, and
[the project philosophy](docs/philosophy.md) for how to fix issues while preserving intended behavior.

<a id="explore-sample-findings"></a>

## Saved results

Explore existing reports without installing Zazzles or making API calls:

| Application | Examples | Reports and source expectations |
|---|---|---|
| OWASP Juice Shop | Browser/server XSS and database operations | [Browse HTML](https://zazzcode.github.io/zazzles/docs/samples/juice-shop/findings.html) · [Sample notes](docs/samples/juice-shop/README.md) |
| Node.js Goof | Command injection, XSS, and database review | [Browse HTML](https://zazzcode.github.io/zazzles/docs/samples/nodejs-goof/findings.html) · [Sample notes](docs/samples/nodejs-goof/README.md) |
| Vulnerable TypeScript app | Command injection at `/api/ping`, reflected XSS, and logging | [Browse HTML](https://zazzcode.github.io/zazzles/docs/samples/vulnerable-typescript-app/findings.html) · [Sample notes](docs/samples/vulnerable-typescript-app/README.md) |
| VulnPy | Shared Python sinks across framework adapters | [Browse HTML](https://zazzcode.github.io/zazzles/docs/samples/vulnpy/findings.html) · [Sample notes](docs/samples/vulnpy/README.md) |

The [sample index](docs/samples/README.md) links downloadable HTML, JSON, and SARIF. Compare counts
against the [expected-vs-actual tables](.zazz/project/vulnerable-sample-apps.md)—efficacy is
in-scope analyzer catch on those keys, not total bugs in each app. Notes identify scanner and target
versions; older snapshots may predate current coverage.

### Verify a sample finding yourself

Start with one known case rather than comparing whole-report totals. For the TypeScript command
injection example, clone and pin the source outside the scanner checkout:

```bash
git clone https://github.com/ryanmcmorrowsnyk/vulnerable-typescript-app.git \
  ../vulnerable-typescript-app
git -C ../vulnerable-typescript-app checkout --detach 7f8b240a2f02beba099da3632d1ba679ff8bc32f

./bin/scan --analyze --entry src/server.ts --route /api/ping \
  --only-family command --judge openai --judge-limit 1 \
  --output-dir "$HOME/zazzles-findings" ../vulnerable-typescript-app
```

No target installation or server startup is needed. In the generated HTML, expand `GET /api/ping`
and inspect the process call at `src/server.ts:90`, the `host` input, and the shell-command evidence.
The [source-reviewed detection guide](.zazz/evaluation/vulnerable-typescript-app-detection-guide.md)
records the expected command-injection case; the
[saved sample](docs/samples/vulnerable-typescript-app/README.md) records its prior assessment.

Verify the target revision with `git -C ../vulnerable-typescript-app rev-parse HEAD` and confirm it
has no local changes with `git -C ../vulnerable-typescript-app status --short`. Compare the same
source location, input-to-operation flow, status, and evidence—not just the number of findings.
A fresh model response may be inconclusive; inspect its reason rather than treating that as protection.
Keep vulnerable baselines unchanged and make repairs in a separate copy. The
[reference policy](docs/samples/reference-policy.md) explains baseline hashes and verification.

## Contributing

See the [contributor setup and notes](docs/contributing.md) for development prerequisites, tests,
repository structure, worktree conventions, and the review process. User setup does not require
adopting the project's contributor workflow.

## Documentation

- [Getting started](docs/getting-started.md) and [running scans](docs/running-scans.md)
- [Decision-model setup](docs/decision-models.md) and [interpreting results](docs/interpreting-results.md)
- [Sample reports and verification](docs/samples/README.md)
- [Technical approach](docs/technical-approach.md) and [analysis rules](docs/analysis/README.md)
- [CI integration](docs/ci.md) and [documentation index](docs/README.md)
- [Implementation plan and roadmap](.zazz/project/implementation-plan.md)
