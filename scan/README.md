# Code Scan

[Zazzles modules](../README.md#modules) · [Code Scan user docs](../docs/scan/README.md)

**Code Scan** (`scan/`) analyzes JavaScript, TypeScript, Python and PHP application source for
security vulnerabilities, evidence gaps, and code smells or poor coding practices that can impact
security or performance. Its reports contain the operation, paths, controls and evidence gaps for
each claim. Optional model assessment helps evaluate supported claims.

- [Setup and build](../docs/scan/getting-started.md)
- [Running scans](../docs/scan/running-scans.md)
- [Detection capabilities](../docs/scan/detection-capabilities.md)
- [Interpreting results](../docs/scan/interpreting-results.md)
- [Sample reports](../docs/samples/README.md)

The canonical Go command is in [scan/cmd/scan](cmd/scan/) (with the root compatibility entry point
in [cmd/scan](../cmd/scan/)). Shared CLI orchestration lives in [scan/cli](cli/), and the analyzer,
pipeline, judge, and reporting packages live in [scan/internal](internal/).
[Contributor guide](../docs/contributing.md)
