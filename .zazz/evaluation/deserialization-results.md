# Unsafe deserialization analyzer verification

The scanner implementation was verified at `47513617e694c36e41144ecfc0a324daa997effe`.
The pre-implementation baseline was `04399c6`. The [contract](../specifications/unsafe-deserialization.md)
defines the acceptance cases.

| Criterion | Evidence |
| --- | --- |
| AC1 Python | `TestDeserializationPython`, `TestDeserializationPythonTransfers` and `TestPythonPackageVersion` pass. |
| AC2 JavaScript and TypeScript | `TestDeserializationJS` passes in both languages. Transfer, browser exclusion and Next.js source-only tests pass. |
| AC3 PHP | `TestDeserializationPHP`, `TestDeserializationPHPTransfers` and `TestDeserializationPHPBinding` pass. |
| AC4 Facts and selection | `TestDeserializationFacts` and `TestDeserializationSelection` pass. Existing architecture entries and request digests were preserved. |
| AC5 Policy | All 13 policy cases pass with a localhost stub judge. Request replay and context reference tests pass. |
| AC6 Reporting | `TestDeserializationFinding` passes, including Review and the SARIF CWE-502 rule. |
| AC7 Offline samples | All VulnPy and negative sample rows pass. `TestNextJSVulnLab` passes for the 29 existing keyed rows. The two proposed lab scenarios are open. |
| AC8 Isolation | Repository build, vet, full Go tests and race tests pass. The architecture golden adds four fixture roots. The recall comparison preserves the outcomes of 186 other rows at the catalog pins. Both CLI family filters accept `deserialization` with a judge and reject an unknown name. |
| AC9 Live evaluation | Pending the AC7 lab scenario gate. Zero paid requests were made. |
| AC10 Documentation | Capability, rules, CLI, language and results guides list support and limits. A fresh verifier independently passed the available scanner checks. |

## Pinned offline sample results

VulnPy at `b81885e58283a3449b578d20c20557aff637e5ea` produces four sink groups with
30 contexts each. All 120 records have a request witness and no completeness blocker.

| Key | Operation | Offline result |
| --- | --- | --- |
| `VP-DESER-01` | `pickle.load` | 30 candidates at line 8 |
| `VP-DESER-02` | `pickle.loads` | 30 candidates at line 12 |
| `VP-DESER-03` | `yaml.load` with `UnsafeLoader` | 30 candidates at line 17 |
| `VP-DESER-04` | `yaml.load_all` with `UnsafeLoader` | 30 candidates at line 23 |
| `VFA-DESER-01` | Socket-fed pickle, Vulnerable Flask App | No candidate |
| `TS-DESER-N01` | js-yaml `safeLoad`, Vulnerable TypeScript App | No candidate |
| `JS-DESER-N01`, `N01b`, `N01c` | File-fed YAML, Juice Shop | No candidate |
| `JS-DESER-X01` | Call text inside a constant program string, Juice Shop | Excluded |

DVWA, Node.js Goof, Juice Shop and the TypeScript app emit zero deserialization candidates.
The existing Next.js lab passes at pin `ea10efb960d5bf4dbabbfee01dc6e5f881b22898` and
at its current main checkout `8d26f52a4b3179bd75d559bbe6eac0ff8ad311dc`. Its CWE-502
dependency advisory remains classified as SCA. Source-only Next.js fixtures verify request-fed
unsafe YAML and the corresponding data-only controls. The lab scenario branch, its runtime
checks and its draft PR remain open.

## Live evaluation budget

| Target | Offline candidate count | Actual requests |
| --- | ---: | ---: |
| VulnPy | 120 | 0 |
| Next.js lab scenarios | Pending | 0 |
| Python fixture app | 31 | 0 |
| JavaScript fixture app | 13 | 0 |
| TypeScript fixture app | 13 | 0 |
| PHP fixture app | 15 | 0 |
| Total used against the 800-request limit | | 0 |

The offline results establish evidence and deterministic policy behavior. Live verdicts for
the target rows remain unmeasured. The existing published sample accuracy results are historical.
