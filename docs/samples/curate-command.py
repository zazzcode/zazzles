#!/usr/bin/env python3
"""Curate a retained full-scan findings.json into docs/samples/<app>/findings.json.

For a run that used --skip-family input-validation, the unjudged records of the skipped family are
omitted from the published copy (the full report exceeds GitHub's file-size limit) together with the
entries that carried only those records. Everything else, including every judged use, its raw answers
and its evidence, is unchanged. The omission is stated in the report's limitations. Run
docs/samples/refresh.py afterwards to regenerate the HTML and SARIF views offline.
"""
import argparse
import json
from pathlib import Path

SKIP_MARKER = "analyzer not used for this run"


def reduce(report):
    skipped = {u["id"] for u in report["uses"] if u["assessment"].get("status") == "not_run" and SKIP_MARKER in u["assessment"].get("reason", "")}
    if not skipped:
        return report, 0, 0
    report["uses"] = [u for u in report["uses"] if u["id"] not in skipped]
    kept_entries = {u["entry_id"] for u in report["uses"]}
    kept_contexts = {u["invocation_context_id"] for u in report["uses"]}
    total = len(report["entries"])
    report["entries"] = [e for e in report["entries"] if e["id"] in kept_entries]
    report["registrations"] = [r for r in report["registrations"] if r["entry_id"] in kept_entries]
    report["dispatch_bindings"] = [b for b in report["dispatch_bindings"] if b["entry_id"] in kept_entries]
    report["invocation_contexts"] = [c for c in report["invocation_contexts"] if c["id"] in kept_contexts]
    kept = {u["id"] for u in report["uses"]}
    report["findings"] = [f for f in report.get("findings", []) if f["use_id"] in kept]
    dropped = total - len(report["entries"])
    report.setdefault("limitations", []).append(
        f"Published-sample reduction: the full retained report exceeds GitHub's file-size limit, so the {len(skipped)} unjudged "
        f"input-validation records and the {dropped} entries that carried only those records are omitted here. "
        "Every judged record, its raw answers and evidence are unchanged; the complete report is retained with the review package.")
    return report, len(skipped), dropped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="retained full findings.json")
    parser.add_argument("--sample", required=True, help="sample folder name under docs/samples")
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    report, skipped, dropped = reduce(report)
    report["root"] = args.sample
    destination = Path(__file__).resolve().parent / args.sample / "findings.json"
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"curated {args.sample}: omitted {skipped} skipped records and {dropped} entries; {destination.stat().st_size} bytes")


if __name__ == "__main__":
    main()
