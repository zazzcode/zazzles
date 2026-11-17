#!/usr/bin/env python3
"""Reproduce source-oracle probes without installing failing tests in the suite."""

import argparse
import json
import pathlib
import subprocess
import tempfile


PROBES = {
    "cookie_composed_safe",
    "cookie_override_unsafe",
    "message_comparison_unused",
    "message_comparison_after_use",
    "cache_identity_name_only",
    "cache_public_unrelated",
    "admin_ignored_auth",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", choices=("baseline", "improved"), required=True)
    args = parser.parse_args()
    here = pathlib.Path(__file__).resolve().parent
    root = here.parents[2]
    with tempfile.TemporaryDirectory(prefix="zazzles-accuracy-probes-") as scratch:
        overlay = pathlib.Path(scratch) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(root / "internal/parse/accuracy_research_probe_test.go"):
                str(here / "research-probes.txt")
        }}))
        result = subprocess.run([
            "go", "test", "-json", "-overlay", str(overlay), "./internal/parse",
            "-run", "^TestAccuracyResearchProbe$", "-count=1",
        ], cwd=root, text=True, capture_output=True, check=False)
    outcomes = {}
    for line in result.stdout.splitlines():
        event = json.loads(line)
        test = event.get("Test", "")
        if test.startswith("TestAccuracyResearchProbe/") and event["Action"] in ("pass", "fail", "skip"):
            outcomes[test.split("/", 1)[1]] = event["Action"]
    expected = "fail" if args.expect == "baseline" else "pass"
    valid = set(outcomes) == PROBES and all(value == expected for value in outcomes.values())
    valid = valid and result.returncode == (1 if args.expect == "baseline" else 0)
    print(json.dumps({"expect": args.expect, "matched": valid,
                      "go_exit": result.returncode, "outcomes": outcomes}, indent=2, sort_keys=True))
    if not valid:
        print(result.stdout)
        print(result.stderr)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
