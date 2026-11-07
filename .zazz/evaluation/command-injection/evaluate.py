#!/usr/bin/env python3
"""Compare a scanner findings.json against the independent command-injection matrix.

The matrix never enters scanner input. Usage:
  evaluate.py --matrix matrix.json --report TARGET=findings.json [...] [--require-judged] [--out mapping.json]
Without --require-judged a case passes when every expected context has a command
candidate with a resolved request-derived operand path (raw or guarded).
With --require-judged each context must also be a completed confirmed_vulnerability
with a completed assessment, and negative controls must have no command finding.
Exit status 0 only when every expected case and control passes.
"""
import argparse, json, sys


def load(path):
    with open(path) as fh:
        return json.load(fh)


def evaluate(matrix, reports, judged):
    out = {"cases": [], "controls": [], "unexpected": []}
    ok = True
    entries = {t: {e["id"]: e for e in r["entries"]} for t, r in reports.items()}
    cmd = {t: [u for u in r["uses"] if u["kind"] == "command_execution_candidate"] for t, r in reports.items()}
    claimed = {t: set() for t in reports}
    for case in matrix["cases"]:
        t = case["target"]
        if t not in reports:
            continue
        rows, passed = [], True
        for ctx in case["contexts"]:
            want = ctx["registrations"] * len(ctx["methods"])
            found = []
            for u in cmd[t]:
                e = entries[t][u["entry_id"]]
                if (u["sink"]["span"]["file"] == case["sink"]["file"] and u["sink"]["span"]["start_line"] == case["sink"]["line"]
                        and e["location"]["span"]["file"] == ctx["registration_file"] and e["http"]["method"] in ctx["methods"]):
                    found.append(u)
            for u in found:
                claimed[t].add(u["id"])
            # A witness has a resolved request-derived path (raw, or guarded by a control the
            # assessment must judge); unresolved sibling paths stay visible but do not void it.
            complete = [u for u in found if any(p["protection"] in ("raw", "guarded") for p in u["command"]["paths"])]
            confirmed = [u for u in found if u["assessment"].get("status") == "completed" and u["assessment"].get("finding_status") == "confirmed_vulnerability"]
            row = {"framework": ctx["framework"], "registration_file": ctx["registration_file"], "expected": want, "candidates": len(found), "complete": len(complete), "confirmed": len(confirmed)}
            good = len(found) == want and len(complete) == want and (not judged or len(confirmed) == want)
            row["pass"] = good
            passed = passed and good
            rows.append(row)
        out["cases"].append({"id": case["id"], "target": t, "pass": passed, "contexts": rows})
        ok = ok and passed
    for ctrl in matrix["negative_controls"]:
        t = ctrl["target"]
        if t not in reports or "sink" not in ctrl and not ctrl.get("files"):
            continue
        hits = [u for u in cmd[t] if (ctrl.get("sink") and u["sink"]["span"]["file"] == ctrl["sink"]["file"] and u["sink"]["span"]["start_line"] == ctrl["sink"]["line"])
                or (ctrl.get("files") and u["sink"]["span"]["file"] in ctrl["files"])]
        good = not hits
        out["controls"].append({"id": ctrl["id"], "target": t, "pass": good, "command_candidates": len(hits)})
        ok = ok and good
    for t, uses in cmd.items():
        extra = [u["id"] for u in uses if u["id"] not in claimed[t]]
        if extra:
            out["unexpected"].append({"target": t, "count": len(extra), "ids": extra[:10]})
            ok = False
    out["pass"] = ok
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--report", action="append", default=[], help="TARGET=path to findings.json")
    ap.add_argument("--require-judged", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    matrix = load(args.matrix)
    reports = {}
    for item in args.report:
        target, _, path = item.partition("=")
        reports[target] = load(path)
    result = evaluate(matrix, reports, args.require_judged)
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + "\n")
    print(text)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
