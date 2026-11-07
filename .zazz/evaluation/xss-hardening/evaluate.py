#!/usr/bin/env python3
"""Compare scanner findings.json files against the independent XSS matrix.

Usage: evaluate.py --matrix matrix.json --report TARGET=findings.json [...] [--out result.json]
A required case passes when its file/line (and output context, when stated) has at
least `contexts` completed confirmed_vulnerability XSS records. A not_red control
passes when no confirmed record sits on it. Other confirmed records are listed under
`unadjudicated` for source review. Exit 0 only when every case and control passes.
The matrix never enters scanner or model input.
"""
import argparse, json, sys


def xss(report):
    return [u for u in report["uses"] if u["kind"] == "xss_candidate"]


def red(u):
    a = u.get("assessment") or {}
    return a.get("status") == "completed" and a.get("finding_status") == "confirmed_vulnerability"


def at(u, c):
    s = u["sink"]["span"]
    if s["file"] != c["file"]:
        return False
    if c.get("line") and s["start_line"] != c["line"]:
        return False
    if c.get("lines") and s["start_line"] not in c["lines"]:
        return False
    return not c.get("output_context") or u["xss"]["output_context"] == c["output_context"]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--matrix", required=True)
    p.add_argument("--report", action="append", default=[])
    p.add_argument("--out")
    a = p.parse_args()
    matrix = json.load(open(a.matrix))
    reports = dict((r.split("=", 1)[0], json.load(open(r.split("=", 1)[1]))) for r in a.report)
    out, ok, claimed = {"required_red": [], "not_red": [], "unadjudicated": []}, True, set()
    for c in matrix["required_red"]:
        if c["target"] not in reports:
            continue
        found = [u for u in xss(reports[c["target"]]) if at(u, c)]
        confirmed = [u for u in found if red(u)]
        claimed.update(u["id"] for u in confirmed)
        good = len(confirmed) >= c["contexts"]
        ok = ok and good
        out["required_red"].append({"id": c["id"], "pass": good, "expected": c["contexts"], "records": len(found), "confirmed": len(confirmed), "statuses": sorted({str((u.get("assessment") or {}).get("finding_status")) for u in found})})
    for c in matrix["not_red"]:
        if c["target"] not in reports:
            continue
        hits = [u for u in xss(reports[c["target"]]) if at(u, c) and red(u)]
        good = not hits
        ok = ok and good
        out["not_red"].append({"id": c["id"], "pass": good, "confirmed": len(hits)})
    for t, r in reports.items():
        for u in xss(r):
            if red(u) and u["id"] not in claimed:
                s = u["sink"]["span"]
                out["unadjudicated"].append({"target": t, "file": s["file"], "line": s["start_line"], "context": u["xss"]["output_context"], "type": u["xss"]["type"]})
    for row in out["required_red"] + out["not_red"]:
        print(("PASS " if row["pass"] else "FAIL ") + json.dumps(row))
    for row in out["unadjudicated"]:
        print("REVIEW " + json.dumps(row))
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    sys.exit(0 if ok else 1)


main()
