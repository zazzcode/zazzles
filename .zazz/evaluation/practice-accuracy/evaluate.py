#!/usr/bin/env python3
"""Validate and summarize the source-backed practice/security case matrix.

The evaluator is deliberately offline: it never calls the scanner or a model. Case
labels are supplied by reviewers, and optional reports only verify use references.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_INVENTORY = ROOT / ".zazz/evaluation/analyzer-protection-and-flow-inventory.md"
ORACLE_CLASSES = {
    "known_positive", "genuine_safe", "unresolved_trust", "practice_expected",
    "practice_absent", "unjudged_candidate",
}
SELECTION_STATES = {"selected", "carried", "excluded", "missed", "unresolved"}
ASSESSMENT_STATES = {"completed", "assessed", "not_run", "failed", "unresolved", "pending"}
SECURITY_OUTCOMES = {"confirmed", "protected", "review", "needs_review", "not_applicable", "poor_practice", "missing", "pending"}


class EvaluationError(ValueError):
    """Raised when the case matrix or a referenced report violates its contract."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"cannot read JSON {path}: {exc}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvaluationError(message)


def predecessor_ids_from_inventory(path: Path = DEFAULT_INVENTORY) -> set[str]:
    """Read first-column record IDs from the predecessor's Markdown inventory tables."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvaluationError(f"cannot read source inventory {path}: {exc}") from exc
    ids: set[str] = set()
    in_record_table = False
    for line in content.splitlines():
        if not line.lstrip().startswith("|"):
            in_record_table = False
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0].lower() == "id":
            in_record_table = True
            continue
        if not in_record_table or not cells or not cells[0] or set(cells[0]) <= {"-", ":"}:
            continue
        candidate = cells[0].strip("` ")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", candidate):
            ids.add(candidate)
    return ids


def _validate_phase(phase: Any, where: str) -> None:
    _require(isinstance(phase, dict), f"{where} must be an object")
    for key in ("run", "use_ids", "assessment_state", "outcome", "blockers"):
        _require(key in phase, f"{where}.{key} is required")
    _require(isinstance(phase["run"], str), f"{where}.run must be a string")
    _require(isinstance(phase["use_ids"], list) and all(isinstance(x, str) and x for x in phase["use_ids"]),
             f"{where}.use_ids must be an array of non-empty strings")
    _require(len(set(phase["use_ids"])) == len(phase["use_ids"]), f"{where}.use_ids contains duplicates")
    _require(phase["assessment_state"] in ASSESSMENT_STATES,
             f"{where}.assessment_state is not a supported state")
    outcome = phase["outcome"]
    _require(isinstance(outcome, str), f"{where}.outcome must be a string")
    _require(isinstance(phase["blockers"], list) and all(isinstance(x, str) for x in phase["blockers"]),
             f"{where}.blockers must be an array of strings")
    if outcome.lower() in SECURITY_OUTCOMES or outcome.lower() in {"emitted", "absent"}:
        return
    raise EvaluationError(f"{where}.outcome has unsupported value {outcome!r}")


def _identity(case: dict[str, Any]) -> tuple[Any, ...]:
    sink = case["sink"]
    return (case["target"], case["revision"], case["family"], case["entry"],
            sink["file"], sink["start_byte"], sink["end_byte"], sink["operand"])


def validate_cases(document: Any, *, inventory_ids: set[str] | None = None,
                   source_root: Path | None = None) -> list[dict[str, Any]]:
    """Validate schema, identities, source hashes, and predecessor reconciliation."""
    _require(isinstance(document, dict), "cases document must be an object")
    _require(document.get("schema_version") == 1, "schema_version must be 1")
    cases = document.get("cases")
    _require(isinstance(cases, list), "cases must be an array")
    seen_ids: set[str] = set()
    seen_identity: set[tuple[Any, ...]] = set()
    mapped: dict[str, str] = {}
    defect_oracles: dict[str, set[str]] = defaultdict(set)
    for index, case in enumerate(cases):
        where = f"cases[{index}]"
        _require(isinstance(case, dict), f"{where} must be an object")
        required = {"id", "predecessor_ids", "target", "revision", "family", "entry", "sink",
                    "defect_id", "oracle", "selection", "baseline", "after", "disposition", "evidence_refs"}
        _require(required <= case.keys(), f"{where} missing fields: {', '.join(sorted(required - case.keys()))}")
        case_id = case["id"]
        _require(isinstance(case_id, str) and case_id, f"{where}.id must be a non-empty string")
        _require(case_id not in seen_ids, f"duplicate case id {case_id!r}")
        seen_ids.add(case_id)
        _require(isinstance(case["predecessor_ids"], list) and
                 all(isinstance(x, str) and x for x in case["predecessor_ids"]),
                 f"{where}.predecessor_ids must be an array of non-empty IDs")
        _require(len(set(case["predecessor_ids"])) == len(case["predecessor_ids"]),
                 f"{where}.predecessor_ids contains duplicates")
        for key in ("target", "revision", "family", "entry", "defect_id", "disposition"):
            _require(isinstance(case[key], str) and case[key], f"{where}.{key} must be a non-empty string")
        sink = case["sink"]
        _require(isinstance(sink, dict), f"{where}.sink must be an object")
        for key in ("file", "operand"):
            _require(isinstance(sink.get(key), str) and sink[key], f"{where}.sink.{key} must be a non-empty string")
        for key in ("start_byte", "end_byte"):
            _require(isinstance(sink.get(key), int) and sink[key] >= 0, f"{where}.sink.{key} must be a non-negative integer")
        _require(sink["end_byte"] >= sink["start_byte"], f"{where}.sink byte range is reversed")
        _require(sink.get("sha256") is None or isinstance(sink.get("sha256"), str),
                 f"{where}.sink.sha256 must be a SHA-256 string or null for unavailable carried evidence")
        if sink["sha256"] is None:
            _require(isinstance(case.get("selection"), dict) and case["selection"].get("state") == "carried",
                     f"{where}.sink.sha256 may be null only for carried records")
            _require(source_root is None, f"{where}: cannot validate unavailable source hash against a supplied source root")
        else:
            _require(re.fullmatch(r"[0-9a-fA-F]{64}", sink["sha256"]) is not None,
                     f"{where}.sink.sha256 must be a 64-character SHA-256")
        oracle = case["oracle"]
        _require(isinstance(oracle, dict), f"{where}.oracle must be an object")
        _require(oracle.get("class") in ORACLE_CLASSES, f"{where}.oracle.class is unknown")
        _require(isinstance(oracle.get("rationale"), str) and oracle["rationale"].strip(),
                 f"{where}.oracle.rationale is required")
        for key in ("source_refs", "label_history"):
            _require(isinstance(oracle.get(key), list), f"{where}.oracle.{key} must be an array")
        _require(isinstance(case["selection"], dict), f"{where}.selection must be an object")
        _require(case["selection"].get("state") in SELECTION_STATES, f"{where}.selection.state is unknown")
        _require(isinstance(case["selection"].get("reason"), str) and case["selection"]["reason"].strip(),
                 f"{where}.selection.reason is required")
        _validate_phase(case["baseline"], f"{where}.baseline")
        _validate_phase(case["after"], f"{where}.after")
        _require(isinstance(case["evidence_refs"], list) and all(isinstance(x, str) for x in case["evidence_refs"]),
                 f"{where}.evidence_refs must be an array of strings")
        if case["selection"]["state"] == "excluded":
            _require(oracle["class"] == "genuine_safe",
                     f"{where}: only a genuine_safe oracle case can be excluded as safe")
            _require(bool(oracle["source_refs"]) and bool(case["evidence_refs"]),
                     f"{where}: a safe exclusion requires source and evidence references")
        ident = _identity(case)
        _require(ident not in seen_identity, f"duplicate case identity at {case_id!r}")
        seen_identity.add(ident)
        defect_oracles[case["defect_id"]].add(oracle["class"])
        for predecessor_id in case["predecessor_ids"]:
            _require(predecessor_id not in mapped,
                     f"predecessor row {predecessor_id!r} maps ambiguously to {mapped.get(predecessor_id)!r} and {case_id!r}")
            mapped[predecessor_id] = case_id
        if source_root is not None:
            source_file = (source_root / sink["file"]).resolve()
            try:
                source_file.relative_to(source_root.resolve())
            except ValueError as exc:
                raise EvaluationError(f"{where}.sink.file escapes source root") from exc
            try:
                actual = hashlib.sha256(source_file.read_bytes()).hexdigest()
            except OSError as exc:
                raise EvaluationError(f"{where}: cannot read source file {source_file}: {exc}") from exc
            _require(actual.lower() == sink["sha256"].lower(), f"{where}: stale source hash for {sink['file']}")
    for defect_id, classes in defect_oracles.items():
        _require(not ({"known_positive", "genuine_safe"} <= classes),
                 f"defect {defect_id!r} mixes known_positive and genuine_safe oracle classes")
    if inventory_ids is not None:
        unknown = sorted(set(mapped) - inventory_ids)
        unaccounted = sorted(inventory_ids - set(mapped))
        _require(not unknown, f"unknown predecessor IDs: {', '.join(unknown[:10])}")
        _require(not unaccounted, f"unaccounted predecessor rows ({len(unaccounted)}): {', '.join(unaccounted[:10])}")
    return cases


def _report_uses(report_path: Path) -> dict[str, dict[str, Any]]:
    report = _load_json(report_path)
    _require(isinstance(report, dict), f"report {report_path} must be an object")
    report_uses = report.get("uses")
    _require(isinstance(report_uses, list), f"report {report_path} must contain a uses array")
    uses: dict[str, dict[str, Any]] = {}
    for index, use in enumerate(report_uses):
        _require(isinstance(use, dict), f"report use {index} must be an object")
        use_id = use.get("id", use.get("use_id"))
        _require(isinstance(use_id, str) and use_id, f"report use {index} has no id/use_id")
        _require(use_id not in uses, f"duplicate report use id {use_id!r}")
        uses[use_id] = use
    return uses


def _validate_report_identity(case: dict[str, Any], use: dict[str, Any], stage: str) -> None:
    """Use IDs locate records; source span and operand must still agree with the case."""
    case_sink = case["sink"]
    report_sink = use.get("sink")
    _require(isinstance(report_sink, dict), f"{stage} use {use.get('id')!r} has no sink identity")
    span = report_sink.get("span")
    _require(isinstance(span, dict), f"{stage} use {use.get('id')!r} has no sink span")
    for report_key, case_key in (("file", "file"), ("start_byte", "start_byte"), ("end_byte", "end_byte")):
        _require(report_key in span, f"{stage} use {use.get('id')!r} has no sink {report_key}")
        _require(span[report_key] == case_sink[case_key],
                 f"{stage} use {use.get('id')!r} has a different sink {report_key} than case {case['id']!r}")
    report_sha = report_sink.get("sha256")
    _require(isinstance(report_sha, str) and report_sha, f"{stage} use {use.get('id')!r} has no source hash")
    _require(case_sink.get("sha256") is not None and report_sha.lower() == case_sink["sha256"].lower(),
             f"{stage} use {use.get('id')!r} has a different source hash than case {case['id']!r}")
    report_operand = report_sink.get("text")
    _require(isinstance(report_operand, str) and report_operand,
             f"{stage} use {use.get('id')!r} has no sink operand")
    _require(report_operand == case_sink["operand"],
             f"{stage} use {use.get('id')!r} has a different operand than case {case['id']!r}")
    report_entry = use.get("entry_id")
    _require(isinstance(report_entry, str) and report_entry,
             f"{stage} use {use.get('id')!r} has no entry_id")
    _require(report_entry == case["entry"],
             f"{stage} use {use.get('id')!r} has a different entry than case {case['id']!r}")
    kind = use.get("kind")
    _require(isinstance(kind, str) and kind, f"{stage} use {use.get('id')!r} has no kind")
    family = case["family"].lower().replace("-", "_")
    normalized_kind = kind.lower().replace("-", "_")
    if family.startswith("xss"):
        compatible = normalized_kind.startswith("xss")
    elif family == "input_validation":
        compatible = "validation" in normalized_kind
    elif family in {"sql", "nosql", "path", "redirect", "code"}:
        compatible = family in normalized_kind
    elif family == "ssrf":
        compatible = "ssrf" in normalized_kind or "outbound" in normalized_kind
    else:
        compatible = family in normalized_kind
    _require(compatible, f"{stage} use {use.get('id')!r} kind {kind!r} is incompatible with family {case['family']!r}")


def validate_report_references(cases: list[dict[str, Any]], report_paths: Path | list[Path] | None,
                               stage: str) -> None:
    if report_paths is None:
        return
    if isinstance(report_paths, Path):
        report_paths = [report_paths]
    report_uses: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for report_path in report_paths:
        for use_id, use in _report_uses(report_path).items():
            report_uses[use_id].append(use)
    assigned: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        phase = case[stage]
        for use_id in phase["use_ids"]:
            _require(use_id in report_uses, f"{stage} case {case['id']!r} references absent report use {use_id!r}")
            assigned[use_id].append(case["id"])
            for use in report_uses[use_id]:
                _validate_report_identity(case, use, stage)
    ambiguous = {use_id: ids for use_id, ids in assigned.items() if len(ids) > 1}
    example = next(iter(ambiguous.items()), None)
    _require(not ambiguous, f"ambiguous {stage} report use mapping: {example!r}")


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def _selected(case: dict[str, Any]) -> bool:
    return case["selection"]["state"] == "selected"


def _outcome(case: dict[str, Any], stage: str) -> str:
    return case[stage]["outcome"].lower().replace(" ", "_")


def _completed(case: dict[str, Any], stage: str) -> bool:
    return case[stage]["assessment_state"] in {"completed", "assessed"} and bool(case[stage]["run"].strip())


def _security_metrics(cases: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    eligible = [c for c in cases if c["selection"]["state"] in {"selected", "excluded"}
                and c["oracle"]["class"] in {"known_positive", "genuine_safe"}]
    positives = [c for c in eligible if c["oracle"]["class"] == "known_positive" and _selected(c)]
    safes = [c for c in eligible if c["oracle"]["class"] == "genuine_safe"]
    safe_candidates = [c for c in safes if _selected(c)]
    assessed_pos = [c for c in positives if _completed(c, stage)]
    assessed_safe = [c for c in safe_candidates if _completed(c, stage)]
    offline_protected_pos = [c for c in positives if not _completed(c, stage) and _outcome(c, stage) == "protected"]
    offline_protected_safe = [c for c in safe_candidates if not _completed(c, stage)
                              and _outcome(c, stage) == "protected" and bool(c[stage]["use_ids"])]
    missing = [c for c in eligible if _selected(c) and (not c[stage]["use_ids"] or _outcome(c, stage) == "missing")]
    security_cases = [c for c in cases if _selected(c) and c["oracle"]["class"] not in {"practice_expected", "practice_absent"}]
    review = [c for c in security_cases if _outcome(c, stage) in {"review", "needs_review"}]
    no_assessment = [c for c in security_cases if not _completed(c, stage)]
    safe_excluded = [c for c in safes if c["selection"]["state"] == "excluded" and c["selection"]["reason"].strip()]
    unresolved_trust = [c for c in cases if _selected(c) and c["oracle"]["class"] == "unresolved_trust"]
    unjudged_candidates = [c for c in cases if _selected(c) and c["oracle"]["class"] == "unjudged_candidate"]
    unresolved_denominator = [c for c in cases if _selected(c) and c["oracle"]["class"] not in {"practice_expected", "practice_absent"}]
    return {
        "known_positive_recall": _ratio(sum(_completed(c, stage) and _outcome(c, stage) == "confirmed" for c in positives), len(positives)),
        "protected_recognition": _ratio(sum(_outcome(c, stage) == "protected" and bool(c[stage]["use_ids"]) for c in safe_candidates), len(safe_candidates)),
        "safe_exclusions": _ratio(len(safe_excluded), len(safes)),
        "false_confirmed": {**_ratio(sum(_outcome(c, stage) == "confirmed" for c in assessed_safe), len(assessed_safe)),
                            "assessed_all_coverage": _ratio(len(assessed_safe), len(safes))},
        "false_protected": {**_ratio(sum(_outcome(c, stage) == "protected" for c in assessed_pos), len(assessed_pos)),
                            "assessed_all_coverage": _ratio(len(assessed_pos), len(positives))},
        "deterministic_offline_protections": {
            "safe_recognition": _ratio(len(offline_protected_safe), len(safe_candidates)),
            "false_protected_positive": _ratio(len(offline_protected_pos), len(positives)),
            "protected_safe_count": len(offline_protected_safe),
            "protected_positive_count": len(offline_protected_pos),
        },
        "missing_candidates": {oracle: _ratio(sum(c in missing for c in rows), len(rows))
                               for oracle in sorted({c["oracle"]["class"] for c in eligible})
                               for rows in [[c for c in eligible if _selected(c) and c["oracle"]["class"] == oracle]]},
        "unresolved": {"trust_boundary": _ratio(len(unresolved_trust), len(unresolved_denominator)),
                       "unjudged_candidate_count": len(unjudged_candidates)},
        "review_burden": _ratio(len(review), len(security_cases)),
        "review_counts": {"review": len(review), "not_run": sum(c[stage]["assessment_state"] == "not_run" for c in security_cases),
                          "failed": sum(c[stage]["assessment_state"] == "failed" for c in security_cases),
                          "judged_unresolved": sum(_completed(c, stage) and _outcome(c, stage) in {"review", "needs_review"} for c in security_cases)},
        "unjudged_workload": _ratio(len(no_assessment), len(security_cases)),
        "selected_positive_count": len(positives), "selected_safe_count": len(safe_candidates),
    }


def _practice_metrics(cases: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    practice = [c for c in cases if _selected(c) and c["oracle"]["class"] in {"practice_expected", "practice_absent"}]
    measured = [c for c in practice if _outcome(c, stage) in {"emitted", "absent"}]
    emitted = [c for c in measured if _outcome(c, stage) == "emitted"]
    expected = [c for c in practice if c["oracle"]["class"] == "practice_expected"]
    correctly_emitted = sum(c in emitted and c["oracle"]["class"] == "practice_expected" for c in practice)
    detected = sum(c in emitted for c in expected)
    return {"precision": _ratio(correctly_emitted, len(emitted)),
            "recall": _ratio(detected, len(expected)),
            "emitted": len(emitted), "expected": len(expected),
            "expected_total": sum(c["oracle"]["class"] == "practice_expected" for c in practice),
            "pending": len(practice) - len(measured),
            "poor_practice_count": sum(_outcome(c, stage) == "poor_practice" for c in practice)}


def _defect_metrics(cases: list[dict[str, Any]], stage: str) -> dict[str, Any]:
    classes = sorted({case["oracle"]["class"] for case in cases})
    positive_contexts = [case for case in cases if case["oracle"]["class"] == "known_positive"]
    safe_contexts = [case for case in cases if case["oracle"]["class"] == "genuine_safe" and _selected(case)]
    confirmed_contexts = sum(_completed(case, stage) and _outcome(case, stage) == "confirmed"
                             for case in positive_contexts)
    protected_contexts = sum(_outcome(case, stage) == "protected" and bool(case[stage]["use_ids"])
                             for case in safe_contexts)
    recalled = any(_completed(case, stage) and _outcome(case, stage) == "confirmed"
                   for case in positive_contexts)
    return {"oracle_class": classes[0] if len(classes) == 1 else "mixed",
            "oracle_classes": classes,
            "context_count": len(cases),
            "known_positive_contexts": len(positive_contexts),
            "confirmed_contexts": confirmed_contexts,
            "recalled": recalled,
            "positive_defect_recall": _ratio(int(recalled), int(bool(positive_contexts))),
            "positive_context_coverage": _ratio(confirmed_contexts, len(positive_contexts)),
            "safe_candidate_contexts": len(safe_contexts),
            "protected_contexts": protected_contexts,
            "recognized_safe": (protected_contexts > 0) if safe_contexts else None,
            "safe_context_coverage": _ratio(protected_contexts, len(safe_contexts)),
            "safe_defect_recognition": _ratio(int(protected_contexts > 0), int(bool(safe_contexts)))}


def _defect_summary(defects: dict[str, dict[str, Any]]) -> dict[str, Any]:
    positive = [item for item in defects.values() if item["oracle_class"] == "known_positive"]
    safe = [item for item in defects.values() if item["safe_candidate_contexts"] > 0]
    positive_metric = _ratio(sum(item["positive_defect_recall"]["numerator"] for item in positive),
                             sum(item["positive_defect_recall"]["denominator"] for item in positive))
    safe_metric = _ratio(sum(item["safe_defect_recognition"]["numerator"] for item in safe), len(safe))
    safe_context_metric = _ratio(sum(item["protected_contexts"] for item in safe),
                                  sum(item["safe_candidate_contexts"] for item in safe))
    return {"known_positive_defect_recall": positive_metric,
            "genuine_safe_defect_recognition": safe_metric,
            "genuine_safe_context_recognition": safe_context_metric,
            "known_positive_defects": len(positive),
            "genuine_safe_candidate_defects": len(safe),
            "note": "One protected context recognizes a safe defect for this representative metric; context coverage is separate and does not certify every route or sink."}


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce deterministic per-phase metrics overall, by family, and by defect."""
    output: dict[str, Any] = {"schema_version": 1,
                              "selection_summary": {state: sum(c["selection"]["state"] == state for c in cases)
                                                     for state in sorted(SELECTION_STATES)},
                              "phases": {}}
    metric_cases = [c for c in cases if c["selection"]["state"] in {"selected", "excluded"}]
    for stage in ("baseline", "after"):
        groups: dict[str, list[dict[str, Any]]] = {"overall": metric_cases}
        contexts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for case in metric_cases:
            groups.setdefault("family:" + case["family"], []).append(case)
            groups.setdefault("defect:" + case["defect_id"], []).append(case)
            context_key = json.dumps(_identity(case), separators=(",", ":"), ensure_ascii=False)
            contexts[context_key].append(case)
        phase: dict[str, Any] = {"overall": {"security": _security_metrics(cases, stage),
                                               "practice": _practice_metrics(cases, stage)}}
        phase["by_family"] = {k.removeprefix("family:"): {"security": _security_metrics(v, stage),
                                                            "practice": _practice_metrics(v, stage)}
                              for k, v in sorted(groups.items()) if k.startswith("family:")}
        phase["by_defect"] = {k.removeprefix("defect:"): _defect_metrics(v, stage)
                              for k, v in sorted(groups.items()) if k.startswith("defect:")}
        phase["defect_summary"] = _defect_summary(phase["by_defect"])
        phase["by_context"] = {key: {"case_ids": sorted(c["id"] for c in rows),
                                     "security": _security_metrics(rows, stage),
                                     "practice": _practice_metrics(rows, stage)}
                               for key, rows in sorted(contexts.items())}
        output["phases"][stage] = phase
    return output


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", metavar="CASES.json", required=True, help="validate a version 1 case matrix")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY,
                        help="predecessor inventory Markdown (default: repository inventory)")
    parser.add_argument("--source-root", type=Path,
                        help="optional immutable target root; verify every sink file SHA-256")
    parser.add_argument("--before", type=Path, action="append",
                        help="optional before scanner JSON report (repeat for multiple target/run reports)")
    parser.add_argument("--after", type=Path, action="append",
                        help="optional after scanner JSON report (repeat for multiple target/run reports)")
    parser.add_argument("--no-inventory-check", action="store_true",
                        help="skip reconciliation against the 135-row predecessor inventory")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        document = _load_json(Path(args.validate))
        inventory_ids = None if args.no_inventory_check else predecessor_ids_from_inventory(args.inventory)
        cases = validate_cases(document, inventory_ids=inventory_ids, source_root=args.source_root)
        validate_report_references(cases, args.before, "baseline")
        validate_report_references(cases, args.after, "after")
        verified_stages = [stage for stage, paths in (("baseline", args.before), ("after", args.after)) if paths]
        print(json.dumps({"valid": True, "case_count": len(cases),
                          "predecessor_id_count": sum(len(c["predecessor_ids"]) for c in cases),
                          "validation": {"report_mapping": "verified" if verified_stages else "structural_only",
                                         "report_mapping_stages": verified_stages,
                                         "source_hashes": "verified" if args.source_root else "not_requested",
                                         "inventory_reconciliation": "skipped" if args.no_inventory_check else "verified"},
                          "metrics": evaluate(cases)}, indent=2, sort_keys=True))
        return 0
    except EvaluationError as exc:
        print(f"validation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
