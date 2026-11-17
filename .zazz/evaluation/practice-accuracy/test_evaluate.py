"""Hand-computable evaluator contract tests; no scanner or model calls."""

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("evaluate.py")
spec = importlib.util.spec_from_file_location("practice_accuracy_evaluate", MODULE_PATH)
evaluate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate_module)


def case(case_id, oracle, outcome, *, family="sql", defect=None, selection="selected",
         assessment="not_run", use_ids=None, predecessor=None):
    offset = int.from_bytes(case_id.encode("utf-8"), "big")
    return {
        "id": case_id,
        "predecessor_ids": [predecessor or case_id],
        "target": "demo",
        "revision": "a" * 40,
        "family": family,
        "entry": "GET /route",
        "sink": {"file": "src/app.js", "start_byte": offset, "end_byte": offset + 1,
                 "sha256": "b" * 64, "operand": "req.query.value"},
        "defect_id": defect or case_id,
        "oracle": {"class": oracle, "rationale": "source rationale", "source_refs": ["src/app.js:1"], "label_history": []},
        "selection": {"state": selection, "reason": "included for focused evaluation"},
        "baseline": {"run": "baseline-run" if assessment in {"completed", "assessed"} else "",
                     "use_ids": list(use_ids if use_ids is not None else ([case_id + "-use"] if outcome != "missing" else [])),
                     "assessment_state": assessment, "outcome": outcome, "blockers": []},
        "after": {"run": "after-run" if assessment in {"completed", "assessed"} else "",
                  "use_ids": list(use_ids if use_ids is not None else ([case_id + "-use"] if outcome != "missing" else [])),
                  "assessment_state": assessment, "outcome": outcome, "blockers": []},
        "disposition": "retained",
        "evidence_refs": ["evidence.md#case"],
    }


def matrix():
    rows = [
        case("p1", "known_positive", "confirmed", assessment="completed", defect="shared-positive", predecessor="pred-a"),
        case("p2", "known_positive", "missing", defect="shared-positive", predecessor="pred-b"),
        case("s1", "genuine_safe", "protected", assessment="completed", predecessor="pred-c"),
        case("s2", "genuine_safe", "confirmed", assessment="completed", predecessor="pred-d"),
        case("s3", "genuine_safe", "missing", selection="excluded", predecessor="pred-e"),
        case("u1", "unjudged_candidate", "review", assessment="failed", predecessor="pred-f"),
        case("x1", "practice_expected", "emitted", family="NX-BP-11", predecessor="pred-g"),
        case("x2", "practice_expected", "absent", family="NX-BP-21", predecessor="pred-h"),
        case("x3", "practice_absent", "emitted", family="NX-BP-11", predecessor="pred-i"),
    ]
    # Give cases unique sink positions so identities remain distinct even within one defect.
    return rows


def report_use(case_row, use_id, *, kind="sql_query_candidate", operand=None):
    sink = case_row["sink"]
    return {"id": use_id, "entry_id": case_row["entry"], "kind": kind,
            "sink": {"text": operand if operand is not None else sink["operand"], "sha256": sink["sha256"],
                     "span": {key: sink[key] for key in ("file", "start_byte", "end_byte")}}}


class EvaluateTests(unittest.TestCase):
    def test_hand_computable_metrics_and_context_aggregation(self):
        rows = matrix()
        result = evaluate_module.evaluate(rows)["phases"]["after"]["overall"]
        security = result["security"]
        self.assertEqual(security["known_positive_recall"], {"numerator": 1, "denominator": 2, "rate": 0.5})
        self.assertEqual(security["false_confirmed"]["numerator"], 1)
        self.assertEqual(security["false_confirmed"]["denominator"], 2)
        self.assertEqual(security["false_confirmed"]["assessed_all_coverage"]["rate"], 2 / 3)
        self.assertEqual(security["false_protected"]["numerator"], 0)
        self.assertEqual(security["safe_exclusions"], {"numerator": 1, "denominator": 3, "rate": 1 / 3})
        self.assertEqual(security["review_counts"], {"review": 1, "not_run": 1, "failed": 1, "judged_unresolved": 0})
        defect = evaluate_module.evaluate(rows)["phases"]["after"]["by_defect"]["shared-positive"]
        self.assertEqual(defect["context_count"], 2)
        self.assertTrue(defect["recalled"])
        self.assertEqual(defect["positive_defect_recall"], {"numerator": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(defect["safe_context_coverage"]["denominator"], 0)
        practice = result["practice"]
        self.assertEqual(practice["precision"], {"numerator": 1, "denominator": 2, "rate": 0.5})
        self.assertEqual(practice["recall"], {"numerator": 1, "denominator": 2, "rate": 0.5})

    def test_deleting_positive_reduces_recall_denominator(self):
        rows = matrix()
        before = evaluate_module.evaluate(rows)["phases"]["after"]["overall"]["security"]["known_positive_recall"]
        kept = [row for row in rows if row["id"] != "p1"]
        after = evaluate_module.evaluate(kept)["phases"]["after"]["overall"]["security"]["known_positive_recall"]
        self.assertEqual(before["rate"], 0.5)
        self.assertEqual(after, {"numerator": 0, "denominator": 1, "rate": 0.0})

    def test_output_stable_when_case_rows_reordered(self):
        rows = matrix()
        normal = evaluate_module.evaluate(rows)
        reordered = evaluate_module.evaluate(list(reversed(rows)))
        self.assertEqual(normal, reordered)

    def test_zero_denominators_are_null(self):
        result = evaluate_module.evaluate([case("n1", "unjudged_candidate", "review")])["phases"]["after"]["overall"]
        self.assertIsNone(result["security"]["known_positive_recall"]["rate"])
        self.assertIsNone(result["security"]["false_confirmed"]["rate"])
        self.assertIsNone(result["practice"]["precision"]["rate"])

    def test_carried_rows_are_reported_but_excluded_from_selected_denominators(self):
        rows = [case("carried", "known_positive", "confirmed", selection="carried"),
                case("selected", "known_positive", "missing")]
        report = evaluate_module.evaluate(rows)
        self.assertEqual(report["selection_summary"]["carried"], 1)
        self.assertEqual(report["selection_summary"]["selected"], 1)
        self.assertEqual(report["phases"]["after"]["overall"]["security"]["known_positive_recall"],
                         {"numerator": 0, "denominator": 1, "rate": 0.0})
        phase = report["phases"]["after"]
        self.assertEqual(len(phase["by_context"]), 1)
        self.assertEqual(set(phase["by_defect"]), {"selected"})

    def test_pending_practice_cases_are_not_treated_as_absent(self):
        detected = case("detected", "practice_expected", "emitted")
        pending = case("pending", "practice_expected", "pending", assessment="pending", use_ids=[])
        practice = evaluate_module.evaluate([detected, pending])["phases"]["after"]["overall"]["practice"]
        self.assertEqual(practice["recall"], {"numerator": 1, "denominator": 2, "rate": 0.5})
        self.assertEqual(practice["pending"], 1)
        self.assertEqual(practice["expected_total"], 2)

    def test_missing_safe_case_remains_in_protected_recognition_denominator(self):
        rows = [case("safe-protected", "genuine_safe", "protected"),
                case("safe-missing", "genuine_safe", "missing")]
        metric = evaluate_module.evaluate(rows)["phases"]["after"]["overall"]["security"]["protected_recognition"]
        self.assertEqual(metric, {"numerator": 1, "denominator": 2, "rate": 0.5})

    def test_confirmed_without_completed_assessment_does_not_count_as_recall(self):
        row = case("unassessed-positive", "known_positive", "confirmed", assessment="not_run")
        metric = evaluate_module.evaluate([row])["phases"]["after"]["overall"]["security"]["known_positive_recall"]
        self.assertEqual(metric, {"numerator": 0, "denominator": 1, "rate": 0.0})

    def test_carried_safe_case_does_not_inflate_selected_safe_denominator(self):
        rows = [case("carried-safe", "genuine_safe", "protected", selection="carried"),
                case("selected-safe", "genuine_safe", "missing")]
        metric = evaluate_module.evaluate(rows)["phases"]["after"]["overall"]["security"]["protected_recognition"]
        self.assertEqual(metric, {"numerator": 0, "denominator": 1, "rate": 0.0})

    def test_offline_protections_are_reported_separately_from_semantic_error_rates(self):
        rows = [case("offline-safe", "genuine_safe", "protected", assessment="not_run"),
                case("offline-positive", "known_positive", "protected", assessment="not_run"),
                case("semantic-positive", "known_positive", "confirmed", assessment="completed")]
        security = evaluate_module.evaluate(rows)["phases"]["after"]["overall"]["security"]
        offline = security["deterministic_offline_protections"]
        self.assertEqual(offline["safe_recognition"], {"numerator": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(offline["false_protected_positive"], {"numerator": 1, "denominator": 2, "rate": 0.5})
        self.assertEqual(security["false_protected"]["denominator"], 1)

    def test_defect_metrics_count_safe_recognition_once_and_keep_context_coverage(self):
        rows = [case("safe-context-1", "genuine_safe", "protected", assessment="not_run", defect="safe-defect"),
                case("safe-context-2", "genuine_safe", "missing", assessment="not_run", use_ids=[], defect="safe-defect"),
                case("positive-context-1", "known_positive", "confirmed", assessment="completed", defect="positive-defect"),
                case("positive-context-2", "known_positive", "missing", assessment="not_run", use_ids=[], defect="positive-defect")]
        phase = evaluate_module.evaluate(rows)["phases"]["after"]
        defects = phase["by_defect"]
        self.assertEqual(defects["safe-defect"]["safe_defect_recognition"],
                         {"numerator": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(defects["safe-defect"]["protected_contexts"], 1)
        self.assertEqual(defects["safe-defect"]["safe_context_coverage"],
                         {"numerator": 1, "denominator": 2, "rate": 0.5})
        self.assertEqual(defects["positive-defect"]["positive_defect_recall"],
                         {"numerator": 1, "denominator": 1, "rate": 1.0})
        summary = phase["defect_summary"]
        self.assertEqual(summary["known_positive_defect_recall"], {"numerator": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(summary["genuine_safe_defect_recognition"], {"numerator": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(summary["genuine_safe_context_recognition"], {"numerator": 1, "denominator": 2, "rate": 0.5})

    def test_validation_rejects_duplicates_mixed_defects_and_missing_predecessors(self):
        rows = matrix()
        doc = {"schema_version": 1, "cases": rows}
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "duplicate case id"):
            evaluate_module.validate_cases({"schema_version": 1, "cases": rows + [copy.deepcopy(rows[0])]}, inventory_ids={f"pred-{x}" for x in "abcdefghi"})
        mixed = copy.deepcopy(rows[:2])
        mixed[1]["oracle"]["class"] = "genuine_safe"
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "mixes known_positive and genuine_safe"):
            evaluate_module.validate_cases({"schema_version": 1, "cases": mixed}, inventory_ids={"pred-a", "pred-b"})
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "unaccounted predecessor"):
            evaluate_module.validate_cases(doc, inventory_ids={f"pred-{x}" for x in "abcdefghij"})

    def test_safe_exclusion_requires_a_source_supported_safe_oracle(self):
        row = case("excluded", "unjudged_candidate", "missing", selection="excluded")
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "only a genuine_safe oracle"):
            evaluate_module.validate_cases({"schema_version": 1, "cases": [row]})

    def test_validation_rejects_ambiguous_inventory_mapping_and_stale_hash(self):
        rows = matrix()[:2]
        rows[1]["predecessor_ids"] = ["pred-a"]
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "maps ambiguously"):
            evaluate_module.validate_cases({"schema_version": 1, "cases": rows})

        row = copy.deepcopy(matrix()[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            source = root / "src/app.js"
            source.write_text("source", encoding="utf-8")
            row["sink"]["sha256"] = hashlib.sha256(b"source").hexdigest()
            self.assertEqual(len(evaluate_module.validate_cases({"schema_version": 1, "cases": [row]}, source_root=root)), 1)
            row["sink"]["sha256"] = hashlib.sha256(b"stale").hexdigest()
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "stale source hash"):
                evaluate_module.validate_cases({"schema_version": 1, "cases": [row]}, source_root=root)

    def test_unavailable_source_hash_is_carry_only_and_cannot_claim_validation(self):
        row = case("carry-no-hash", "unjudged_candidate", "pending", selection="carried")
        row["sink"]["sha256"] = None
        self.assertEqual(len(evaluate_module.validate_cases({"schema_version": 1, "cases": [row]})), 1)
        malformed = copy.deepcopy(row)
        malformed["selection"] = "carried"
        with self.assertRaisesRegex(evaluate_module.EvaluationError, "may be null only for carried"):
            evaluate_module.validate_cases({"schema_version": 1, "cases": [malformed]})
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "unavailable source hash"):
                evaluate_module.validate_cases({"schema_version": 1, "cases": [row]}, source_root=Path(directory))

    def test_report_references_must_exist_and_be_unambiguous(self):
        rows = matrix()[:2]
        rows[1]["baseline"]["use_ids"] = ["absent-use"]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"uses": [report_use(rows[0], "p1-use")]}), encoding="utf-8")
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "references absent report use"):
                evaluate_module.validate_report_references(rows, report, "baseline")
            rows[0]["baseline"]["use_ids"] = ["shared"]
            rows[1]["baseline"]["use_ids"] = ["shared"]
            rows[1]["sink"] = copy.deepcopy(rows[0]["sink"])
            rows[1]["entry"] = rows[0]["entry"]
            report.write_text(json.dumps({"uses": [report_use(rows[0], "shared")]}), encoding="utf-8")
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "ambiguous baseline report use mapping"):
                evaluate_module.validate_report_references(rows, report, "baseline")

    def test_report_id_cannot_override_a_changed_sink_identity(self):
        row = case("mapped", "known_positive", "missing", use_ids=["same-id"])
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"uses": [report_use(row, "same-id", operand="different operand")]}),
                              encoding="utf-8")
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "different operand"):
                evaluate_module.validate_report_references([row], report, "baseline")
            report.write_text(json.dumps({"uses": [report_use(row, "same-id", kind="xss_candidate")]}),
                              encoding="utf-8")
            with self.assertRaisesRegex(evaluate_module.EvaluationError, "incompatible with family"):
                evaluate_module.validate_report_references([row], report, "baseline")

    def test_cli_without_reports_marks_mapping_structural_only(self):
        with tempfile.TemporaryDirectory() as directory:
            matrix_path = Path(directory) / "cases.json"
            matrix_path.write_text('{"schema_version":1,"cases":[]}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = evaluate_module.main(["--validate", str(matrix_path), "--no-inventory-check"])
            self.assertEqual(status, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["validation"]["report_mapping"], "structural_only")
            self.assertEqual(result["validation"]["source_hashes"], "not_requested")


if __name__ == "__main__":
    unittest.main()
