"""Synthetic publication tests: no research observations or production writes."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

PATH = Path(__file__).resolve().parents[1] / "internal/publication.py"
SPEC = importlib.util.spec_from_file_location("test_publication_module", PATH)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="liemapp-publication-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.raw = self.root / "raw/first-run"
        self.raw.mkdir(parents=True)
        self.logs = self.root / "public/logs/engine"
        self.reports = self.root / "public/reports/engine"
        self.internal = self.root / "private/analyses/engine"
        self.source = self.root / "source.py"
        self.source.write_text("# Synthetic source, not an actual engine\n")
        self.source_hash = publication._hash(self.source)
        self.events = []
        self.add_event()
        self.rules_path = self.root / "rules.json"
        self.rules = {"attack_id": "synthetic-attack", "attack_name": "합성 테스트 공격",
            "library": {"path": "synthetic.xlsx", "sha256": "0" * 64, "sheet": "test", "row": 1},
            "conditions": [{"id": f"{kind}{number}", "kind": kind, "text": "원본 조건 질문",
                            "source_cell": "A1", "operationalization": "전체 원본 숫자를 검사합니다.",
                            "rule": {"op": "compare", "scope": "runtime", "select": {"stage": "encode"},
                                     "field": "raw.ok", "cmp": "eq", "value": True}}
                           for kind in ("AC", "DC") for number in (1, 2, 3)]}
        self.write_rules()
        self.seal()

    def add_event(self, *, engine="engine-a", scope="native_runtime", raw=None):
        self.events.append({"schema_version": "1.0.0", "event_id": f"synthetic-{len(self.events)}",
            "run_id": "synthetic-unit", "sequence": len(self.events) + 1,
            "timestamp_utc": "2026-09-07T01:02:03+00:00",
            "metadata": {"attack_id": "synthetic-attack", "engine": {"id": engine, "revision": "test"},
                         "execution_scope": scope, "model": {"name": "합성 모델"}, "giant_metadata": "do not repeat"},
            "stage": "encode", "context": {"request_id": "synthetic-request", "input_id": "input-1"},
            "source": {"path": str(self.source), "function": "synthetic_function", "line": 1,
                       "logging_point_id": "synthetic-point", "sha256": self.source_hash},
            "raw": raw if raw is not None else {"ok": True}, "readable": {"ok": False},
            "artifacts": {}, "previous_event_hash": None})

    def write_rules(self):
        self.rules_path.write_text(json.dumps(self.rules, ensure_ascii=False))

    def seal(self, status="completed", filename="events.jsonl"):
        previous = None
        for number, event in enumerate(self.events, 1):
            event["sequence"] = number
            event["previous_event_hash"] = previous
            event.pop("event_hash", None)
            event["event_hash"] = hashlib.sha256(publication.analyzer.canonical_json(event)).hexdigest()
            previous = event["event_hash"]
        self.log_path = self.raw / filename
        self.log_path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in self.events))
        (self.raw / "seal.json").write_text(json.dumps({"schema_version": "1.0.0", "run_id": "synthetic-unit",
            "event_count": len(self.events), "last_event_hash": previous, "status": status,
            "events_sha256": publication._hash(self.log_path), "reason": None if status == "completed" else "Synthetic execution unavailable"}))

    def tensor(self, values):
        array = np.asarray(values)
        path = self.raw / "tensor.npy"
        np.save(path, array, allow_pickle=False)
        self.events[0]["artifacts"]["values"] = {"path": path.name, "sha256": publication._hash(path),
            "dtype": str(array.dtype), "shape": list(array.shape), "bytes": path.stat().st_size, "preview": [999]}
        self.seal()

    def publish(self, **kwargs):
        return publication.publish(self.log_path, self.rules_path, log_output_dir=self.logs,
            report_output_dir=self.reports, analysis_dir=self.internal, **kwargs)

    def document(self, condition="AC1", attack="synthetic-attack", engine="engine-a"):
        return json.loads((self.logs / f"{attack}-{condition}-{engine}-LogFile.json").read_text())

    def test_six_readable_json_one_report_and_private_original_analysis(self):
        before = publication._hash(self.log_path)
        result = self.publish()
        self.assertEqual(len(list(self.logs.iterdir())), 6)
        self.assertEqual([p.name for p in self.reports.iterdir()], ["synthetic-attack-engine-a-Report.md"])
        self.assertEqual(result["summary"], {"T": 6, "F": 0, "observed_not_satisfied": 0, "not_evaluated": 0})
        self.assertNotIn("evidence", result)
        self.assertEqual(publication._hash(self.log_path), before)
        self.assertEqual(set(p.name for p in self.internal.iterdir()), {"analysis.json", "report.md", "publication.json"})
        doc = self.document()
        self.assertEqual(list(doc)[1:6], ["summary", "question", "measurement_plan", "measurements", "judgment_basis"])
        self.assertNotIn("metadata", doc["events"][0])
        self.assertNotIn("giant_metadata", json.dumps(doc))
        self.assertIs(doc["events"][0]["raw"]["ok"], True)

    def test_pure_renderer_replays_every_json_and_markdown_without_writes(self):
        self.tensor(np.arange(12, dtype=np.float32))
        manifest = self.publish()
        analysis = publication._read(self.internal / "analysis.json")
        original_analysis = copy.deepcopy(analysis)
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        with patch.object(publication, "_dump", side_effect=AssertionError("Renderer attempted a write")):
            documents, report = publication.render_documents(analysis,
                targets={key: Path(path) for key, path in manifest["condition_files"].items()},
                report_path=Path(manifest["report"]), presentation={}, presentation_path=None,
                mapping={}, mapping_path=None, internal_file=self.internal / "analysis.json",
                internal_sha256=publication._hash(self.internal / "analysis.json"), supplements=[],
                attack_label="synthetic-attack", engine_label="engine-a")
        self.assertEqual(analysis, original_analysis)
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
        self.assertEqual(report, Path(manifest["report"]).read_text())
        for document in documents:
            identifier = document["summary"]["condition_id"]
            expected = Path(manifest["condition_files"][identifier]).read_text()
            self.assertEqual(json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n", expected)

    def test_pure_renderer_preserves_display_and_unevaluated_supplement_context(self):
        self.seal("blocked")
        supplement_path = self.root / "supplement.json"
        supplement_path.write_text(json.dumps({"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "제약",
            "summary": ["필수 장치 미확보"],
            "source_runs": [{"log_path": str(self.log_path), "events_sha256": publication._hash(self.log_path)}]}))
        presentation_path = self.root / "presentation.json"
        presentation_path.write_text(json.dumps({"attack_id": "synthetic-attack", "purpose": "표시용 목적"}))
        manifest = self.publish(presentation_path=presentation_path, supplement_paths=[supplement_path])
        analysis = publication._read(self.internal / "analysis.json")
        documents, report = publication.render_documents(analysis,
            targets=manifest["condition_files"], report_path=manifest["report"],
            presentation=publication._read(presentation_path), presentation_path=presentation_path,
            mapping={}, mapping_path=None, internal_file=self.internal / "analysis.json",
            internal_sha256=publication._hash(self.internal / "analysis.json"),
            supplements=publication._supplements([supplement_path], analysis),
            attack_label="synthetic-attack", engine_label="engine-a")
        self.assertEqual(report, Path(manifest["report"]).read_text())
        self.assertEqual(documents[0], self.document())
        self.assertEqual(list(documents[0])[2], "supplementary_context")

    def test_evidence_true_false_null_are_not_collapsed_in_publication(self):
        self.events[0]["raw"]["no"] = False
        self.rules["conditions"][1]["rule"]["field"] = "raw.no"
        self.rules["conditions"][2]["rule"]["field"] = "raw.absent"
        self.write_rules(); self.seal(); self.publish()
        a, b, c = (self.document(name)["summary"] for name in ("AC1", "AC2", "AC3"))
        self.assertEqual([a["verdict"], b["verdict"], c["verdict"]], ["T", "F", "F"])
        self.assertEqual([a["evidence_status"], b["evidence_status"], c["evidence_status"]], ["observed_satisfied", "observed_not_satisfied", "not_evaluated"])
        self.assertIsNone(c["evidence_value"])
        self.assertEqual(c["evaluation_reason"], "missing_required_evidence")
        original = json.loads((self.internal / "analysis.json").read_text())
        self.assertIsNone(original["conditions"][2]["value"])

    def test_unavailable_runtime_is_explicit_unevaluated_f_not_safe(self):
        self.events[0]["metadata"]["execution_scope"] = "preflight"
        self.seal("blocked"); self.publish()
        doc = self.document()
        self.assertEqual(doc["summary"]["evaluation_reason"], "scope_unavailable")
        self.assertEqual(doc["summary"]["verdict"], "F")
        self.assertIsNone(doc["summary"]["evidence_value"])
        self.assertEqual(doc["summary"]["evidence_status"], "not_evaluated")
        self.assertIn("안전", doc["summary"]["explanation"])

    def test_incomplete_native_run_is_not_observed_false(self):
        self.seal("failed"); self.publish()
        self.assertEqual(self.document()["summary"]["evaluation_reason"], "run_incomplete")

    def test_two_arbitrary_engines_use_same_evaluation(self):
        for engine in ("engine-a", "completely-different-engine-b"):
            with self.subTest(engine=engine):
                self.events[0]["metadata"]["engine"]["id"] = engine
                self.seal()
                result = publication.publish(self.log_path, self.rules_path,
                    log_output_dir=self.root / engine / "logs", report_output_dir=self.root / engine / "report",
                    analysis_dir=self.root / engine / "analysis")
                self.assertEqual(result["summary"]["T"], 6)

    def test_explicit_labels_preserve_case_and_dot(self):
        result = self.publish(attack_label="SIAI", engine_label="llama.cpp")
        self.assertEqual(Path(result["report"]).name, "SIAI-llama.cpp-Report.md")
        self.assertEqual(self.document(attack="SIAI", engine="llama.cpp")["summary"]["engine_id"], "engine-a")

    def test_unsafe_explicit_filename_labels_are_rejected(self):
        for label in ("../escape", "A/B", "A\\B", ".hidden", "A\nB", "NUL", "NUL.txt", "", "a..b"):
            with self.subTest(label=label), self.assertRaises(publication.PublicationError):
                self.publish(engine_label=label)
        self.assertFalse(self.reports.exists())

    def test_actual_preview_not_descriptor_preview_and_all_numbers_preserved(self):
        values = np.array([2**63 + i for i in range(12)], dtype=np.uint64)
        self.tensor(values); self.publish()
        artifact = self.document()["events"][0]["artifacts"]["values"]
        self.assertEqual(artifact["preview"], values[:8].tolist())
        self.assertFalse(artifact["preview_is_complete"])
        self.assertEqual(artifact["total_element_count"], 12)
        full = (self.logs / artifact["full_value"]["path"]).resolve()
        self.assertEqual(full, self.raw / "tensor.npy")
        self.assertEqual(publication._hash(full), artifact["full_value"]["sha256"])

    def test_actual_log_filename_is_never_guessed(self):
        self.seal(filename="explicit-name.jsonl")
        self.publish()
        path = self.document()["provenance"]["raw_log"]["path"]
        self.assertEqual((self.logs / path).resolve(), self.log_path)

    def test_bad_chain_rejects_before_public_outputs(self):
        self.log_path.write_text(self.log_path.read_text().replace('"ok": true', '"ok": false'))
        with self.assertRaises(publication.analyzer.EvidenceError):
            self.publish()
        self.assertFalse(self.reports.exists())
        self.assertFalse(self.logs.exists())

    def test_bad_artifact_hash_is_not_published_as_f(self):
        self.tensor(np.ones(3, dtype=np.float32))
        (self.raw / "tensor.npy").write_bytes(b"corrupt")
        with self.assertRaises(publication.analyzer.EvidenceError):
            self.publish()
        self.assertFalse(self.reports.exists())

    def test_shape_mismatch_even_outside_evaluation_is_rejected(self):
        self.tensor(np.ones(3, dtype=np.float32))
        self.events[0]["artifacts"]["values"]["shape"] = [99]
        self.seal()
        with self.assertRaises(publication.analyzer.EvidenceError):
            self.publish()

    def test_matching_logging_reason_source_and_units_are_used_only_for_display(self):
        self.tensor(np.array([1, 2], dtype=np.float32))
        mapping = self.root / "mapping.json"
        mapping.write_text(json.dumps({"attack_id": "synthetic-attack", "engine_id": "engine-a",
            "logging_points": [{"logging_point_id": "synthetic-point", "source": self.events[0]["source"],
                "reason": "해당 함수를 기록한 구체적 이유", "condition_ids": ["AC1"], "source_snapshot": "source.py"}]}))
        presentation = self.root / "presentation.json"
        presentation.write_text(json.dumps({"attack_id": "synthetic-attack", "conditions": {"AC1": {
            "question": "이 처리가 완료됐나요?", "explanation": "단순히 코드가 존재하는지와 다릅니다.", "measurement_plan": ["전체 값을 비교합니다."]}},
            "field_labels": {"raw.ok": {"label": "성공 여부", "unit": "참/거짓"}},
            "artifact_labels": {"encode.values": {"label": "실제 입력 값", "unit": "수치 단위"}}}))
        self.publish(mapping_path=mapping, presentation_path=presentation)
        doc = self.document()
        self.assertEqual(doc["question"]["plain"], "이 처리가 완료됐나요?")
        self.assertEqual(doc["logging_points"][0]["reason_origin"], "matching_source_mapping")
        self.assertEqual(doc["events"][0]["artifacts"]["values"]["unit"], "수치 단위")
        self.assertEqual(doc["measurements"]["items"][0]["label"], "성공 여부")
        self.assertIs(doc["summary"]["evidence_value"], True)

    def test_unobserved_candidate_mapping_is_not_claimed_as_runtime(self):
        mapping = self.root / "mapping.json"
        mapping.write_text(json.dumps({"attack_id": "synthetic-attack", "engine_id": "engine-a",
            "logging_points": [{"mapping_id": str(i), "source": None, "reason": "후보일 뿐입니다", "condition_ids": ["AC1"]} for i in range(2)]}))
        self.publish(mapping_path=mapping)
        self.assertEqual([p["observed"] for p in self.document()["logging_points"]], [True, False, False])

    def test_malformed_presentation_is_rejected_without_partial_publication(self):
        path = self.root / "bad-presentation.json"
        path.write_text(json.dumps({"attack_id": "synthetic-attack", "conditions": {"AC1": {"measurement_plan": "not a list"}}}))
        with self.assertRaises(publication.PublicationError):
            self.publish(presentation_path=path)
        self.assertFalse(self.logs.exists())

    def test_supplement_bound_to_verified_source_and_embedded_in_one_report(self):
        path = self.root / "supplement.json"
        data = {"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "별도 관찰",
                "summary": ["이 자료는 공격 성공률이 아닙니다."], "tables": [{"title": "원문", "columns": [{"key": "prompt", "label": "실제 질문"}], "rows": [{"prompt": "<script>alert(1)</script> [fake](javascript:x)"}]}],
                "source_runs": [{"log_path": str(self.log_path), "events_sha256": publication._hash(self.log_path)}]}
        path.write_text(json.dumps(data))
        result = self.publish(supplement_paths=[path])
        report = Path(result["report"]).read_text()
        self.assertIn("별도 보조 관찰", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("[fake](javascript:x)", report)
        self.assertEqual(len(list(self.reports.iterdir())), 1)

    def test_foreign_or_bad_hash_supplement_is_rejected(self):
        path = self.root / "supplement.json"
        data = {"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "보조", "source_runs": [{"log_path": str(self.log_path), "events_sha256": "0" * 64}]}
        path.write_text(json.dumps(data))
        with self.assertRaises(publication.analyzer.EvidenceError):
            self.publish(supplement_paths=[path])
        data["engine_id"] = "other-engine"
        path.write_text(json.dumps(data))
        with self.assertRaises(publication.PublicationError):
            self.publish(supplement_paths=[path])

    def test_unevaluated_json_has_separate_readable_context_not_measured_evidence(self):
        self.seal("blocked")
        path = self.root / "supplement.json"
        path.write_text(json.dumps({"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "실행 제약",
            "summary": ["합성 시험에서는 필요한 장치를 사용할 수 없습니다."],
            "source_runs": [{"log_path": str(self.log_path), "events_sha256": publication._hash(self.log_path)}]}))
        self.publish(supplement_paths=[path])
        document = self.document()
        self.assertEqual(list(document)[2], "supplementary_context")
        self.assertFalse(document["supplementary_context"][0]["used_for_verdict"])
        self.assertIn("필요한 장치", document["supplementary_context"][0]["summary"][0])
        self.assertEqual(document["summary"]["evidence_status"], "not_evaluated")
        self.assertIsNone(document["summary"]["evidence_value"])

    def test_observed_condition_does_not_mix_supplements_into_evidence_json(self):
        path = self.root / "supplement.json"
        path.write_text(json.dumps({"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "별도 관찰",
            "summary": ["보조 관찰은 측정값이 아닙니다."],
            "source_runs": [{"log_path": str(self.log_path), "events_sha256": publication._hash(self.log_path)}]}))
        self.publish(supplement_paths=[path])
        self.assertNotIn("supplementary_context", self.document())

    def test_long_supplement_text_is_preserved_in_safely_fenced_row_details(self):
        path = self.root / "supplement.json"
        prompt = "실제 질문입니다.\n```\n<script>not active</script>\n" + "원문 " * 50
        data = {"attack_id": "synthetic-attack", "engine_id": "engine-a", "title": "원문 관찰",
                "tables": [{"columns": [{"key": "prompt", "label": "실제 질문"}], "rows": [{"prompt": prompt}]}],
                "source_runs": [{"log_path": str(self.log_path), "events_sha256": publication._hash(self.log_path)}]}
        path.write_text(json.dumps(data))
        report = Path(self.publish(supplement_paths=[path])["report"]).read_text()
        self.assertIn("<details><summary>관찰 1", report)
        self.assertIn("````text\n" + prompt + "\n````", report)
        self.assertNotIn("| 실제 질문 |", report)

    def test_requested_model_is_not_presented_as_successfully_loaded(self):
        self.events[0]["metadata"].pop("model")
        self.events[0]["metadata"]["requested_model"] = {"name": "candidate-model"}
        self.events[0]["metadata"]["runtime"] = {"device_available": False}
        self.seal("blocked")
        report = Path(self.publish()["report"]).read_text()
        self.assertIn("실행 전 검토 모델(로드 성공 의미 아님): candidate-model", report)
        self.assertIn('"device_available": false', report)

    def test_changed_labels_are_rejected_without_retaining_stale_publications(self):
        self.publish()
        before = {path: path.read_bytes() for path in [*self.logs.iterdir(), *self.reports.iterdir(), *self.internal.iterdir()]}
        for private in (self.internal, self.root / "private/new-analysis"):
            with self.subTest(analysis_dir=private), self.assertRaisesRegex(publication.PublicationError, "migration"):
                publication.publish(self.log_path, self.rules_path, log_output_dir=self.logs,
                    report_output_dir=self.reports, analysis_dir=private, engine_label="engine-renamed",
                    replace=True, backup_dir=self.root / "new-backup")
            self.assertFalse((self.root / "new-backup").exists())
        self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))
        self.assertEqual(len(list(self.logs.iterdir())), 6)
        self.assertEqual(len(list(self.reports.iterdir())), 1)

    def test_changed_condition_set_requires_explicit_migration(self):
        self.publish()
        self.rules["conditions"].pop()
        self.write_rules()
        with self.assertRaisesRegex(publication.PublicationError, "migration"):
            self.publish(replace=True, backup_dir=self.root / "backup")
        self.assertEqual(len(list(self.logs.iterdir())), 6)

    def test_equal_labels_do_not_authorize_replacing_a_different_engine(self):
        self.publish(engine_label="display-name")
        self.events[0]["metadata"]["engine"]["id"] = "different-engine"
        self.seal()
        with self.assertRaisesRegex(publication.PublicationError, "different attack/engine"):
            publication.publish(self.log_path, self.rules_path, log_output_dir=self.logs,
                report_output_dir=self.reports, analysis_dir=self.root / "private/new-analysis",
                engine_label="display-name", replace=True, backup_dir=self.root / "backup")

    def test_no_overwrite_without_explicit_backup(self):
        self.publish()
        before = {path: path.read_bytes() for path in [*self.logs.iterdir(), *self.reports.iterdir(), *self.internal.iterdir()]}
        with self.assertRaises(FileExistsError):
            self.publish()
        with self.assertRaises(publication.PublicationError):
            self.publish(replace=True)
        self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))

    def test_replace_backs_up_exact_previous_files_and_preserves_unrelated_files(self):
        self.publish()
        unrelated = self.reports / "user-note.txt"
        unrelated.write_text("사용자 파일")
        old_report = next(self.reports.glob("*.md")).read_bytes()
        self.events[0]["raw"]["ok"] = False
        self.seal()
        backup = self.root / "backup/new-publication"
        result = self.publish(replace=True, backup_dir=backup)
        backup_manifest = json.loads((backup / "backup.json").read_text())
        saved = next(Path(item["backup"]) for item in backup_manifest["files"] if item["original"].endswith(".md"))
        self.assertEqual(saved.read_bytes(), old_report)
        self.assertEqual(result["summary"]["observed_not_satisfied"], 6)
        self.assertEqual(unrelated.read_text(), "사용자 파일")
        self.assertTrue((backup / "internal-analysis/publication.json").is_file())

    def test_install_failure_rolls_back_previous_public_and_internal_files(self):
        self.publish()
        before = {path: path.read_bytes() for path in [*self.logs.iterdir(), *self.reports.iterdir(), *self.internal.iterdir()]}
        self.events[0]["raw"]["ok"] = False
        self.seal()
        original = publication._atomic_copy
        calls = 0
        def failing(source, target, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("Synthetic install failure")
            return original(source, target, **kwargs)
        with patch.object(publication, "_atomic_copy", side_effect=failing), self.assertRaisesRegex(OSError, "Synthetic"):
            self.publish(replace=True, backup_dir=self.root / "backup")
        self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))
        self.assertFalse(list(self.reports.glob("*.lock")))

    def test_raw_and_public_directory_overlap_is_rejected(self):
        with self.assertRaises(publication.PublicationError):
            publication.publish(self.log_path, self.rules_path, log_output_dir=self.raw / "logs",
                report_output_dir=self.reports, analysis_dir=self.internal)
        with self.assertRaises(publication.PublicationError):
            publication.publish(self.log_path, self.rules_path, log_output_dir=self.logs,
                report_output_dir=self.reports, analysis_dir=self.logs / "private")

    def test_symlink_output_target_is_not_replaced(self):
        self.logs.mkdir(parents=True)
        target = self.logs / "synthetic-attack-AC1-engine-a-LogFile.json"
        target.symlink_to(self.source)
        with self.assertRaises(publication.PublicationError):
            self.publish(replace=True, backup_dir=self.root / "backup")
        self.assertEqual(publication._hash(self.source), self.source_hash)

    def test_unrelated_internal_files_are_not_replaced(self):
        self.publish()
        note = self.internal / "user-note.txt"
        note.write_text("preserve")
        with self.assertRaises(publication.PublicationError):
            self.publish(replace=True, backup_dir=self.root / "backup")
        self.assertEqual(note.read_text(), "preserve")

    def test_cli_reports_invalid_evidence_without_publishing_f(self):
        (self.raw / "seal.json").unlink()
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            status = publication.main(["--log", str(self.log_path), "--rules", str(self.rules_path),
                "--log-output-dir", str(self.logs), "--report-output-dir", str(self.reports),
                "--analysis-dir", str(self.internal)])
        self.assertEqual(status, 2)
        self.assertIn("rejected", errors.getvalue())
        self.assertFalse(self.reports.exists())


if __name__ == "__main__":
    unittest.main()
