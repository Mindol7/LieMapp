"""MLC pipeline control-flow tests; no model, public HTTP or real evidence writes."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm/complete_run.py"
spec = importlib.util.spec_from_file_location("mlc_completion_pipeline_tests", SCRIPT)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.mapping = self.root / "mapping/public-http-native-v1"
        self.here = self.root / "scripts/mlc-llm"
        self.here.mkdir(parents=True)
        self.mapping.mkdir(parents=True)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in {"ROOT": self.root, "HERE": self.here, "MAPPING_BASE": self.mapping.parent,
                            "MAPPING": self.mapping, "SUPPLEMENT": self.root / ".evidence/supplements/context.json",
                            "READY": self.here / "evaluation-readiness.json", "CONFIG": self.root / "config.json",
                            "PYTHON": Path(sys.executable)}.items():
            self.stack.enter_context(patch.object(P, name, value))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.args = SimpleNamespace(run_id="unit-native-run", parity=self.root / ".evidence/audits/parity.json",
                                    development_run=self.root / ".evidence/raw/ama/mlc-llm/unit-development")

    def create(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        return path

    def pipeline(self):
        path = self.root / ".evidence/pipelines/unit-native-run"
        path.mkdir(parents=True)
        return path

    def test_only_safe_single_component_run_ids(self):
        for value in ("", ".", "..", "../escape", "a/b", "a\\b", " space", "a\nb", "한글", "a" * 129):
            with self.subTest(value=value), self.assertRaises(ValueError):
                P.paths_for(value)
        self.assertEqual(P.paths_for("ama-mlc-001")["run"].name, "ama-mlc-001")

    def test_existing_raw_mapping_context_pipeline_or_audit_is_never_reused(self):
        paths = P.paths_for(self.args.run_id)
        P.unused_outputs(paths)
        for key, value in paths.items():
            with self.subTest(key=key):
                value.parent.mkdir(parents=True, exist_ok=True)
                value.touch()
                with self.assertRaises(FileExistsError):
                    P.unused_outputs(paths)
                value.unlink()

    def test_existing_rule_directory_is_allowed(self):
        self.create(self.mapping / "conditions.json", {"existing": "preserved"})
        P.unused_outputs(P.paths_for(self.args.run_id))
        self.assertEqual(json.loads((self.mapping / "conditions.json").read_text()), {"existing": "preserved"})

    def test_symlinked_output_parent_is_rejected(self):
        external = self.root / "external"
        external.mkdir()
        alias = self.root / ".evidence/raw"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlinked output"):
            P.paths_for(self.args.run_id)

    def test_exact_order_and_explicit_log_no_second_inference(self):
        paths = P.paths_for(self.args.run_id)
        commands = P.commands(self.args, paths)
        self.assertEqual([name for name, _ in commands], ["00-readiness", "01-native-evaluation", "02-source-mapping",
                         "03-readable-context", "04-common-publication", "05-independent-audit"])
        evaluation = commands[1][1]
        self.assertEqual(evaluation[evaluation.index("--timeout") + 1], "1800")
        publication = commands[4][1]
        self.assertNotIn("--execute", publication)
        self.assertEqual(publication[publication.index("--log") + 1], str(paths["run"] / "events.jsonl"))
        self.assertIn("--replace", publication)
        self.assertIn("--publication", commands[5][1])
        self.assertIn("--parity", commands[5][1])

    def test_stage_records_actual_stdout_stderr_and_exit(self):
        directory = self.pipeline()
        command = [sys.executable, "-B", "-c", "import sys; print('unit stdout'); print('unit stderr', file=sys.stderr)"]
        result = P.run_stage("unit", command, directory, [])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual((directory / "unit/stdout.log").read_text(), "unit stdout\n")
        self.assertEqual((directory / "unit/stderr.log").read_text(), "unit stderr\n")
        recorded = P.read(directory / "unit/command.json")
        self.assertEqual(recorded["command"], command)
        self.assertIs(recorded["shell"], False)
        self.assertIs(P.read(directory / "unit/result.json")["process_started"], True)

    def test_nonzero_exit_stops_with_preserved_logs(self):
        directory = self.pipeline()
        with self.assertRaises(P.StageFailure):
            P.run_stage("unit", [sys.executable, "-B", "-c", "print('partial'); raise SystemExit(7)"], directory, [])
        result = P.read(directory / "unit/result.json")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["status"], "failed")
        self.assertIn("partial", (directory / "unit/stdout.log").read_text())

    def test_spawn_error_is_recorded_without_fake_exit_zero(self):
        directory = self.pipeline()
        with self.assertRaises(P.StageFailure):
            P.run_stage("unit", [str(self.root / "nonexistent-program")], directory, [])
        result = P.read(directory / "unit/result.json")
        self.assertIsNone(result["exit_code"])
        self.assertFalse(result["process_started"])
        self.assertEqual(result["error"]["type"], "FileNotFoundError")

    def test_dependency_change_stops_before_spawn(self):
        directory = self.pipeline()
        path = self.create(self.root / "source.py", "original")
        records = [P.descriptor(path)]
        path.write_text("changed")
        with patch.object(P.subprocess, "Popen") as spawn, self.assertRaises(P.StageFailure):
            P.run_stage("unit", ["not-executed"], directory, records)
        spawn.assert_not_called()
        self.assertFalse(P.read(directory / "unit/result.json")["process_started"])

    def test_no_stage_after_failure_and_no_completed_status(self):
        def stage(name, *_):
            if name == "01-native-evaluation":
                raise P.StageFailure("unit controlled failure")
            return {"stage": name}
        with patch.object(P, "snapshot_dependencies", return_value=[]), patch.object(P, "run_stage", side_effect=stage) as run:
            self.assertEqual(P.execute(self.args), 1)
        self.assertEqual(run.call_count, 2)
        result = P.read(P.paths_for(self.args.run_id)["pipeline"] / "pipeline-result.json")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["passed_stages"], ["00-readiness"])

    def test_zero_exit_does_not_publish_incomplete_run(self):
        with patch.object(P, "snapshot_dependencies", return_value=[]), \
             patch.object(P, "run_stage", side_effect=lambda name, *_: {"stage": name}) as run:
            self.assertEqual(P.execute(self.args), 1)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(P.read(P.paths_for(self.args.run_id)["pipeline"] / "pipeline-result.json")["status"], "failed")

    def test_exit_zero_without_final_audit_never_means_completed(self):
        with patch.object(P, "snapshot_dependencies", return_value=[]), patch.object(P, "check_run", return_value="hash"), \
             patch.object(P, "run_stage", side_effect=lambda name, *_: {"stage": name}) as run:
            self.assertEqual(P.execute(self.args), 1)
        self.assertEqual(run.call_count, 6)
        result = P.read(P.paths_for(self.args.run_id)["pipeline"] / "pipeline-result.json")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_stage"], "final-artifact-validation")

    def test_completed_only_after_all_stages_and_final_artifact_validation(self):
        with patch.object(P, "snapshot_dependencies", return_value=[]), patch.object(P, "check_run", return_value="hash"), \
             patch.object(P, "completion_artifacts", return_value=[{"unit": "checked"}]) as final, \
             patch.object(P, "run_stage", side_effect=lambda name, *_: {"stage": name}) as run:
            self.assertEqual(P.execute(self.args), 0)
        self.assertEqual(run.call_count, 6)
        final.assert_called_once()
        result = P.read(P.paths_for(self.args.run_id)["pipeline"] / "pipeline-result.json")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["passed_stages"][-1], "05-independent-audit")

    def completed_fixture(self):
        paths = P.paths_for(self.args.run_id)
        self.create(paths["run"] / "events.jsonl", "unit-only-evidence\n")
        sha = P.digest(paths["run"] / "events.jsonl")
        self.create(paths["run"] / "run.json", {"run_id": self.args.run_id, "engine": {"id": "mlc-llm"},
                    "protocol_id": P.PROTOCOL_ID, "protocol": {"split": "held_out", "requested_count": 128}})
        self.create(paths["run"] / "seal.json", {"status": "completed", "events_sha256": sha})
        self.create(paths["run"] / "observations.json", {})
        self.create(paths["mapping_json"], {"source_run": {"run_id": self.args.run_id, "events_sha256": sha}})
        self.create(paths["mapping_md"], "unit-only mapping")
        self.create(paths["supplement"], {})
        self.create(self.root / "report/ama/mlc-llm/AMA-MLC-LLM-Report.md", "unit-only report")
        for condition in ("AC1", "AC2", "AC3", "DC1", "DC2"):
            self.create(self.root / "LieMappAnalyzer/LogFile/ama/mlc-llm" / f"AMA-{condition}-MLC-LLM-LogFile.json", {})
        audit = {"audit_status": "pass", "run_id": self.args.run_id, "engine_id": "mlc-llm",
                 "protocol_id": P.PROTOCOL_ID, "request_count": 128, "hashes": {"raw_log": sha},
                 "publication": {}, "mapping": {}, "logging_parity": {"status": "pass"}}
        self.create(paths["audit"] / "audit.json", audit)
        return paths, audit

    def test_final_artifact_check_requires_actual_complete_file_set(self):
        paths, _ = self.completed_fixture()
        self.assertEqual(len(P.completion_artifacts(paths, self.args.run_id)), 14)
        target = self.root / "LieMappAnalyzer/LogFile/ama/mlc-llm/AMA-DC2-MLC-LLM-LogFile.json"
        target.unlink()
        with self.assertRaisesRegex(ValueError, "five condition JSON"):
            P.completion_artifacts(paths, self.args.run_id)

    def test_failed_wrong_run_or_unverified_audit_cannot_complete(self):
        paths, audit = self.completed_fixture()
        for key, value in (("audit_status", "failed"), ("run_id", "other"), ("request_count", 127), ("publication", None)):
            self.create(paths["audit"] / "audit.json", {**audit, key: value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "No passing independent audit"):
                P.completion_artifacts(paths, self.args.run_id)

    def test_changed_raw_bytes_after_audit_cannot_complete(self):
        paths, _ = self.completed_fixture()
        (paths["run"] / "events.jsonl").write_text("modified unit fixture")
        with self.assertRaisesRegex(ValueError, "changed raw evidence"):
            P.completion_artifacts(paths, self.args.run_id)

    def test_wrong_readiness_parity_or_development_never_loads_model_code(self):
        self.create(self.args.parity, {"status": "passed"})
        self.args.development_run.mkdir(parents=True)
        ready = {"parity": {"path": str(self.args.parity.relative_to(self.root)), "sha256": P.digest(self.args.parity)},
                 "development_run": {"directory": str(self.args.development_run.relative_to(self.root))}}
        for field in ("parity", "development"):
            changed = json.loads(json.dumps(ready))
            if field == "parity":
                changed["parity"]["sha256"] = "0" * 64
            else:
                changed["development_run"]["directory"] += "-wrong"
            self.create(P.READY, changed)
            with patch.object(P, "load") as loader, self.assertRaises(ValueError):
                P.verify_ready(self.args)
            loader.assert_not_called()

    def test_json_and_pipeline_records_are_create_only(self):
        path = self.root / "new.json"
        P.write_new(path, {"status": "started"})
        with self.assertRaises(FileExistsError):
            P.write_new(path, {"status": "completed"})
        self.assertEqual(P.read(path)["status"], "started")


if __name__ == "__main__":
    unittest.main()
