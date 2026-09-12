"""Model-free receipt safety tests. Fixtures are not research evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "internal/record_interrupted_run.py"
spec = importlib.util.spec_from_file_location("record_interrupted_run_tests", SOURCE)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class InterruptedRunReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run_id = "ama-mlc-test-001"
        self.run = self.root / ".evidence/raw/ama/mlc-llm" / self.run_id
        self.pipeline = self.root / ".evidence/pipelines" / self.run_id
        self.output = self.root / ".evidence/audits/receipt.json"
        self.run.mkdir(parents=True)
        (self.pipeline / "01-native-evaluation").mkdir(parents=True)
        self.output.parent.mkdir(parents=True)
        self.write(self.run / "run.json", {"run_id": self.run_id, "attack_id": "ama", "engine": {"id": "mlc-llm"}})
        self.command = ["python", str(self.root / "LieMappBench/Attack-Execution-Dataset/attack-script/ama/mlc-llm/run_public.py"),
                        "--run-id", self.run_id]
        self.start = {"run_id": self.run_id, "status": "started", "steps": [
            {"stage": "01-native-evaluation", "command": self.command},
            {"stage": "02-source-mapping", "command": ["python", "map.py", "--run-dir", str(self.run)]},
            {"stage": "04-common-publication", "command": ["python", "developer.py", "--log", str(self.run / "events.jsonl"),
                "--attack", "ama", "--engine", "mlc-llm"]}]}
        self.write(self.pipeline / "pipeline-start.json", self.start)
        self.write(self.pipeline / "01-native-evaluation/command.json", {"command": self.command, "cwd": str(self.root)})
        self.write(self.pipeline / "dependencies.json", [])
        (self.pipeline / "01-native-evaluation/stderr.log").write_text("KeyboardInterrupt: Pipeline interrupted by signal 15\n")
        self.events = [self.event(1, "ama_request_started", "a"), self.event(2, "ama_request_finished", "a"),
                       self.event(3, "ama_request_started", "b")]
        self.save_events()

    def write(self, path, document):
        path.write_text(json.dumps(document))

    def event(self, sequence, stage, request):
        return {"run_id": self.run_id, "sequence": sequence, "stage": stage, "event_id": str(sequence),
                "metadata": {"attack_id": "ama", "engine": {"id": "mlc-llm"}}, "context": {"request_id": request}}

    def save_events(self, tail=b""):
        (self.run / "events.jsonl").write_bytes(b"".join((json.dumps(e) + "\n").encode() for e in self.events) + tail)

    def build(self, **kwargs):
        return M.build_receipt(self.run, self.pipeline, self.output, root=self.root, **kwargs)

    def test_counts_signal_and_unknown_sender_without_old_writes(self):
        old = {p: p.read_bytes() for d in (self.run, self.pipeline) for p in d.rglob("*") if p.is_file()}
        receipt = self.build()
        self.assertEqual(receipt["events"]["request_started_count"], 2)
        self.assertEqual(receipt["events"]["request_finished_count"], 1)
        self.assertEqual(receipt["events"]["incomplete_request_ids"], ["b"])
        self.assertEqual(receipt["events"]["last_complete_event"]["sequence"], 3)
        self.assertEqual(receipt["signal_observations"][0]["signal_number"], 15)
        self.assertIsNone(receipt["termination_sender"])
        self.assertFalse(receipt["current_configuration_compared_to_old_run"])
        self.assertFalse((self.run / "seal.json").exists())
        self.assertFalse((self.pipeline / "pipeline-result.json").exists())
        self.assertEqual(old, {p: p.read_bytes() for d in (self.run, self.pipeline) for p in d.rglob("*") if p.is_file()})

    def test_partial_final_line_is_marked_not_repaired(self):
        self.save_events(b'{"run_id": "incomplete')
        receipt = self.build()
        self.assertEqual(receipt["events"]["parsed_event_count"], 3)
        self.assertTrue(receipt["events"]["has_trailing_partial_line"])
        self.assertEqual(receipt["events"]["malformed_lines"][0]["line"], 4)
        self.assertTrue((self.run / "events.jsonl").read_bytes().endswith(b'"incomplete'))

    def test_valid_final_json_without_newline_is_counted(self):
        data = (self.run / "events.jsonl").read_bytes()
        (self.run / "events.jsonl").write_bytes(data[:-1])
        receipt = self.build()
        self.assertEqual(receipt["events"]["parsed_event_count"], 3)
        self.assertFalse(receipt["events"]["has_trailing_partial_line"])
        self.assertFalse(receipt["events"]["file_ends_with_newline"])

    def test_malformed_interior_line_is_not_called_trailing_partial(self):
        data = (self.run / "events.jsonl").read_bytes()
        (self.run / "events.jsonl").write_bytes(b"{bad json}\n" + data)
        receipt = self.build()
        self.assertEqual(receipt["events"]["parsed_event_count"], 3)
        self.assertFalse(receipt["events"]["has_trailing_partial_line"])
        self.assertEqual(len(receipt["events"]["malformed_lines"]), 1)

    def test_duplicate_finish_ids_not_hidden(self):
        self.events.append(self.event(4, "ama_request_finished", "a"))
        self.save_events()
        self.assertEqual(self.build()["events"]["duplicate_finished_ids"], ["a"])

    def test_existing_output_is_untouched(self):
        self.output.write_text("user-owned")
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.output.read_text(), "user-owned")

    def test_output_symlink_and_symlink_parent_rejected(self):
        target = self.root / "target.json"
        target.write_text("keep")
        self.output.symlink_to(target)
        with self.assertRaises(ValueError): self.build()
        self.output.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.output.parent, target_is_directory=True)
        self.output = alias / "new.json"
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(target.read_text(), "keep")

    def test_outside_project_and_old_input_directory_outputs_rejected(self):
        self.output = self.root.parent / (self.root.name + "-outside.json")
        with self.assertRaises(ValueError): self.build()
        self.output = self.run / "receipt.json"
        with self.assertRaises(ValueError): self.build()
        self.output = self.pipeline / "receipt.json"
        with self.assertRaises(ValueError): self.build()

    def test_input_symlink_rejected(self):
        (self.run / "linked.json").symlink_to(self.run / "run.json")
        with self.assertRaises(ValueError): self.build()

    def test_foreign_pipeline_run_rejected(self):
        self.start["run_id"] = "ama-mlc-test-002"
        self.write(self.pipeline / "pipeline-start.json", self.start)
        with self.assertRaises(ValueError): self.build()

    def test_foreign_pipeline_engine_rejected(self):
        self.command[1] = self.command[1].replace("mlc-llm", "vllm")
        self.write(self.pipeline / "pipeline-start.json", self.start)
        self.write(self.pipeline / "01-native-evaluation/command.json", {"command": self.command, "cwd": str(self.root)})
        with self.assertRaises(ValueError): self.build()

    def test_foreign_pipeline_raw_pointer_rejected(self):
        self.start["steps"][1]["command"][-1] = str(self.run.parent / "another")
        self.write(self.pipeline / "pipeline-start.json", self.start)
        with self.assertRaises(ValueError): self.build()

    def test_foreign_event_engine_and_run_rejected(self):
        self.events[-1]["metadata"]["engine"]["id"] = "vllm"
        self.save_events()
        with self.assertRaises(ValueError): self.build()
        self.events[-1]["metadata"]["engine"]["id"] = "mlc-llm"
        self.events[-1]["run_id"] = "another"
        self.save_events()
        with self.assertRaises(ValueError): self.build()

    def test_signal_not_invented_from_unrelated_number(self):
        (self.pipeline / "01-native-evaluation/stderr.log").write_text("task 15 interrupted\n")
        self.assertEqual(self.build()["signal_observations"], [])

    def test_only_frozen_snapshot_compared_not_current_configuration(self):
        snapshot = self.pipeline / "source-snapshots/internal/experiments.json"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text('{"run":"001"}')
        record = M.descriptor(snapshot)
        current = self.root / "internal/experiments.json"
        current.parent.mkdir()
        current.write_text('{"run":"002"}')
        self.write(self.pipeline / "dependencies.json", [{"path": "internal/experiments.json", "snapshot": str(snapshot.relative_to(self.pipeline)),
                                                           "sha256": record["sha256"], "bytes": record["bytes"]}])
        receipt = self.build()
        self.assertTrue(receipt["frozen_dependency_snapshots"][0]["matches_recorded_dependency"])
        self.assertFalse(receipt["current_configuration_compared_to_old_run"])
        self.assertEqual(current.read_text(), '{"run":"002"}')

    def test_optional_host_observation_does_not_attribute_sender(self):
        with patch.object(M, "observe_linux_host", return_value={"scope": "current instance only", "boot_epoch_seconds": 123}):
            receipt = self.build(observe_host=True)
        self.assertEqual(receipt["current_linux_host_observation"]["boot_epoch_seconds"], 123)
        self.assertIsNone(receipt["termination_sender"])


if __name__ == "__main__":
    unittest.main()
