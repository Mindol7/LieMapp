"""Synthetic source-boundary tests, never fabricated research evidence."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "LieMappBench/Attack-Execution-Dataset/attack-script/siai/SGLang/export_publication_mapping.py"
SPEC = importlib.util.spec_from_file_location("sglang_publication_mapping_test", PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PublicationMappingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sglang-mapping-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "synthetic_source.py"
        self.path.write_text("def hook():\n    value = 1\n    emit('example', value, 'unit.source')\n\ndef forward():\n    hook()\n")
        self.digest = module.analyzer.file_sha256(self.path)
        self.hook = {"path": str(self.path), "function": "hook", "line": 1, "sha256": self.digest}
        self.point = {"stage": "example", "actual_hook": self.hook,
                      "native_engine_site": {"path": str(self.path), "function": "forward", "line": 6, "sha256": self.digest},
                      "conditions": ["AC1"], "reason_ko": "실제 호출의 수치를 기록합니다."}
        self.event = {"event_id": "unit-event", "source": {**self.hook, "line": 3, "logging_point_id": "unit.source"}}

    def convert(self, **kwargs):
        return module.convert_point(self.point, [self.event], kwargs.get("snapshots", []), self.root / "new-mapping.json")

    def test_actual_emit_line_not_function_definition_is_exported(self):
        row = self.convert()
        self.assertEqual(row["source"]["line"], 3)
        self.assertEqual(row["original_hook_definition"]["line"], 1)
        self.assertEqual(row["native_engine_site"]["line"], 6)
        self.assertEqual(row["condition_ids"], ["AC1"])
        self.assertNotIn("source_snapshot", row)

    def test_mismatched_event_source_is_rejected(self):
        for key, value in (("path", "/unrelated/source.py"), ("function", "unrelated"), ("sha256", "0" * 64)):
            with self.subTest(key=key):
                original = copy.deepcopy(self.event)
                self.event["source"][key] = value
                with self.assertRaises(module.MappingError):
                    self.convert()
                self.event = original

    def test_line_inside_function_but_not_emit_is_rejected(self):
        self.event["source"]["line"] = 2
        with self.assertRaisesRegex(module.MappingError, "emit/source"):
            self.convert()

    def test_wrong_native_function_is_rejected(self):
        self.point["native_engine_site"]["function"] = "different"
        with self.assertRaisesRegex(module.MappingError, "Native engine"):
            self.convert()

    def test_verified_snapshot_is_used_when_live_source_has_changed(self):
        snapshot = self.root / "source-snapshot.py"
        snapshot.write_bytes(self.path.read_bytes())
        self.path.write_text("# later unrelated source revision\n")
        row = self.convert(snapshots=[snapshot])
        self.assertEqual(row["source_snapshot"], snapshot.name)
        self.assertEqual(row["source"]["sha256"], self.digest)

    def test_no_matching_source_or_snapshot_is_rejected(self):
        self.path.write_text("# changed\n")
        with self.assertRaisesRegex(module.MappingError, "recorded hash"):
            self.convert()


if __name__ == "__main__":
    unittest.main()
