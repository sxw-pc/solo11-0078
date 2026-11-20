from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from charorder.config import load_config
from charorder.errors import ConfigError

from tests.support import DEMO_CONFIG, ci_key, minimal_config, write_config


class DemoConfigTests(unittest.TestCase):
    def test_demo_config_loads_and_resolves_paths(self) -> None:
        config = load_config(DEMO_CONFIG)
        self.assertEqual(config.version, 1)
        self.assertEqual(len(config.sources), 3)
        self.assertEqual(len(config.keys), 7)
        self.assertEqual({source.kind for source in config.sources}, {"csv", "jsonl", "sqlite"})
        self.assertTrue(all(source.path.is_absolute() for source in config.sources))
        self.assertEqual(config.project.name, "销售主数据 · 排序键切换预检")
        self.assertEqual(config.max_report_rows, 500)
        self.assertEqual(len(config.config_sha256), 64)

    def test_demo_has_one_key_per_destination_and_valid_transforms(self) -> None:
        config = load_config(DEMO_CONFIG)
        self.assertEqual(len({key.destination for key in config.keys}), len(config.keys))
        for key in config.keys:
            self.assertIn(key.source_id, config.source_map)
            self.assertTrue(key.columns)


class ConfigFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.csv = self.root / "records.csv"
        self.csv.write_text("id,email\n1,a@example.com\n", encoding="utf-8")
        self.base = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "records.csv",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="email_key", source_id="s1", columns=["email"])],
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _expect(self, config: dict, pattern: str) -> None:
        path = write_config(self.root / "config.json", config)
        with self.assertRaisesRegex(ConfigError, pattern):
            load_config(path)

    def test_missing_file(self) -> None:
        with self.assertRaisesRegex(ConfigError, "配置文件不存在"):
            load_config(self.root / "absent.json")

    def test_malformed_json(self) -> None:
        path = self.root / "bad.json"
        path.write_text("{bad", encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "JSON 解析失败"):
            load_config(path)

    def test_top_level_unknown_field(self) -> None:
        config = copy.deepcopy(self.base)
        config["typo"] = True
        self._expect(config, "未知字段")

    def test_wrong_version(self) -> None:
        config = copy.deepcopy(self.base)
        config["version"] = 2
        self._expect(config, "version 必须为 1")

    def test_missing_source_file(self) -> None:
        config = copy.deepcopy(self.base)
        config["sources"][0]["path"] = "missing.csv"
        self._expect(config, "文件不存在")

    def test_unknown_source_type(self) -> None:
        config = copy.deepcopy(self.base)
        config["sources"][0]["type"] = "parquet"
        self._expect(config, "type 必须是")

    def test_key_references_unknown_source(self) -> None:
        config = copy.deepcopy(self.base)
        config["keys"][0]["source"] = "nope"
        self._expect(config, "不存在的源")

    def test_unknown_key_field(self) -> None:
        config = copy.deepcopy(self.base)
        config["keys"][0]["collation"] = "icu"
        self._expect(config, "未知字段")

    def test_invalid_normalization(self) -> None:
        config = copy.deepcopy(self.base)
        config["keys"][0]["transform"]["normalization"] = "NFC-ish"
        self._expect(config, "normalization 必须是")

    def test_duplicate_key_ids(self) -> None:
        config = copy.deepcopy(self.base)
        config["keys"].append(copy.deepcopy(config["keys"][0]))
        self._expect(config, "id 重复")

    def test_negative_length(self) -> None:
        config = copy.deepcopy(self.base)
        config["keys"][0]["max_bytes"] = 0
        self._expect(config, "正整数")

    def test_unknown_severity_override(self) -> None:
        config = copy.deepcopy(self.base)
        config["severity_overrides"] = {"NOT_A_CHECK": "high"}
        self._expect(config, "未知检查码")

    def test_invalid_report_rows(self) -> None:
        config = copy.deepcopy(self.base)
        config["reports"]["max_report_rows"] = 0
        self._expect(config, "1..100000")

    def test_invalid_byte_policy_rejects_unknown_value(self) -> None:
        config = copy.deepcopy(self.base)
        config["sources"][0]["invalid_byte_policy"] = "guess"
        self._expect(config, "invalid_byte_policy 只能是")

    def test_whole_source_policy_requires_replace(self) -> None:
        config = copy.deepcopy(self.base)
        config["sources"][0]["encoding_errors"] = "strict"
        config["sources"][0]["invalid_byte_policy"] = "whole_source"
        self._expect(config, "需要 encoding_errors=replace")

    def test_csv_delimiter_must_be_one_character(self) -> None:
        config = copy.deepcopy(self.base)
        config["sources"][0]["delimiter"] = "||"
        self._expect(config, "单个字符")

    def test_delimiter_rejected_for_jsonl(self) -> None:
        jsonl = self.root / "records.jsonl"
        jsonl.write_text('{"id":"1","email":"a@example.com"}\n', encoding="utf-8")
        config = copy.deepcopy(self.base)
        config["sources"][0] = {
            "id": "s1",
            "type": "jsonl",
            "path": "records.jsonl",
            "record_id_field": "id",
            "delimiter": ",",
        }
        self._expect(config, "只有 CSV")

    def test_sqlite_non_utf8_encoding_rejected(self) -> None:
        db = self.root / "records.sqlite"
        db.write_bytes(b"SQLite format 3\x00")
        config = copy.deepcopy(self.base)
        config["sources"][0] = {
            "id": "s1",
            "type": "sqlite",
            "path": "records.sqlite",
            "record_id_field": "id",
            "table": "records",
            "encoding": "latin-1",
        }
        self._expect(config, "SQLite TEXT 必须以 utf-8")


if __name__ == "__main__":
    unittest.main()
