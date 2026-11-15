from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.config import load_config
from charorder.errors import InputError
from charorder.ingest import load_sources

from tests.support import ci_key, minimal_config, write_config


class IngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _load(
        self,
        source: dict,
        *,
        keys: list[dict] | None = None,
        encoding_errors: str | None = None,
    ):
        if encoding_errors is not None:
            source["encoding_errors"] = encoding_errors
        config_data = minimal_config(
            source=source,
            keys=keys
            or [ci_key(key_id="email_key", source_id=source["id"], columns=["email"])],
        )
        config_path = write_config(self.root / "config.json", config_data)
        return load_sources(load_config(config_path))[0]

    def test_csv_bom_records_and_line_refs(self) -> None:
        path = self.root / "records.csv"
        path.write_bytes(
            b"\xef\xbb\xbfid,email\n1,A@Example.com\n2,b@example.com\n"
        )
        load = self._load(
            {
                "id": "s1",
                "type": "csv",
                "path": path.name,
                "encoding": "utf-8-sig",
                "record_id_field": "id",
            }
        )
        self.assertEqual(load.columns, ["id", "email"])
        self.assertEqual([record.record_id for record in load.records], ["1", "2"])
        self.assertEqual([record.record_ref for record in load.records], ["row:2", "row:3"])
        self.assertEqual(load.sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_csv_missing_needed_column_is_fatal(self) -> None:
        path = self.root / "records.csv"
        path.write_text("id,other\n1,x\n", encoding="utf-8")
        with self.assertRaisesRegex(InputError, "缺少键规则所需列"):
            self._load(
                {
                    "id": "s1",
                    "type": "csv",
                    "path": path.name,
                    "record_id_field": "id",
                }
            )

    def test_csv_extra_columns_are_reported(self) -> None:
        path = self.root / "records.csv"
        path.write_text("id,email\n1,a@example.com,extra\n", encoding="utf-8")
        load = self._load(
            {
                "id": "s1",
                "type": "csv",
                "path": path.name,
                "record_id_field": "id",
            }
        )
        self.assertIn("SOURCE_ROW_MISMATCH", {issue.code for issue in load.issues})
        self.assertEqual(len(load.records), 1)

    def test_invalid_bytes_replace_vs_strict(self) -> None:
        path = self.root / "records.csv"
        path.write_bytes(b"id,email,notes\n1,a@example.com,bad\xffbyte\n")
        source = {
            "id": "s1",
            "type": "csv",
            "path": path.name,
            "encoding": "utf-8",
            "record_id_field": "id",
        }
        with self.assertRaisesRegex(InputError, "严格解码"):
            self._load(
                source,
                keys=[ci_key(key_id="k", source_id="s1", columns=["email"])],
                encoding_errors="strict",
            )
        load = self._load(
            source,
            keys=[ci_key(key_id="k", source_id="s1", columns=["email"])],
            encoding_errors="replace",
        )
        issue = next(item for item in load.issues if item.code == "SOURCE_INVALID_BYTES")
        self.assertGreaterEqual(issue.details["replacement_chars"], 1)
        self.assertIn("�", load.records[0].values["notes"])
        self.assertFalse(load.decode_note["valid"])

    def test_jsonl_parse_error_skips_bad_lines_and_continues(self) -> None:
        path = self.root / "records.jsonl"
        path.write_text(
            '{"id":"1","email":"a@example.com"}\n'
            "{not json}\n"
            '["not","object"]\n'
            '{"id":"2","email":"b@example.com"}\n',
            encoding="utf-8",
        )
        load = self._load(
            {
                "id": "s1",
                "type": "jsonl",
                "path": path.name,
                "record_id_field": "id",
            }
        )
        self.assertEqual(len(load.records), 2)
        self.assertEqual(
            [record.record_ref for record in load.records], ["line:1", "line:4"]
        )
        parse_issues = [item for item in load.issues if item.code == "SOURCE_PARSE_ERROR"]
        self.assertEqual(len(parse_issues), 2)
        self.assertEqual(parse_issues[0].details["line"], 2)

    def test_jsonl_non_text_value_is_reported(self) -> None:
        path = self.root / "records.jsonl"
        path.write_text('{"id":1,"email":123}\n', encoding="utf-8")
        load = self._load(
            {
                "id": "s1",
                "type": "jsonl",
                "path": path.name,
                "record_id_field": "id",
            }
        )
        record = load.records[0]
        self.assertEqual(record.record_id, "1")
        self.assertEqual(record.values["email"], "123")
        self.assertIn("NON_TEXT_VALUE", {issue.code for issue in record.defects})

    def test_jsonl_missing_record_id_is_preserved_for_audit(self) -> None:
        path = self.root / "records.jsonl"
        path.write_text('{"email":"a@example.com"}\n', encoding="utf-8")
        load = self._load(
            {
                "id": "s1",
                "type": "jsonl",
                "path": path.name,
                "record_id_field": "id",
            }
        )
        record = load.records[0]
        self.assertIsNone(record.record_id)
        self.assertIn("MISSING_RECORD_ID", {issue.code for issue in record.defects})

    def test_sqlite_is_read_read_only_and_metadata_is_decoded(self) -> None:
        path = self.root / "records.sqlite"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE records (id TEXT, email TEXT)")
        connection.execute("INSERT INTO records VALUES ('1', 'A@Example.com')")
        connection.commit()
        connection.close()
        before = path.read_bytes()
        load = self._load(
            {
                "id": "s1",
                "type": "sqlite",
                "path": path.name,
                "record_id_field": "id",
                "table": "records",
            }
        )
        after = path.read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(load.columns, ["id", "email"])
        self.assertEqual(load.records[0].record_id, "1")
        self.assertEqual(load.records[0].values["email"], "A@Example.com")
        self.assertTrue(load.decode_note["sqlite_read_only"])

    def test_sqlite_missing_table_is_fatal(self) -> None:
        path = self.root / "records.sqlite"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE other (id TEXT, email TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(InputError, "不存在表或视图"):
            self._load(
                {
                    "id": "s1",
                    "type": "sqlite",
                    "path": path.name,
                    "record_id_field": "id",
                    "table": "records",
                }
            )

    def test_jsonl_whole_file_invalid_bytes_still_parse_after_replacement(self) -> None:
        path = self.root / "records.jsonl"
        payload = json.dumps(
            {"id": "1", "email": "a@example.com", "notes": "bad __X__ byte"}
        ).encode("utf-8")
        path.write_bytes(payload.replace(b"__X__", b"\xff") + b"\n")
        load = self._load(
            {
                "id": "s1",
                "type": "jsonl",
                "path": path.name,
                "record_id_field": "id",
            }
        )
        self.assertEqual(len(load.records), 1)
        self.assertIn("SOURCE_INVALID_BYTES", {issue.code for issue in load.issues})


if __name__ == "__main__":
    unittest.main()
