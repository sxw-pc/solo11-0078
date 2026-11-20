"""Decode-provenance (U+FFFD) evidence tests.

Covers: source-level contamination tracing, legal U+FFFD vs. decoder-inserted
U+FFFD, CSV quoted newlines/escapes, JSONL line-local damage, the strict
decoding contract, and the conservative-versus-precise road maps.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.errors import InputError
from charorder.ingest import load_sources
from charorder.verify import verify_run

from tests.support import ci_key, minimal_config, write_config

FFFD = "�"


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(
        self,
        *,
        name: str,
        data: bytes | None = None,
        kind: str = "csv",
        keys: list[dict] | None = None,
        extra_source: dict | None = None,
    ):
        path = self.root / name
        if data is not None:
            path.write_bytes(data)
        source = {
            "id": "s1",
            "type": kind,
            "path": name,
            "record_id_field": "id",
            "encoding": "utf-8",
        }
        if extra_source:
            source.update(extra_source)
        config_data = minimal_config(
            source=source,
            keys=keys
            or [ci_key(key_id="email_key", source_id="s1", columns=["email"])],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        return config

    def _scan(self, config, loads=None):
        return scan(config, loads or load_sources(config))


class CsvContaminationTests(_Base):
    def test_distinct_invalid_bytes_in_key_column_are_uncertain_not_evidence(self) -> None:
        config = self._config(
            name="data.csv",
            data=(
                b"id,email\n"
                b"1,aa\xffbb@example.com\n"
                b"2,cc\xfddd@example.com\n"
                b"3,clean@example.com\n"
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
            ],
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "field")
        self.assertEqual(load.contaminated_columns, {"email"})
        self.assertEqual(
            [record.contaminated_columns for record in load.records],
            [{"email"}, {"email"}, set()],
        )
        # Distinct illegal bytes both decoded to U+FFFD, but they must never
        # be compared as if they were real source values.
        result = scan(config, [load])
        self.assertEqual(result.summary["uncertain_keys"], 2)
        self.assertEqual(result.summary["determinate_keys"], 1)
        self.assertEqual(result.collisions, [])
        for key in result.key_results:
            if key.record_id in {"1", "2"}:
                self.assertEqual(key.uncertainty, "uncertain")
                self.assertIn("email", key.uncertain_columns)
                self.assertIn(
                    "UNCERTAIN_DECODED_KEY",
                    {defect.code for defect in key.defects},
                )
            else:
                self.assertEqual(key.uncertainty, "determinate")

    def test_clean_key_column_keeps_real_collision_evidence(self) -> None:
        config = self._config(
            name="data.csv",
            data=(
                b"id,email,alias\n"
                b"1,aa\xffbb@example.com,Shared@Example.com\n"
                b"2,cc\xfddd@example.com,shared@example.com\n"
                b"3,clean@example.com,unique@example.com\n"
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="alias_key", source_id="s1", columns=["alias"]),
            ],
        )
        result = self._scan(config)
        alias_groups = [
            group for group in result.collisions if group.rule_id == "alias_key"
        ]
        self.assertEqual(len(alias_groups), 1)
        group = alias_groups[0]
        self.assertEqual(group.reason_code, "NORMALIZATION_COLLISION")
        self.assertEqual(group.uncertainty, "determinate")
        self.assertEqual(group.uncertain_participants, 0)
        self.assertFalse(
            [group for group in result.collisions if group.rule_id == "email_key"]
        )
        rules = {rule["rule_id"]: rule for rule in result.plan["rules"]}
        self.assertEqual(rules["alias_key"]["uncertain_keys"], 0)
        self.assertEqual(rules["alias_key"]["collision_groups"], 1)
        self.assertEqual(rules["email_key"]["uncertain_keys"], 2)
        self.assertEqual(rules["email_key"]["collision_groups"], 0)

    def test_composite_key_is_uncertain_when_only_one_component_is_hit(self) -> None:
        config = self._config(
            name="data.csv",
            data=(
                b"id,name,company\n"
                b"1,ACME,To\xffkyo\n"
                b"2,acme,tokyo\n"
            ),
            keys=[
                ci_key(
                    key_id="compound",
                    source_id="s1",
                    columns=["name", "company"],
                ),
                ci_key(key_id="name_key", source_id="s1", columns=["name"]),
            ],
        )
        result = self._scan(config)
        compound = [
            key for key in result.key_results if key.rule_id == "compound"
        ]
        name_only = [
            key for key in result.key_results if key.rule_id == "name_key"
        ]
        # Only the record whose company had the bad byte is affected.
        self.assertEqual(
            {key.record_ref: key.uncertainty for key in compound},
            {"row:2": "uncertain", "row:3": "determinate"},
        )
        self.assertTrue(all(key.determinate for key in name_only))
        # The repaired component must not manufacture a collision.
        self.assertEqual(
            [group for group in result.collisions if group.rule_id == "compound"],
            [],
        )

    def test_quoted_newline_and_escaped_quote_do_not_shift_columns(self) -> None:
        config = self._config(
            name="data.csv",
            data=(
                b'id,email,notes\n'
                b'1,clean@example.com,"line1\nline2, still notes"\n'
                b'2,other@example.com,"quote "" and \xff bad"\n'
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="notes_key", source_id="s1", columns=["notes"]),
            ],
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "field")
        self.assertEqual(load.contaminated_columns, {"notes"})
        self.assertEqual(load.records[0].contaminated_columns, set())
        self.assertEqual(load.records[1].contaminated_columns, {"notes"})
        result = scan(config, [load])
        email_keys = [
            key for key in result.key_results if key.rule_id == "email_key"
        ]
        self.assertTrue(all(key.determinate for key in email_keys))
        notes_keys = [
            key for key in result.key_results if key.rule_id == "notes_key"
        ]
        # Record 1 spans physical lines 2-3 because of the quoted newline.
        self.assertEqual(
            {key.record_ref: key.determinate for key in notes_keys},
            {"row:3": True, "row:4": False},
        )

    def test_literal_fffd_is_not_treated_as_illegal(self) -> None:
        literal = FFFD.encode("utf-8")
        config = self._config(
            name="data.csv",
            data=(
                b"id,email\n"
                b"1,lit" + literal + b"@example.com\n"
                b"2,other@example.com\n"
            ),
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "none")
        self.assertEqual(load.contaminated_columns, set())
        result = scan(config, [load])
        self.assertEqual(result.summary["uncertain_keys"], 0)
        self.assertEqual(result.summary["determinate_keys"], 2)
        self.assertIn(
            "LITERAL_REPLACEMENT_CHARACTER", result.summary["findings_by_code"]
        )
        self.assertNotIn("REPLACEMENT_CHARACTER", result.summary["findings_by_code"])
        self.assertEqual(result.verdict, "review")

    def test_literal_and_inserted_fffd_are_counted_separately(self) -> None:
        literal = FFFD.encode("utf-8")
        config = self._config(
            name="data.csv",
            data=b"id,email\n1,lit" + literal + b"and\xffbad@example.com\n",
        )
        load = load_sources(config)[0]
        record = load.records[0]
        origin = record.contamination_origins["email"]
        self.assertEqual(origin["inserted"], 1)
        self.assertEqual(origin["literal"], 1)
        result = scan(config, [load])
        key = result.key_results[0]
        self.assertEqual(key.uncertainty, "uncertain")
        codes = {defect.code for defect in key.defects}
        self.assertIn("REPLACEMENT_CHARACTER", codes)
        self.assertIn("LITERAL_REPLACEMENT_CHARACTER", codes)

    def test_strict_decoding_still_fails_without_touching_bytes(self) -> None:
        path = self.root / "data.csv"
        original = b"id,email\n1,aa\xffbb@example.com\n"
        path.write_bytes(original)
        config = self._config(
            name="data.csv",
            extra_source={"encoding_errors": "strict"},
        )
        with self.assertRaisesRegex(InputError, "严格解码"):
            load_sources(config)
        self.assertEqual(path.read_bytes(), original)

    def test_raw_sha256_binds_original_bytes(self) -> None:
        data = b"id,email\n1,aa\xffbb@example.com\n"
        config = self._config(name="data.csv", data=data)
        load = load_sources(config)[0]
        self.assertEqual(load.sha256, hashlib.sha256(data).hexdigest())
        result = scan(config, [load])
        self.assertEqual(result.summary["input_sha256"]["s1"], load.sha256)
        self.assertEqual(
            result.plan["source_fingerprints"][0]["sha256"], load.sha256
        )

    def test_mixed_group_keeps_clean_subgroup_determinate(self) -> None:
        # The bad byte is in the key column itself, so the repaired key must
        # not be counted with the clean look-alikes.  The two clean records
        # still collide deterministically.
        config = self._config(
            name="data.csv",
            data=(
                b"id,email\n"
                b"1,shared@example.com\n"
                b"2,Shared@Example.com\n"
                b"3,shared@example.com\xff\n"
            ),
        )
        result = self._scan(config)
        determinate = [
            group
            for group in result.collisions
            if group.rule_id == "email_key" and group.determinate
        ]
        uncertain = [
            group
            for group in result.collisions
            if group.rule_id == "email_key" and not group.determinate
        ]
        self.assertEqual(len(determinate), 1)
        self.assertEqual(
            sorted(item.record_id for item in determinate[0].participants),
            ["1", "2"],
        )
        # The repaired key has a different target (the U+FFFD is appended),
        # so it forms no group at all rather than polluting the clean one.
        self.assertEqual(uncertain, [])
        self.assertEqual(
            next(
                key
                for key in result.key_results
                if key.record_id == "3"
            ).uncertainty,
            "uncertain",
        )

    def test_damage_outside_the_key_column_does_not_poison_the_key(self) -> None:
        config = self._config(
            name="data.csv",
            data=(
                b"id,email,notes\n"
                b"1,shared@example.com,ok\n"
                b"2,Shared@Example.com,ok\n"
                b"3,shared@example.com,bad\xff\n"
            ),
        )
        result = self._scan(config)
        group = [
            group
            for group in result.collisions
            if group.rule_id == "email_key"
        ][0]
        self.assertTrue(group.determinate)
        self.assertEqual(
            sorted(item.record_id for item in group.participants), ["1", "2", "3"]
        )
        self.assertTrue(
            all(key.determinate for key in result.key_results)
        )

    def test_non_utf8_codec_widens_to_whole_source_with_reason(self) -> None:
        config = self._config(
            name="data.csv",
            data=b"id,email,alias\n1,aa\x81bb@example.com,ok@example.com\n",
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="alias_key", source_id="s1", columns=["alias"]),
            ],
            extra_source={"encoding": "cp1252"},
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "whole_source")
        self.assertTrue(load.contamination_reasons)
        result = scan(config, [load])
        # Under the conservative fallback the clean column also becomes
        # uncertain, but the reason is recorded rather than guessed.
        alias_keys = [
            key for key in result.key_results if key.rule_id == "alias_key"
        ]
        self.assertTrue(all(not key.determinate for key in alias_keys))
        self.assertTrue(
            all(key.uncertainty_reasons for key in alias_keys)
        )
        source_note = load.decode_note
        self.assertEqual(source_note["mapping"], "whole_source")
        self.assertIn("invalid_sequences", source_note)


class JsonlContaminationTests(_Base):
    def test_line_provenance_marks_only_the_damaged_field(self) -> None:
        config = self._config(
            name="data.jsonl",
            kind="jsonl",
            data=(
                b'{"id":"1","email":"a@example.com","notes":"bad \xff"}\n'
                b'{"id":"2","email":"b@example.com","notes":"ok"}\n'
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="notes_key", source_id="s1", columns=["notes"]),
            ],
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "field")
        self.assertEqual(load.contaminated_columns, {"notes"})
        result = scan(config, [load])
        email_keys = [
            key for key in result.key_results if key.rule_id == "email_key"
        ]
        self.assertTrue(all(key.determinate for key in email_keys))
        notes_keys = {
            key.record_ref: key for key in result.key_results if key.rule_id == "notes_key"
        }
        self.assertTrue(notes_keys["line:1"].uncertainty == "uncertain")
        self.assertTrue(notes_keys["line:2"].determinate)

    def test_escaped_unicode_before_the_damage_does_not_shift_the_field(self) -> None:
        config = self._config(
            name="data.jsonl",
            kind="jsonl",
            data=(
                b'{"id":"1","email":"a\\u0041@example.com","notes":"x \\" \\\\ \xff"}\n'
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="notes_key", source_id="s1", columns=["notes"]),
            ],
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contaminated_columns, {"notes"})
        result = scan(config, [load])
        email = [key for key in result.key_results if key.rule_id == "email_key"][0]
        self.assertTrue(email.determinate)
        self.assertEqual(email.target_key, "aa@example.com")

    def test_duplicate_keys_in_one_line_use_last_value(self) -> None:
        config = self._config(
            name="data.jsonl",
            kind="jsonl",
            data=b'{"id":"1","email":"a@example.com","email":"b\xff@example.com"}\n',
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contaminated_columns, {"email"})
        self.assertEqual(load.records[0].values["email"], "b" + FFFD + "@example.com")

    def test_key_name_damage_widens_to_whole_source(self) -> None:
        config = self._config(
            name="data.jsonl",
            kind="jsonl",
            data=b'{"id":"1","email":"a@example.com","note\xffs":"x"}\n',
            keys=[ci_key(key_id="email_key", source_id="s1", columns=["email"])],
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "whole_source")
        self.assertTrue(load.contamination_reasons)
        result = scan(config, [load])
        self.assertTrue(all(not key.determinate for key in result.key_results))

    def test_parse_error_line_is_still_reported_and_byte_range_traced(self) -> None:
        config = self._config(
            name="data.jsonl",
            kind="jsonl",
            data=(
                b'{"id":"1","email":"a@example.com"}\n'
                b'{"id":"2","email":"b\xff@example.com"\n'
            ),
        )
        load = load_sources(config)[0]
        self.assertIn(
            "SOURCE_PARSE_ERROR", {issue.code for issue in load.issues}
        )
        self.assertEqual(len(load.records), 1)
        self.assertTrue(load.contaminated_columns or load.contamination_reasons)
        result = scan(config, [load])
        # The surviving clean record keeps determinate evidence.
        self.assertEqual(result.summary["uncertain_keys"], 0)
        self.assertEqual(result.summary["determinate_keys"], 1)
        self.assertEqual(
            result.summary["sources"][0]["contamination"]["reasons"], load.contamination_reasons
        )

    def test_sqlite_byte_values_carry_field_provenance(self) -> None:
        path = self.root / "data.sqlite"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE records (id TEXT, email BLOB)")
        # A blob with an illegal UTF-8 byte is decoded per value.
        connection.execute(
            "INSERT INTO records VALUES (?, ?)", ("1", b"a\xffb@example.com")
        )
        connection.execute(
            "INSERT INTO records VALUES (?, ?)", ("2", b"clean@example.com")
        )
        connection.commit()
        connection.close()
        config = self._config(
            name="data.sqlite",
            kind="sqlite",
            keys=[ci_key(key_id="email_key", source_id="s1", columns=["email"])],
            extra_source={"table": "records"},
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "field")
        self.assertEqual(load.contaminated_columns, {"email"})
        result = scan(config, [load])
        key = next(
            item for item in result.key_results if item.record_id == "1"
        )
        self.assertEqual(key.uncertainty, "uncertain")
        other = next(
            item for item in result.key_results if item.record_id == "2"
        )
        self.assertTrue(other.determinate)

    def test_sqlite_whole_source_policy_widens(self) -> None:
        path = self.root / "data.sqlite"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE records (id TEXT, email BLOB, alias TEXT)")
        connection.execute(
            "INSERT INTO records VALUES (?, ?, ?)",
            ("1", b"a\xffb@example.com", "ok@example.com"),
        )
        connection.commit()
        connection.close()
        config = self._config(
            name="data.sqlite",
            kind="sqlite",
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="alias_key", source_id="s1", columns=["alias"]),
            ],
            extra_source={
                "table": "records",
                "invalid_byte_policy": "whole_source",
            },
        )
        load = load_sources(config)[0]
        self.assertEqual(load.contamination_scope, "whole_source")
        result = scan(config, [load])
        self.assertEqual(result.summary["determinate_keys"], 0)
        self.assertEqual(result.summary["uncertain_keys"], 2)


class ConservativeVsPreciseTests(_Base):
    def _scan_policy(self, policy: str):
        config = self._config(
            name="data.csv",
            data=(
                b"id,email,alias\n"
                b"1,aa\xffbb@example.com,Shared@Example.com\n"
                b"2,cc\xfddd@example.com,shared@example.com\n"
                b"3,clean@example.com,unique@example.com\n"
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="alias_key", source_id="s1", columns=["alias"]),
            ],
            extra_source={"invalid_byte_policy": policy},
        )
        return self._scan(config)

    def test_precise_and_conservative_produce_different_but_safe_results(self) -> None:
        precise = self._scan_policy("field")
        conservative = self._scan_policy("whole_source")

        # Precise locates the damaged column and keeps the clean one actionable.
        self.assertEqual(precise.summary["uncertain_keys"], 2)
        self.assertEqual(precise.summary["determinate_collision_groups"], 1)
        rules = {rule["rule_id"]: rule for rule in precise.plan["rules"]}
        self.assertEqual(rules["email_key"]["uncertain_keys"], 2)
        self.assertEqual(rules["alias_key"]["uncertain_keys"], 0)
        self.assertEqual(rules["alias_key"]["collision_groups"], 1)

        # Conservative refuses to call any key from the damaged source certain.
        self.assertEqual(conservative.summary["uncertain_keys"], 6)
        self.assertEqual(conservative.summary["determinate_collision_groups"], 0)
        conservative_rules = {
            rule["rule_id"]: rule for rule in conservative.plan["rules"]
        }
        self.assertEqual(conservative_rules["alias_key"]["uncertain_keys"], 3)

        # Both keep the damaged keys out of the determinate set.
        for result in (precise, conservative):
            for key in result.key_results:
                if key.rule_id == "email_key" and key.record_id != "3":
                    self.assertEqual(key.uncertainty, "uncertain")
            self.assertFalse(result.plan["gate"]["passes"])


class ArtifactConsistencyTests(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.config = self._config(
            name="data.csv",
            data=(
                b"id,email,alias\n"
                b"1,aa\xffbb@example.com,Shared@Example.com\n"
                b"2,aa\xffbb@example.com,shared@example.com\n"
                b"3,clean@example.com,unique@example.com\n"
            ),
            keys=[
                ci_key(key_id="email_key", source_id="s1", columns=["email"]),
                ci_key(key_id="alias_key", source_id="s1", columns=["alias"]),
            ],
        )
        self.result, self.manifest, self.output = execute(
            self.config, self.root / "run"
        )

    def test_uncertain_collision_is_not_a_determinate_arbitration_target(self) -> None:
        enum_groups = [
            group for group in self.result.collisions if group.rule_id == "email_key"
        ]
        # Both damaged records map to the same replacement text, yet the group
        # is explicitly uncertain and excluded from the plan's arbitration list.
        self.assertEqual(len(enum_groups), 1)
        self.assertEqual(enum_groups[0].uncertainty, "uncertain")
        self.assertEqual(enum_groups[0].reason_code, "UNCERTAIN_COLLISION")
        step = self.result.plan["steps"][3]
        self.assertTrue(
            all(
                example["rule_id"] != "email_key" for example in step["examples"]
            )
        )
        self.assertTrue(
            any(
                example["rule_id"] == "email_key"
                for example in step["uncertain_examples"]
            )
        )
        self.assertEqual(step["status"], "blocked")

    def test_plan_and_findings_agree_with_ledger(self) -> None:
        collisions_doc = json.loads(
            (self.output / "collisions.json").read_text(encoding="utf-8")
        )
        uncertainty_counts = collisions_doc["counts"]
        self.assertEqual(
            uncertainty_counts["uncertain_groups"],
            self.result.summary["uncertain_collision_groups"],
        )
        connection = sqlite3.connect(
            (self.output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        connection.row_factory = sqlite3.Row
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM key_results WHERE uncertainty = 'uncertain'"
                ).fetchone()[0],
                self.result.summary["uncertain_keys"],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collisions WHERE uncertainty = 'uncertain'"
                ).fetchone()[0],
                self.result.summary["uncertain_collision_groups"],
            )
            source = connection.execute(
                "SELECT * FROM sources WHERE source_id = 's1'"
            ).fetchone()
            self.assertEqual(source["contamination_scope"], "field")
            self.assertEqual(json.loads(source["contaminated_columns_json"]), ["email"])
            member = connection.execute(
                "SELECT uncertainty FROM collision_members WHERE record_id = '1'"
            ).fetchone()
            self.assertEqual(member["uncertainty"], "uncertain")
        finally:
            connection.close()
        verify_run(self.output)

    def test_html_and_markdown_mark_uncertainty(self) -> None:
        html = (self.output / "report.html").read_text(encoding="utf-8")
        markdown = (self.output / "report.md").read_text(encoding="utf-8")
        plan_md = (self.output / "plan.md").read_text(encoding="utf-8")
        for text in (html, markdown, plan_md):
            self.assertIn("不确定", text)
        self.assertIn("不确定碰撞组", html)
        self.assertIn("解码污染来源", markdown)
        self.assertIn("uncertain_examples", self.result.plan["steps"][3])

    def test_manifest_binds_bytes_and_reports_uncertainty(self) -> None:
        data = (self.root / "data.csv").read_bytes()
        self.assertEqual(
            self.manifest["contamination"][0]["sha256"],
            hashlib.sha256(data).hexdigest(),
        )
        self.assertEqual(
            self.manifest["uncertainty"]["uncertain_keys"],
            self.result.summary["uncertain_keys"],
        )
        self.assertFalse(self.manifest["uncertainty"]["gate_passes"])

    def test_cli_summary_and_html_agree_on_uncertainty(self) -> None:
        import contextlib
        import io

        from charorder.cli import main

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(
                [
                    "run",
                    "--config",
                    str(self.root / "config.json"),
                    "--out",
                    str(self.root / "cli-run"),
                ]
            )
        self.assertEqual(code, 0)
        cli_text = out.getvalue()
        self.assertIn("结论：blocked", cli_text)
        html = (self.root / "cli-run" / "report.html").read_text(encoding="utf-8")
        plan_md = (self.root / "cli-run" / "plan.md").read_text(encoding="utf-8")
        self.assertIn("不确定", html)
        self.assertIn("不确定", plan_md)
        self.assertIn("不确定碰撞组", html)
        # The verify command must accept the run and its gate stays closed.
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["verify", "--run", str(self.root / "cli-run")])
        self.assertEqual(code, 0)


class PlanMustNotReleaseUncertainKeysTests(_Base):
    def test_all_clean_source_still_passes(self) -> None:
        config = self._config(
            name="clean.csv",
            data=b"id,email\n1,a@example.com\n2,b@example.com\n",
        )
        result = self._scan(config)
        self.assertEqual(result.summary["uncertain_keys"], 0)
        self.assertTrue(result.plan["gate"]["passes"])
        self.assertTrue(all(rule["status"] == "ready" for rule in result.plan["rules"]))

    def test_uncertain_rule_cannot_be_ready(self) -> None:
        config = self._config(
            name="data.csv",
            data=b"id,email\n1,a\xffb@example.com\n",
        )
        result = self._scan(config)
        # A source-level high finding blocks the run, and the rule must still
        # be marked uncertain rather than being silently released.
        self.assertEqual(result.verdict, "blocked")
        rule = result.plan["rules"][0]
        self.assertNotEqual(rule["status"], "ready")
        self.assertIn(rule["status"], {"blocked", "uncertain"})
        self.assertEqual(rule["uncertain_keys"], 1)
        self.assertFalse(result.plan["gate"]["passes"])

    def test_medium_only_damage_still_blocks_the_gate(self) -> None:
        config = self._config(
            name="data.csv",
            data=b"id,email\n1,a\xffb@example.com\n",
        )
        # Lower the source-level finding so only uncertainty remains.
        raw = json.loads((self.root / "config.json").read_text(encoding="utf-8"))
        raw["severity_overrides"] = {
            "SOURCE_INVALID_BYTES": "medium",
            "REPLACEMENT_CHARACTER": "low",
        }
        write_config(self.root / "config.json", raw)
        config = load_config(self.root / "config.json")
        result = self._scan(config)
        self.assertEqual(result.verdict, "review")
        self.assertEqual(result.summary["uncertain_keys"], 1)
        # The gate must not pass on uncertain evidence.
        self.assertFalse(result.plan["gate"]["passes"])
        self.assertEqual(result.plan["gate"]["uncertain_keys"], 1)
        self.assertEqual(result.plan["steps"][2]["status"], "uncertain")


if __name__ == "__main__":
    unittest.main()
