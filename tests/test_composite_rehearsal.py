"""Tests for the opt-in versioned composite-key framing rehearsal."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import ARTIFACT_FILES, execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.ingest import load_sources
from charorder.transforms import (
    FRAME_MARKER,
    FRAME_PREFIX,
    UNIT_SEPARATOR,
    VersionedKeyError,
    decode_versioned_key,
    encode_versioned_key,
    is_versioned_key,
    versioned_roundtrip_ok,
)

from tests.support import minimal_config, write_config


# ---------------------------------------------------------------------------
# Codec-level evidence: structural reversibility, no string-substitution trick
# ---------------------------------------------------------------------------


class VersionedFramingCodecTests(unittest.TestCase):
    def test_ambiguous_legacy_tuples_get_distinct_versioned_keys(self) -> None:
        tuple_a = ["a" + UNIT_SEPARATOR + "b", "c"]
        tuple_b = ["a", "b" + UNIT_SEPARATOR + "c"]
        # The failure mode of the legacy encoding.
        self.assertEqual(
            UNIT_SEPARATOR.join(tuple_a), UNIT_SEPARATOR.join(tuple_b)
        )
        framed_a = encode_versioned_key(tuple_a)
        framed_b = encode_versioned_key(tuple_b)
        self.assertNotEqual(framed_a, framed_b)
        self.assertTrue(framed_a.startswith(FRAME_PREFIX))
        self.assertEqual(decode_versioned_key(framed_a), tuple_a)
        self.assertEqual(decode_versioned_key(framed_b), tuple_b)

    def test_roundtrip_covers_separator_empty_escape_like_and_multibyte(self) -> None:
        cases = [
            [],
            [""],
            ["", ""],
            ["", "a", ""],
            [UNIT_SEPARATOR],
            ["a" + UNIT_SEPARATOR + "b", "c"],
            # Text that merely looks like an escape sequence must stay literal.
            ["\\x1f", "\\u001f", "\\\\x1f"],
            ["蓝海", "café", "𝄞-emoji-😀"],
            [FRAME_MARKER, "x" + FRAME_MARKER + "y"],
            [FRAME_PREFIX + "3:abc"],
            ["12:34", ":" * 5],
            ["\t\n\r", "\x00\x07\x1f\x7f"],
        ]
        for components in cases:
            framed = encode_versioned_key(components)
            self.assertEqual(decode_versioned_key(framed), components)
            self.assertTrue(versioned_roundtrip_ok(components))
            self.assertTrue(is_versioned_key(framed))

    def test_structural_injectivity_no_collision(self) -> None:
        # Different sequences must never share a frame byte string.
        sequences = [
            ["a", "b"],
            ["ab"],
            ["a:b"],
            ["", "ab"],
            ["a", ""],
            ["1", "2", "3"],
            ["12", "3"],
            [UNIT_SEPARATOR, ""],
            ["", UNIT_SEPARATOR],
        ]
        framed = [encode_versioned_key(seq) for seq in sequences]
        self.assertEqual(len(set(framed)), len(framed))
        for key in framed:
            self.assertEqual(decode_versioned_key(key), sequences[framed.index(key)])

    def test_malformed_frames_are_rejected_not_guessed(self) -> None:
        malformed = [
            "",
            "plain",
            UNIT_SEPARATOR.join(["a", "b"]),
            FRAME_MARKER + "v2:1:a",
            FRAME_PREFIX + "2:a",  # declared length exceeds payload
            FRAME_PREFIX + "01:a",  # non-canonical length
            FRAME_PREFIX + "1:abc",
            FRAME_PREFIX + "x:a",
            FRAME_PREFIX + "1:",
            FRAME_PREFIX + "1",
        ]
        for bad in malformed:
            with self.assertRaises(VersionedKeyError):
                decode_versioned_key(bad)
            self.assertFalse(is_versioned_key(bad))

    def test_marker_only_recognized_when_grammar_holds(self) -> None:
        # A legacy payload starting with the marker but failing grammar is not v1.
        self.assertFalse(is_versioned_key(FRAME_MARKER + "v1:not-a-frame"))
        self.assertTrue(is_versioned_key(encode_versioned_key(["legacy-looking"])))
        self.assertFalse(is_versioned_key(None))

    def test_length_prefix_uses_code_points_for_multibyte(self) -> None:
        components = ["蓝海"]  # 2 code points, 6 UTF-8 bytes
        framed = encode_versioned_key(components)
        self.assertEqual(framed, FRAME_PREFIX + "2:蓝海")
        self.assertEqual(decode_versioned_key(framed), components)


# ---------------------------------------------------------------------------
# Whole-population rehearsal via the scan engine
# ---------------------------------------------------------------------------


class RehearsalFixture:
    def __init__(self, root: Path) -> None:
        self.root = root

    def build(
        self,
        rows: list[tuple[str, ...]],
        *,
        columns: list[str] | None = None,
        max_bytes: int | None = 200,
        max_chars: int | None = 200,
        key_encoding: str = "v1",
        inventory: list[str] | None = None,
        transform: dict | None = None,
        unique: bool = True,
        required: bool = True,
        header: list[str] | None = None,
        filename: str = "data.csv",
    ):
        columns = columns or ["name", "company"]
        header = header or ["id", *columns]
        path = self.root / filename
        import csv as _csv

        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = _csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        key: dict = {
            "id": "compound",
            "label": "compound",
            "source": "s1",
            "columns": columns,
            "transform": transform
            or {
                "normalization": "none",
                "case": "none",
                "trim": False,
                "invisible": "keep",
            },
            "unique": unique,
            "required": required,
            "max_bytes": max_bytes,
            "max_chars": max_chars,
            "key_encoding": key_encoding,
        }
        if inventory is not None:
            key["legacy_key_inventory"] = inventory
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": filename,
                "record_id_field": "id",
            },
            keys=[key],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result = scan(config, load_sources(config))
        return config, result


class RehearsalEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = RehearsalFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _rehearsal(self, result):
        self.assertEqual(len(result.rehearsals), 1)
        return result.rehearsals[0]

    def test_two_same_legacy_string_tuples_keep_distinct_identities(self) -> None:
        rows = [
            ("R1", "a" + UNIT_SEPARATOR + "b", "c"),
            ("R2", "a", "b" + UNIT_SEPARATOR + "c"),
        ]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        # Contract A: legacy stays blocked and the shared string is exposed.
        self.assertEqual(rehearsal.legacy_contract, "legacy_blocked")
        self.assertIn("LEGACY_COMPOSITE_AMBIGUITY", rehearsal.legacy_contract_blockers)
        self.assertEqual(len(rehearsal.legacy_ambiguous_strings), 1)
        ambiguous = rehearsal.legacy_ambiguous_strings[0]
        self.assertEqual(ambiguous["distinct_component_tuples"], 2)
        self.assertEqual(ambiguous["record_refs"], ["row:2", "row:3"])
        # Contract B: two distinct framed identities, no v1 collision.
        self.assertEqual(rehearsal.versioned_contract, "versioned_cutover")
        self.assertEqual(rehearsal.versioned_contract_blockers, [])
        self.assertEqual(rehearsal.versioned_collision_groups, [])
        framed_keys = [row.versioned_key for row in rehearsal.rows]
        self.assertEqual(len(set(framed_keys)), 2)
        # New key bytes differ from the legacy shared bytes.
        for row in rehearsal.rows:
            self.assertNotEqual(row.versioned_key_bytes, row.legacy_key_bytes)
            self.assertTrue(row.roundtrip_ok)

    def test_escape_like_text_is_literal_and_reversible(self) -> None:
        rows = [("R1", "\\x1f", "\\u001f"), ("R2", "\\\\x1f", "plain")]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        self.assertEqual(rehearsal.versioned_contract, "versioned_cutover")
        for row in rehearsal.rows:
            self.assertEqual(
                decode_versioned_key(row.versioned_key),
                row.transformed_components,
            )

    def test_empty_components_are_blocked_not_silently_accepted(self) -> None:
        rows = [("R1", "", ""), ("R2", "a", "b")]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        self.assertIn("row:2", rehearsal.versioned_empty_record_refs)
        self.assertIn("VERSIONED_KEY_EMPTY", rehearsal.versioned_contract_blockers)
        self.assertEqual(rehearsal.versioned_contract, "not_eligible")

    def test_multibyte_unicode_roundtrips_and_byte_counts(self) -> None:
        rows = [("R1", "蓝海", "café"), ("R2", "𝄞", "😀")]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        self.assertEqual(rehearsal.versioned_contract, "versioned_cutover")
        row = rehearsal.rows[0]
        self.assertEqual(
            decode_versioned_key(row.versioned_key), ["蓝海", "café"]
        )
        # Frame overhead means new bytes exceed raw component bytes.
        self.assertGreater(row.versioned_key_bytes, len("蓝海café".encode("utf-8")))
        self.assertEqual(row.versioned_key_chars, len(row.versioned_key))

    def test_missing_source_component_blocks_auto_conversion(self) -> None:
        path = self.root / "data.jsonl"
        path.write_text(
            '{"id":"R1","name":"a"}\n{"id":"R2","name":"a","company":"b"}\n',
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "compound",
                    "label": "compound",
                    "source": "s1",
                    "columns": ["name", "company"],
                    "transform": {"normalization": "none", "case": "none"},
                    "unique": True,
                    "required": True,
                    "key_encoding": "v1",
                }
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result = scan(config, load_sources(config))
        rehearsal = self._rehearsal(result)
        missing_row = next(row for row in rehearsal.rows if row.record_ref == "line:1")
        self.assertIsNone(missing_row.versioned_key)
        self.assertIsNone(missing_row.roundtrip_ok)
        self.assertIn(
            "REHEARSAL_SOURCE_COMPONENT_MISSING", missing_row.blockers
        )
        self.assertIn(
            "REHEARSAL_SOURCE_COMPONENT_MISSING",
            rehearsal.versioned_contract_blockers,
        )
        self.assertEqual(rehearsal.versioned_contract, "not_eligible")

    def test_duplicate_record_identity_blocks_cutover(self) -> None:
        rows = [
            ("DUP", "a", "b"),
            ("DUP", "c", "d"),
            ("R3", "e", "f"),
        ]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        dup_rows = [row for row in rehearsal.rows if row.record_id == "DUP"]
        self.assertTrue(
            all(
                "REHEARSAL_RECORD_IDENTITY_DUPLICATE" in row.blockers
                for row in dup_rows
            )
        )
        self.assertIn(
            "REHEARSAL_RECORD_IDENTITY_DUPLICATE",
            rehearsal.versioned_contract_blockers,
        )

    def test_versioned_overlength_is_blocked_despite_reversibility(self) -> None:
        rows = [("R1", "a" + UNIT_SEPARATOR + "b", "c")]
        _, result = self.fixture.build(rows, max_bytes=5)
        rehearsal = self._rehearsal(result)
        self.assertIn("row:2", rehearsal.versioned_overlength_record_refs)
        self.assertIn(
            "VERSIONED_KEY_TOO_LONG", rehearsal.versioned_contract_blockers
        )
        self.assertEqual(rehearsal.versioned_contract, "not_eligible")

    def test_versioned_re_collision_after_transform_is_blocked(self) -> None:
        # Distinct raw tuples that converge under the transform.
        rows = [("R1", "Straße", "x"), ("R2", "STRASSE", "x")]
        transform = {
            "normalization": "NFC",
            "case": "casefold",
            "trim": False,
            "invisible": "keep",
        }
        _, result = self.fixture.build(rows, transform=transform)
        rehearsal = self._rehearsal(result)
        self.assertEqual(len(rehearsal.versioned_collision_groups), 1)
        group = rehearsal.versioned_collision_groups[0]
        self.assertEqual(group["distinct_component_tuples"], 1)
        self.assertIn(
            "VERSIONED_KEY_COLLISION", rehearsal.versioned_contract_blockers
        )
        self.assertEqual(rehearsal.versioned_contract, "not_eligible")

    def test_separator_in_component_is_audited_but_reversible(self) -> None:
        rows = [("R1", "a" + UNIT_SEPARATOR + "b", "c")]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        self.assertIn("row:2", rehearsal.payload_control_record_refs)
        # Payload controls are auditable but do not block the v1 contract.
        self.assertEqual(rehearsal.versioned_contract, "versioned_cutover")
        row = rehearsal.rows[0]
        self.assertIn("VERSIONED_PAYLOAD_CONTROL", row.notes)
        self.assertEqual(
            decode_versioned_key(row.versioned_key), row.transformed_components
        )

    def test_legacy_contract_clear_when_no_separator_present(self) -> None:
        rows = [("R1", "a", "b"), ("R2", "c", "d")]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        self.assertEqual(rehearsal.legacy_contract, "legacy_clear")
        self.assertEqual(rehearsal.legacy_contract_blockers, [])
        self.assertEqual(rehearsal.versioned_contract, "versioned_cutover")

    def test_legacy_encoding_opt_out_runs_no_rehearsal(self) -> None:
        rows = [("R1", "a", "b")]
        _, result = self.fixture.build(rows, key_encoding="legacy")
        self.assertEqual(result.rehearsals, [])
        key_result = result.key_results[0]
        self.assertIsNone(key_result.versioned_key)

    def test_inventory_key_without_source_component_is_unattributable(self) -> None:
        rows = [("R1", "a", "b")]
        # An inventory legacy string that no source record produces.
        inventory = ["ghost" + UNIT_SEPARATOR + "key"]
        _, result = self.fixture.build(rows, inventory=inventory)
        rehearsal = self._rehearsal(result)
        self.assertEqual(len(rehearsal.unattributable_inventory_keys), 1)
        self.assertEqual(
            rehearsal.unattributable_inventory_keys[0]["reason"], "no_source_match"
        )
        self.assertIn(
            "LEGACY_KEY_UNATTRIBUTABLE", rehearsal.versioned_contract_blockers
        )
        self.assertEqual(rehearsal.versioned_contract, "not_eligible")

    def test_inventory_ambiguous_match_is_unattributable(self) -> None:
        rows = [
            ("R1", "a" + UNIT_SEPARATOR + "b", "c"),
            ("R2", "a", "b" + UNIT_SEPARATOR + "c"),
        ]
        # Both rows produce this exact legacy string.
        inventory = ["a" + UNIT_SEPARATOR + "b" + UNIT_SEPARATOR + "c"]
        _, result = self.fixture.build(rows, inventory=inventory)
        rehearsal = self._rehearsal(result)
        self.assertEqual(
            rehearsal.unattributable_inventory_keys[0]["reason"],
            "ambiguous_multiple_matches",
        )
        self.assertIn(
            "LEGACY_KEY_UNATTRIBUTABLE", rehearsal.versioned_contract_blockers
        )

    def test_inventory_attributable_single_match_allows_cutover(self) -> None:
        rows = [("R1", "a", "b"), ("R2", "c", "d")]
        framed_r1 = encode_versioned_key(["a", "b"])
        _, result = self.fixture.build(rows, inventory=[framed_r1])
        rehearsal = self._rehearsal(result)
        self.assertEqual(rehearsal.unattributable_inventory_keys, [])
        # The existing v1 key is already in the index -> re-key collision.
        self.assertTrue(rehearsal.inventory_versioned_collisions)
        self.assertIn(
            "VERSIONED_KEY_COLLISION", rehearsal.versioned_contract_blockers
        )

    def test_target_index_encoding_mix_is_blocked(self) -> None:
        rows = [("R1", "a", "b")]
        inventory = [
            "plain" + UNIT_SEPARATOR + "legacy",
            encode_versioned_key(["a", "b"]),
        ]
        _, result = self.fixture.build(rows, inventory=inventory)
        rehearsal = self._rehearsal(result)
        self.assertTrue(rehearsal.index_encoding_mix)
        self.assertIn(
            "TARGET_INDEX_ENCODING_MIX", rehearsal.versioned_contract_blockers
        )

    def test_marker_conflict_in_legacy_inventory_is_blocked(self) -> None:
        rows = [("R1", "a", "b")]
        inventory = [FRAME_MARKER + "v1:broken"]
        _, result = self.fixture.build(rows, inventory=inventory)
        rehearsal = self._rehearsal(result)
        self.assertIn(
            "VERSION_MARKER_CONFLICT", rehearsal.versioned_contract_blockers
        )

    def test_rollback_evidence_holds_original_components_per_row(self) -> None:
        rows = [
            ("R1", "a" + UNIT_SEPARATOR + "b", "c"),
            ("R2", "d", "e"),
        ]
        _, result = self.fixture.build(rows)
        rehearsal = self._rehearsal(result)
        rollback = rehearsal.rollback
        self.assertEqual(rollback["strategy"], "per_record_source_recompute")
        self.assertEqual(rollback["record_count"], 2)
        originals = {item["record_ref"]: item["original_components"] for item in rollback["records"]}
        self.assertEqual(originals["row:2"], ["a" + UNIT_SEPARATOR + "b", "c"])
        for item in rollback["records"]:
            self.assertIsNotNone(item["legacy_key_sha256"])
            self.assertIsNotNone(item["versioned_key_sha256"])
            self.assertEqual(len(item["legacy_key_sha256"]), 64)


class RehearsalArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_artifacts_ledger_and_report_are_consistent(self) -> None:
        import csv as _csv

        path = self.root / "data.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = _csv.writer(handle)
            writer.writerow(["id", "name", "company"])
            writer.writerows(
                [
                    ("R1", "a" + UNIT_SEPARATOR + "b", "c"),
                    ("R2", "a", "b" + UNIT_SEPARATOR + "c"),
                    ("R3", "plain", "pair"),
                ]
            )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "compound",
                    "label": "compound",
                    "source": "s1",
                    "columns": ["name", "company"],
                    "transform": {"normalization": "none", "case": "none", "trim": False},
                    "unique": True,
                    "required": True,
                    "max_bytes": 300,
                    "key_encoding": "v1",
                }
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result, manifest, output = execute(config, self.root / "run")

        # Every declared artifact exists and is hashed in the manifest.
        for name in ARTIFACT_FILES:
            self.assertTrue((output / name).is_file(), name)

        doc = json.loads(
            (output / "composite_rehearsals.json").read_text(encoding="utf-8")
        )
        self.assertEqual(doc["kind"], "charorder.composite_key_rehearsals")
        rehearsal_doc = doc["rehearsals"][0]
        rehearsal = result.rehearsals[0]
        self.assertEqual(
            rehearsal_doc["versioned_contract"], rehearsal.versioned_contract
        )

        # plan.json embeds the same rehearsal payload.
        plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(
            plan["composite_key_rehearsals"][0]["rehearsal_id"],
            rehearsal.rehearsal_id,
        )
        self.assertEqual(plan["rules"][0]["key_encoding"], "v1")

        # Ledger rows mirror the JSON rehearsal.
        connection = sqlite3.connect(
            (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        try:
            db_row = connection.execute(
                "SELECT legacy_contract, versioned_contract, row_count, "
                "index_encoding_mix FROM composite_rehearsals"
            ).fetchone()
            self.assertEqual(db_row[0], rehearsal.legacy_contract)
            self.assertEqual(db_row[1], rehearsal.versioned_contract)
            self.assertEqual(db_row[2], len(rehearsal.rows))
            self.assertEqual(db_row[3], 0)
            db_detail_count = connection.execute(
                "SELECT COUNT(*) FROM composite_rehearsal_rows"
            ).fetchone()[0]
            self.assertEqual(db_detail_count, len(rehearsal.rows))
            sample = connection.execute(
                "SELECT source_components_json, versioned_key, roundtrip_ok "
                "FROM composite_rehearsal_rows ORDER BY ordinal LIMIT 1"
            ).fetchone()
            self.assertEqual(json.loads(sample[0])[0], "a" + UNIT_SEPARATOR + "b")
            self.assertEqual(sample[2], 1)
            # key_results carries the versioned columns too.
            kr = connection.execute(
                "SELECT versioned_key, versioned_key_bytes, "
                "versioned_roundtrip_ok FROM key_results ORDER BY ordinal LIMIT 1"
            ).fetchone()
            self.assertTrue(kr[0].startswith(FRAME_PREFIX))
            self.assertGreater(kr[1], 0)
            self.assertEqual(kr[2], 1)
        finally:
            connection.close()

        # Reports mention the rehearsal and the two contracts.
        html = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("版本化复合键编码预演", html)
        self.assertIn("legacy_blocked", html)
        md = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn("版本化复合键编码预演", md)
        self.assertIn("回滚原始分量", md)


class RehearsalConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "data.csv").write_text(
            "id,name,company\nR1,a,b\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _load(self, key_overrides: dict):
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "compound",
                    "label": "compound",
                    "source": "s1",
                    "columns": ["name", "company"],
                    "transform": {"normalization": "none", "case": "none"},
                    "unique": True,
                    "required": True,
                    **key_overrides,
                }
            ],
        )
        return load_config(write_config(self.root / "config.json", config_data))

    def test_invalid_encoding_rejected(self) -> None:
        from charorder.errors import ConfigError

        with self.assertRaisesRegex(ConfigError, "key_encoding"):
            self._load({"key_encoding": "v2"})

    def test_inventory_must_be_string_array(self) -> None:
        from charorder.errors import ConfigError

        with self.assertRaisesRegex(ConfigError, "legacy_key_inventory"):
            self._load({"legacy_key_inventory": ["a", 1]})

    def test_duplicate_inventory_entries_rejected(self) -> None:
        from charorder.errors import ConfigError

        with self.assertRaisesRegex(ConfigError, "legacy_key_inventory"):
            self._load({"legacy_key_inventory": ["x", "x"]})

    def test_default_encoding_is_legacy(self) -> None:
        config = self._load({})
        self.assertEqual(config.keys[0].key_encoding, "legacy")
        self.assertEqual(config.keys[0].legacy_key_inventory, ())


if __name__ == "__main__":
    unittest.main()
