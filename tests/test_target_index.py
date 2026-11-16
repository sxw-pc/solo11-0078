"""Target-unique-index offline rehearsal tests.

Scenarios (two synthetic sources: CSV legacy_a + SQLite legacy_b):
  G1 same target key across sources (merge vs split)
  G2 identical raw text but different target keys under different Unicode
     transforms (must never be force-merged)
  G3 split replacement that collides a second time (cascade block)
  G4 invalid adjudication (unknown / duplicate source identity)
  G5 expired / stale adjudication (expiry and binding mismatch)
  G6 one source record occupied by two contradictory decisions
  G7 replacement key over the target byte-length limit
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from charorder.artifacts import ARTIFACT_FILES, execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.errors import ConfigError
from charorder.ingest import load_sources
from charorder.models import TargetIndexRehearsal
from charorder.target_index import rule_digest

from tests.support import write_config


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

# legacy_a.csv rows: id, email, alt, code
# legacy_b sqlite contacts: contact_id, email, alt, code
CSV_ROWS = [
    # G1: both systems transform "Alice@X.com" / "alice@x.com" to alice@x.com
    ("A1", "Alice@X.com", "shared@x.com", "AAA"),
    # G2: accented raw text; NFC vs NFD normalization yields distinct keys
    ("A2", "bob@x.com", "uniq-a@x.com", "Café"),
    # G3: alt collides with B3 alt; valid split needs replacements, one of
    # which cascades into another projection key
    ("A3", "anna@x.com", "cascade@x.com", "GGG"),
    # G6: this record collides with B6 under the email rule
    ("A6", "dual@x.com", "dual-alt-a@x.com", "JJJ"),
]

SQLITE_ROWS = [
    # G1 cross-source same target key
    ("B1", "alice@x.com", "other-b1@x.com", "BBB"),
    # G2: same visual text "Café" but stored NFD; NFD rule keeps it distinct
    ("B2", "rob@x.com", "uniq-b@x.com", "Café"),
    # G3 alt collision with A3
    ("B3", "ben@x.com", "cascade@x.com", "HHH"),
    # untouched clean row whose key a bad replacement would collide with
    ("B4", "clean@x.com", "clean-alt@x.com", "CCC"),
    # G6: second group participation for the same B6 record via alt rule
    ("B6", "Dual@X.com", "dual-alt-a@x.com", "KKK"),
]


class TargetIndexTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._write_sources()
        self.config_data = self._base_config()
        self._adj_entries: list[dict] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    # ------------------------------------------------------------------ utils
    def _write_sources(self) -> None:
        import unicodedata

        csv_path = self.root / "legacy_a.csv"
        lines = ["id,email,alt,code"]
        lines.extend(",".join(row) for row in CSV_ROWS)
        csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.csv_bytes = csv_path.read_bytes()

        sqlite_path = self.root / "legacy_b.sqlite"
        # Store the visually-identical "Café" in NFD form so that the NFD rule
        # of code_b produces a different binary target key than the NFC rule.
        nfd_rows = [
            tuple(
                unicodedata.normalize("NFD", value) if column == 3 else value
                for column, value in enumerate(row)
            )
            for row in SQLITE_ROWS
        ]
        connection = sqlite3.connect(sqlite_path)
        try:
            connection.execute(
                "CREATE TABLE contacts ("
                "contact_id TEXT PRIMARY KEY, email TEXT, alt TEXT, code TEXT)"
            )
            connection.executemany(
                "INSERT INTO contacts (contact_id, email, alt, code) VALUES (?, ?, ?, ?)",
                nfd_rows,
            )
            connection.commit()
        finally:
            connection.close()
        self.sqlite_bytes = sqlite_path.read_bytes()

    def _key(
        self,
        key_id: str,
        source_id: str,
        column: str,
        *,
        normalization: str = "NFC",
        case: str = "casefold",
        max_bytes: int | None = 40,
        destination: str = "crm_v2.identity.email_key",
    ) -> dict:
        return {
            "id": key_id,
            "label": key_id,
            "source": source_id,
            "columns": [column],
            "destination": destination,
            "transform": {
                "normalization": normalization,
                "case": case,
                "width_fold": True,
                "trim": True,
                "collapse_whitespace": True,
                "invisible": "remove",
            },
            "unique": False,
            "required": True,
            "max_bytes": max_bytes,
        }

    def _base_config(self) -> dict:
        return {
            "version": 1,
            "project": {
                "name": "双旧系统客户号合并演练",
                "target": "crm_v2 / utf8mb4 / binary utf8 key",
            },
            "sources": [
                {
                    "id": "legacy_a",
                    "type": "csv",
                    "path": "legacy_a.csv",
                    "record_id_field": "id",
                },
                {
                    "id": "legacy_b",
                    "type": "sqlite",
                    "path": "legacy_b.sqlite",
                    "table": "contacts",
                    "record_id_field": "contact_id",
                },
            ],
            "keys": [
                self._key("email_a", "legacy_a", "email"),
                self._key("email_b", "legacy_b", "email"),
                self._key(
                    "alt_a",
                    "legacy_a",
                    "alt",
                    destination="crm_v2.identity.alt_key",
                ),
                self._key(
                    "alt_b",
                    "legacy_b",
                    "alt",
                    destination="crm_v2.identity.alt_key",
                ),
                # G2: same raw text, deliberately different Unicode transforms
                self._key(
                    "code_a",
                    "legacy_a",
                    "code",
                    normalization="NFC",
                    case="none",
                    destination="crm_v2.identity.code_key",
                ),
                self._key(
                    "code_b",
                    "legacy_b",
                    "code",
                    normalization="NFD",
                    case="none",
                    destination="crm_v2.identity.code_key",
                ),
            ],
            "target_indexes": [
                {
                    "id": "ux_identity_email",
                    "label": "客户身份邮箱唯一索引",
                    "destination": "crm_v2.identity.email_key",
                    "rules": ["email_a", "email_b"],
                    "max_bytes": 40,
                },
                {
                    "id": "ux_identity_alt",
                    "label": "客户备用邮箱唯一索引",
                    "destination": "crm_v2.identity.alt_key",
                    "rules": ["alt_a", "alt_b"],
                    "max_bytes": 40,
                },
                {
                    "id": "ux_identity_code",
                    "label": "客户代码唯一索引",
                    "destination": "crm_v2.identity.code_key",
                    "rules": ["code_a", "code_b"],
                    "max_bytes": 40,
                },
            ],
            "reports": {"max_report_rows": 200},
        }

    def load(self, config_data: dict | None = None):
        data = json.loads(json.dumps(config_data or self.config_data))
        if self._adj_entries:
            data["adjudications"] = list(self._adj_entries)
        # Always persist before loading so config.config_sha256 is the hash of
        # exactly the bytes on disk (adjudication docs bind against that hash).
        path = write_config(self.root / "config.json", data)
        config = load_config(path)
        result = scan(config, load_sources(config))
        return config, result

    def prime(self):
        """Load once without adjudication docs so helpers can read key results."""
        saved = list(self._adj_entries)
        self._adj_entries = []
        config, result = self.load()
        self._adj_entries = saved
        return config, result

    def finalize(self, *, rebind: bool = True):
        """Persist the final config (with adjudication references), rebind every
        adjudication doc to that config hash and the current input hashes, then
        reload and scan. This mirrors a reviewer authoring docs against the exact
        run they will be checked against. ``rebind=False`` preserves the binding
        hashes already written so stale-binding scenarios can be exercised."""
        data = json.loads(json.dumps(self.config_data))
        data["adjudications"] = list(self._adj_entries)
        path = write_config(self.root / "config.json", data)
        config = load_config(path)
        input_sha = {
            load.spec.id: load.sha256 for load in load_sources(config)
        }
        if rebind:
            for entry in self._adj_entries:
                doc_path = self.root / entry["path"]
                doc = json.loads(doc_path.read_text("utf-8"))
                doc["config_sha256"] = config.config_sha256
                doc["input_sha256"] = input_sha
                doc_path.write_text(
                    json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
        return self.load()

    def rehearsal(
        self, result, index_id: str = "ux_identity_email"
    ) -> TargetIndexRehearsal:
        return next(item for item in result.target_rehearsals if item.spec.id == index_id)

    def group_by_key(self, rehearsal, target_key: str):
        return next(
            group for group in rehearsal.groups if group.target_key == target_key
        )

    # ----------------------------------------------------- adjudication docs
    def _rule_digests(self, config) -> dict[str, str]:
        return {rule.id: rule_digest(rule) for rule in config.keys}

    def _member(self, config, result, rule_id, record_ref):
        kr = next(
            item
            for item in result.key_results
            if item.rule_id == rule_id and item.record_ref == record_ref
        )
        return {
            "source_id": kr.source_id,
            "rule_id": kr.rule_id,
            "record_ref": kr.record_ref,
            "record_id": kr.record_id,
            "raw_display": kr.raw_display,
            "target_key": kr.target_key,
            "rule_digest": self._rule_digests(config)[rule_id],
        }

    def write_adjudications(
        self,
        config,
        result,
        *,
        index_id: str,
        decisions: list[dict],
        expires_at: str | None = None,
        config_sha256: str | None = None,
        input_sha256: dict[str, str] | None = None,
    ) -> str:
        doc = {
            "schema_version": 1,
            "kind": "charorder.target_adjudications",
            "index_id": index_id,
            "config_sha256": config_sha256 or config.config_sha256,
            "input_sha256": input_sha256
            or {load.spec.id: load.sha256 for load in result.source_loads},
            "decisions": decisions,
        }
        if expires_at is not None:
            doc["expires_at"] = expires_at
        path = self.root / f"adjudications-{index_id}.json"
        path.write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        self._adj_entries.append({"index_id": index_id, "path": path.name})
        return str(path)

    @staticmethod
    def future_expiry(days: int = 30) -> str:
        return (
            (datetime.now(timezone.utc) + timedelta(days=days))
            .replace(microsecond=0)
            .isoformat()
        )

    @staticmethod
    def past_expiry(days: int = 1) -> str:
        return (
            (datetime.now(timezone.utc) - timedelta(days=days))
            .replace(microsecond=0)
            .isoformat()
        )


# ---------------------------------------------------------------------------
# 1. Cross-source target collision is visible and blocks without adjudication
# ---------------------------------------------------------------------------


class CrossSourceVisibilityTests(TargetIndexTestBase):
    def test_collisions_visible_in_rehearsal_projection_and_findings(self) -> None:
        config, result = self.load()
        self.assertEqual(len(result.target_rehearsals), 3)
        rehearsal = self.rehearsal(result)
        target_keys = {group.target_key for group in rehearsal.groups}
        self.assertIn("alice@x.com", target_keys)  # G1
        self.assertIn("dual@x.com", target_keys)  # G6
        g1 = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(g1.reason_code, "CROSS_SOURCE_COLLISION")
        self.assertEqual(len(g1.participants), 2)
        self.assertEqual(sorted(g1.sources), ["legacy_a", "legacy_b"])
        self.assertTrue(rehearsal.blocked)
        codes = result.summary["findings_by_code"]
        self.assertGreaterEqual(codes.get("TARGET_INDEX_COLLISION", 0), 3)
        self.assertIn("TARGET_ADJUDICATION_MISSING", codes)
        # gate cannot pass on per-rule readiness alone
        self.assertFalse(result.plan["gate"]["passes"])
        self.assertGreaterEqual(
            result.plan["gate"]["target_blocking_codes"].get(
                "TARGET_ADJUDICATION_MISSING", 0
            ),
            1,
        )
        blocked_indexes = result.plan["gate"]["target_indexes_blocked"]
        self.assertGreaterEqual(blocked_indexes, 1)
        # every affected target key exists in the single projection view
        projected_keys = {row.target_key for row in rehearsal.projection}
        self.assertIn("alice@x.com", projected_keys)
        # rules participating in a blocked index are not marked ready
        rule_status = {rule["rule_id"]: rule["status"] for rule in result.plan["rules"]}
        self.assertEqual(rule_status["email_a"], "blocked")
        self.assertEqual(rule_status["email_b"], "blocked")

    def test_same_raw_text_different_target_keys_is_not_merged(self) -> None:
        import unicodedata

        config, result = self.load()
        rehearsal = self.rehearsal(result, "ux_identity_code")
        # No collision group: the two visually-identical "Café" raw texts are
        # kept distinct by the NFC vs NFD rule transforms.
        self.assertEqual(rehearsal.groups, [])
        nfc_key = unicodedata.normalize("NFC", "Café")
        nfd_key = unicodedata.normalize("NFD", "Café")
        self.assertNotEqual(nfc_key.encode("utf-8"), nfd_key.encode("utf-8"))
        projected = {row.target_key for row in rehearsal.projection}
        self.assertIn(nfc_key, projected)
        self.assertIn(nfd_key, projected)
        # both rows survive as separate untouched target rows and are not merged
        code_rows = [
            row
            for row in rehearsal.projection
            if row.origin == "untouched"
            and row.target_key in {nfc_key, nfd_key}
        ]
        self.assertEqual(len(code_rows), 2)
        raw_displays = {row.provenance[0]["raw_display"] for row in code_rows}
        self.assertEqual(len(raw_displays), 2)


# ---------------------------------------------------------------------------
# 2. The two authorized adjudication routes produce different outcomes
# ---------------------------------------------------------------------------


class AdjudicationRouteTests(TargetIndexTestBase):
    def _g1_members(self, config, result):
        return [
            self._member(config, result, "email_a", "row:2"),
            self._member(config, result, "email_b", "row:1"),
        ]

    def test_merge_collapses_to_one_target_row_with_full_provenance(self) -> None:
        config, result = self.prime()
        members = self._g1_members(config, result)
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-G1-MERGE",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "reason": "两个旧系统确认同一客户实体",
                    "reviewed_by": "reviewer-1",
                    "reviewed_at": "2026-11-01T00:00:00Z",
                    "members": members,
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        g1 = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(g1.decision, "merge")
        self.assertEqual(g1.block_reasons, [])
        merge_rows = [
            row for row in rehearsal.projection if row.origin == "merge"
        ]
        self.assertEqual(len(merge_rows), 1)
        row = merge_rows[0]
        self.assertEqual(row.target_key, "alice@x.com")
        # full source->target provenance evidence is retained
        self.assertEqual(len(row.provenance), 2)
        self.assertEqual(
            {p["source_id"] for p in row.provenance}, {"legacy_a", "legacy_b"}
        )

    def test_split_keeps_multiple_distinct_target_rows(self) -> None:
        config, result = self.prime()
        members = self._g1_members(config, result)
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-G1-SPLIT",
                    "target_key": "alice@x.com",
                    "decision": "split",
                    "reason": "确认为两个不同客户实体",
                    "reviewed_by": "reviewer-2",
                    "reviewed_at": "2026-11-02T00:00:00Z",
                    "members": members,
                    "replacements": [
                        {
                            "source_id": "legacy_a",
                            "rule_id": "email_a",
                            "record_ref": "row:2",
                            "record_id": "A1",
                            "replacement_key": "alice@x.com::legacy-a-A1",
                        },
                        {
                            "source_id": "legacy_b",
                            "rule_id": "email_b",
                            "record_ref": "row:1",
                            "record_id": "B1",
                            "replacement_key": "alice@x.com::legacy-b-B1",
                        },
                    ],
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        g1 = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(g1.decision, "split")
        self.assertEqual(g1.block_reasons, [])
        replacement_rows = [
            row for row in rehearsal.projection if row.origin == "replacement"
        ]
        self.assertEqual(len(replacement_rows), 2)
        keys = {row.target_key for row in replacement_rows}
        self.assertEqual(
            keys,
            {"alice@x.com::legacy-a-A1", "alice@x.com::legacy-b-B1"},
        )
        for row in replacement_rows:
            self.assertEqual(len(row.provenance), 1)

    def test_merge_and_split_yield_different_projection_row_counts(self) -> None:
        # same collision, two legal routes: one row vs two rows, different keys
        merge_count = self._projection_count(decision="merge")
        split_count = self._projection_count(decision="split")
        self.assertEqual(merge_count, 1)
        self.assertEqual(split_count, 2)

    def _projection_count(self, *, decision: str) -> int:
        # reset any adjudication state from a previous route in the same test
        self._adj_entries = []
        config, result = self.prime()
        members = [
            self._member(config, result, "email_a", "row:2"),
            self._member(config, result, "email_b", "row:1"),
        ]
        decisions: list[dict]
        if decision == "merge":
            decisions = [
                {
                    "adjudication_id": "ADJ-MERGE-COUNT",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": members,
                }
            ]
        else:
            decisions = [
                {
                    "adjudication_id": "ADJ-SPLIT-COUNT",
                    "target_key": "alice@x.com",
                    "decision": "split",
                    "members": members,
                    "replacements": [
                        {
                            "source_id": "legacy_a",
                            "rule_id": "email_a",
                            "record_ref": "row:2",
                            "record_id": "A1",
                            "replacement_key": "alice@x.com::a",
                        },
                        {
                            "source_id": "legacy_b",
                            "rule_id": "email_b",
                            "record_ref": "row:1",
                            "record_id": "B1",
                            "replacement_key": "alice@x.com::b",
                        },
                    ],
                }
            ]
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=decisions,
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        g1 = self.group_by_key(rehearsal, "alice@x.com")
        return len(g1.projected_targets)


# ---------------------------------------------------------------------------
# 3. Cascade conflicts: replacement collides again / overlength
# ---------------------------------------------------------------------------


class CascadeConflictTests(TargetIndexTestBase):
    def _alt_members(self, config, result):
        return [
            self._member(config, result, "alt_a", "row:4"),
            self._member(config, result, "alt_b", "row:3"),
        ]

    def test_replacement_second_collision_blocks_index(self) -> None:
        config, result = self.prime()
        members = self._alt_members(config, result)
        # A3's replacement collides with the untouched key clean-alt@x.com (B4)
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_alt",
            decisions=[
                {
                    "adjudication_id": "ADJ-G3-CASCADE",
                    "target_key": "cascade@x.com",
                    "decision": "split",
                    "members": members,
                    "replacements": [
                        {
                            "source_id": "legacy_a",
                            "rule_id": "alt_a",
                            "record_ref": "row:4",
                            "record_id": "A3",
                            "replacement_key": "clean-alt@x.com",
                        },
                        {
                            "source_id": "legacy_b",
                            "rule_id": "alt_b",
                            "record_ref": "row:3",
                            "record_id": "B3",
                            "replacement_key": "cascade@x.com::b3",
                        },
                    ],
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result, "ux_identity_alt")
        self.assertTrue(rehearsal.blocked)
        codes = result.summary["findings_by_code"]
        self.assertIn("TARGET_REPLACEMENT_COLLISION", codes)
        duplicate_keys = {
            item["target_key_escaped"].strip("'")
            for item in rehearsal.projection_duplicates
        }
        self.assertIn("clean-alt@x.com", duplicate_keys)
        group = self.group_by_key(rehearsal, "cascade@x.com")
        self.assertEqual(group.decision, "invalid")
        self.assertIn("TARGET_REPLACEMENT_COLLISION", group.block_reasons)
        self.assertFalse(result.plan["gate"]["passes"])

    def test_replacement_overlength_blocks_index(self) -> None:
        config, result = self.prime()
        members = self._alt_members(config, result)
        long_key = "x" * 41 + "@x.com"  # 47 bytes > 40 byte limit
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_alt",
            decisions=[
                {
                    "adjudication_id": "ADJ-G7-OVERLENGTH",
                    "target_key": "cascade@x.com",
                    "decision": "split",
                    "members": members,
                    "replacements": [
                        {
                            "source_id": "legacy_a",
                            "rule_id": "alt_a",
                            "record_ref": "row:4",
                            "record_id": "A3",
                            "replacement_key": long_key,
                        },
                        {
                            "source_id": "legacy_b",
                            "rule_id": "alt_b",
                            "record_ref": "row:3",
                            "record_id": "B3",
                            "replacement_key": "cascade@x.com::b3",
                        },
                    ],
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result, "ux_identity_alt")
        self.assertTrue(rehearsal.blocked)
        codes = result.summary["findings_by_code"]
        self.assertIn("TARGET_REPLACEMENT_OVERLENGTH", codes)
        overlength = {
            item["target_key_escaped"].strip("'")
            for item in rehearsal.projection_overlength
            if item["origin"] == "replacement"
        }
        self.assertIn(long_key, overlength)
        group = self.group_by_key(rehearsal, "cascade@x.com")
        self.assertIn("TARGET_REPLACEMENT_OVERLENGTH", group.block_reasons)


# ---------------------------------------------------------------------------
# 4. Invalid adjudication: nonexistent / duplicated source identity
# ---------------------------------------------------------------------------


class InvalidAdjudicationTests(TargetIndexTestBase):
    def test_unknown_and_duplicate_identity_is_rejected(self) -> None:
        config, result = self.prime()
        good_a = self._member(config, result, "email_a", "row:2")
        good_b = self._member(config, result, "email_b", "row:1")
        # unknown identity: record_ref that does not exist in this run
        unknown = dict(good_b)
        unknown["record_ref"] = "row:999"
        unknown["record_id"] = "GHOST"
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-G4-BAD-IDENTITY",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": [good_a, unknown],
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        group = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(group.decision, "invalid")
        self.assertTrue(
            any("MEMBER_IDENTITY_NOT_FOUND" in reason for reason in group.block_reasons)
        )
        codes = result.summary["findings_by_code"]
        self.assertIn("TARGET_ADJUDICATION_INVALID", codes)
        self.assertTrue(rehearsal.blocked)

        # duplicate identity inside one decision is rejected at config load
        dup_doc = {
            "schema_version": 1,
            "kind": "charorder.target_adjudications",
            "index_id": "ux_identity_email",
            "config_sha256": config.config_sha256,
            "input_sha256": {
                load.spec.id: load.sha256 for load in result.source_loads
            },
            "decisions": [
                {
                    "adjudication_id": "ADJ-DUP",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": [good_a, dict(good_a)],
                }
            ],
        }
        dup_path = self.root / "dup.json"
        dup_path.write_text(json.dumps(dup_doc, ensure_ascii=False), encoding="utf-8")
        bad_config = dict(self.config_data)
        bad_config["adjudications"] = [
            {"index_id": "ux_identity_email", "path": "dup.json"}
        ]
        write_config(self.root / "config-dup.json", bad_config)
        with self.assertRaisesRegex(ConfigError, "来源身份在同一裁决内重复"):
            load_config(self.root / "config-dup.json")

    def test_rule_digest_mismatch_blocks(self) -> None:
        config, result = self.prime()
        members = [
            self._member(config, result, "email_a", "row:2"),
            self._member(config, result, "email_b", "row:1"),
        ]
        members[1]["rule_digest"] = "0" * 64  # tampered digest
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-G4-DIGEST",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": members,
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        group = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(group.decision, "invalid")
        self.assertTrue(
            any("RULE_DIGEST_MISMATCH" in reason for reason in group.block_reasons)
        )


# ---------------------------------------------------------------------------
# 5. Expired / stale adjudication never takes effect
# ---------------------------------------------------------------------------


class StaleAdjudicationTests(TargetIndexTestBase):
    def _decisions(self, config, result):
        return [
            {
                "adjudication_id": "ADJ-G5-EXPIRED",
                "target_key": "alice@x.com",
                "decision": "merge",
                "members": [
                    self._member(config, result, "email_a", "row:2"),
                    self._member(config, result, "email_b", "row:1"),
                ],
            }
        ]

    def test_expired_adjudication_is_not_applied(self) -> None:
        config, result = self.prime()
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=self._decisions(config, result),
            expires_at=self.past_expiry(),
        )
        config, result = self.finalize()
        rehearsal = self.rehearsal(result)
        self.assertTrue(rehearsal.stale)
        group = self.group_by_key(rehearsal, "alice@x.com")
        self.assertEqual(group.decision, "invalid")
        self.assertIn("TARGET_ADJUDICATION_STALE", group.block_reasons)
        codes = result.summary["findings_by_code"]
        self.assertIn("TARGET_ADJUDICATION_STALE", codes)
        # no merge row is allowed to enter the projection
        self.assertFalse(any(row.origin == "merge" for row in rehearsal.projection))
        register = {item["adjudication_id"]: item for item in rehearsal.adjudication_register}
        self.assertFalse(register["ADJ-G5-EXPIRED"]["applied"])

    def test_binding_mismatch_on_changed_input_marks_stale(self) -> None:
        config, result = self.prime()
        tampered_input = {
            load.spec.id: ("0" * 64 if load.spec.id == "legacy_a" else load.sha256)
            for load in result.source_loads
        }
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=self._decisions(config, result),
            expires_at=self.future_expiry(),
            input_sha256=tampered_input,
        )
        config, result = self.finalize(rebind=False)
        rehearsal = self.rehearsal(result)
        self.assertTrue(rehearsal.stale)
        self.assertTrue(rehearsal.blocked)
        stale_finding = next(
            f for f in result.findings if f.code == "TARGET_ADJUDICATION_STALE"
        )
        self.assertIn("ADJUDICATION_INPUT_MISMATCH", stale_finding.details["reasons"])


# ---------------------------------------------------------------------------
# 6. One record occupied by two contradictory decisions
# ---------------------------------------------------------------------------


class DoubleOccupancyTests(TargetIndexTestBase):
    def test_record_participating_in_two_groups_across_indexes_blocks(self) -> None:
        # B6 (legacy_b row:5) collides under the email rule with A6 AND its
        # alt key collides under the alt rule with A6's alt — one source
        # record participating in two collision groups at once.
        config, result = self.load()
        email_rehearsal = self.rehearsal(result, "ux_identity_email")
        alt_rehearsal = self.rehearsal(result, "ux_identity_alt")
        self.assertTrue(
            any(g.target_key == "dual@x.com" for g in email_rehearsal.groups)
        )
        self.assertTrue(
            any(g.target_key == "dual-alt-a@x.com" for g in alt_rehearsal.groups)
        )
        b6_email = {
            (p.source_id, p.rule_id, p.record_ref)
            for g in email_rehearsal.groups
            for p in g.participants
            if p.source_id == "legacy_b" and p.record_ref == "row:5"
        }
        b6_alt = {
            (p.source_id, p.rule_id, p.record_ref)
            for g in alt_rehearsal.groups
            for p in g.participants
            if p.source_id == "legacy_b" and p.record_ref == "row:5"
        }
        # the same physical record B6 is a member of groups in two indexes
        self.assertEqual(b6_email, {("legacy_b", "email_b", "row:5")})
        self.assertEqual(b6_alt, {("legacy_b", "alt_b", "row:5")})
        # without adjudication both indexes block; per-rule ready cannot pass
        self.assertTrue(email_rehearsal.blocked and alt_rehearsal.blocked)
        self.assertFalse(result.plan["gate"]["passes"])

    def test_duplicate_occupancy_within_one_index_is_conflict(self) -> None:
        config, result = self.prime()
        # Two decisions in one index both consume B6/email_b row:5.
        # Decision 1 resolves dual@x.com; decision 2 references the same
        # identity but a different (non-colliding) key, which is impossible.
        b6_member = self._member(config, result, "email_b", "row:5")
        a6_member = self._member(config, result, "email_a", "row:5")
        # craft second decision reusing B6 against the alice group members
        alice_a = self._member(config, result, "email_a", "row:2")
        alice_b = self._member(config, result, "email_b", "row:1")
        ghost = dict(b6_member)
        ghost["target_key"] = "alice@x.com"
        ghost["raw_display"] = alice_b["raw_display"]
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-OCC-1",
                    "target_key": "dual@x.com",
                    "decision": "merge",
                    "members": [a6_member, b6_member],
                },
                {
                    "adjudication_id": "ADJ-OCC-2",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": [alice_a, ghost],
                },
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        codes = result.summary["findings_by_code"]
        self.assertIn("TARGET_ADJUDICATION_CONFLICT", codes)
        rehearsal = self.rehearsal(result)
        self.assertTrue(rehearsal.blocked)
        conflict = next(
            f for f in result.findings if f.code == "TARGET_ADJUDICATION_CONFLICT"
        )
        self.assertEqual(conflict.details["identity"], ["legacy_b", "email_b", "row:5"])


# ---------------------------------------------------------------------------
# 7. Full artifact / ledger / report integration
# ---------------------------------------------------------------------------


class ArtifactIntegrationTargetTests(TargetIndexTestBase):
    def test_target_index_artifacts_ledger_and_report(self) -> None:
        config, result = self.prime()
        members = [
            self._member(config, result, "email_a", "row:2"),
            self._member(config, result, "email_b", "row:1"),
        ]
        self.write_adjudications(
            config,
            result,
            index_id="ux_identity_email",
            decisions=[
                {
                    "adjudication_id": "ADJ-ARTIFACT-MERGE",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "reviewed_by": "reviewer-x",
                    "members": members,
                }
            ],
            expires_at=self.future_expiry(),
        )
        config, result = self.finalize()
        out = self.root / "run"
        result, manifest, output = execute(config, out, force=True)
        for name in ARTIFACT_FILES:
            self.assertTrue((output / name).is_file(), name)
        doc = json.loads((output / "target_indexes.json").read_text("utf-8"))
        self.assertEqual(doc["kind"], "charorder.target_index_rehearsals")
        self.assertEqual(doc["counts"]["indexes"], 3)
        email_rehearsal = next(
            item for item in doc["target_indexes"] if item["index_id"] == "ux_identity_email"
        )
        merge_group = next(
            g for g in email_rehearsal["groups"] if g["target_key"] == "alice@x.com"
        )
        self.assertEqual(merge_group["decision"], "merge")
        # provenance retains every source identity
        merge_row = next(r for r in email_rehearsal["projection"] if r["origin"] == "merge")
        self.assertEqual(len(merge_row["provenance"]), 2)

        import sqlite3

        connection = sqlite3.connect(output / "ledger.sqlite")
        try:
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM target_indexes"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM target_collisions WHERE index_id = ?",
                    ("ux_identity_email",),
                ).fetchone()[0],
                2,
            )
            member_count = connection.execute(
                """
                SELECT COUNT(*) FROM target_collision_members m
                JOIN target_collisions c ON m.group_id = c.group_id
                WHERE c.index_id = 'ux_identity_email'
                  AND c.target_key = 'alice@x.com'
                """
            ).fetchone()[0]
            self.assertEqual(member_count, 2)
            adjudicated = connection.execute(
                "SELECT applied, stale FROM adjudications WHERE adjudication_id = ?",
                ("ADJ-ARTIFACT-MERGE",),
            ).fetchone()
            self.assertEqual(adjudicated, (1, 0))
            projection_count = connection.execute(
                "SELECT COUNT(*) FROM target_projection WHERE index_id = ?",
                ("ux_identity_email",),
            ).fetchone()[0]
            self.assertEqual(projection_count, len(email_rehearsal["projection"]))
        finally:
            connection.close()

        html = (output / "report.html").read_text("utf-8")
        self.assertIn("目标唯一索引离线演练", html)
        self.assertIn("ux_identity_email", html)
        md = (output / "report.md").read_text("utf-8")
        self.assertIn("目标唯一索引离线演练", md)
        plan = json.loads((output / "plan.json").read_text("utf-8"))
        self.assertEqual(plan["target_indexes"][0]["index_id"], "ux_identity_email")
        phases = {step["phase"] for step in plan["steps"]}
        self.assertIn("target_indexes", phases)


# ---------------------------------------------------------------------------
# 8. Configuration validation and legacy compatibility
# ---------------------------------------------------------------------------


class ConfigAndCompatibilityTests(TargetIndexTestBase):
    def test_target_index_requires_two_distinct_sources(self) -> None:
        bad = json.loads(json.dumps(self.config_data))
        # both rules from legacy_a; give them a shared destination so the
        # single-source check is the one that fires
        bad["keys"][2]["destination"] = "crm_v2.identity.email_key"
        bad["target_indexes"][0]["rules"] = ["email_a", "alt_a"]
        write_config(self.root / "bad.json", bad)
        with self.assertRaisesRegex(ConfigError, "至少两个不同来源"):
            load_config(self.root / "bad.json")

    def test_unknown_rule_and_destination_mismatch_are_rejected(self) -> None:
        bad = json.loads(json.dumps(self.config_data))
        bad["target_indexes"][0]["rules"] = ["email_a", "missing_rule"]
        write_config(self.root / "bad2.json", bad)
        with self.assertRaisesRegex(ConfigError, "指向不存在的键规则"):
            load_config(self.root / "bad2.json")

        bad2 = json.loads(json.dumps(self.config_data))
        bad2["keys"][1]["destination"] = "elsewhere.key"
        write_config(self.root / "bad3.json", bad2)
        with self.assertRaisesRegex(ConfigError, "同一目标唯一索引内的规则必须指向同一目标"):
            load_config(self.root / "bad3.json")

    def test_adjudication_file_must_exist_and_match_index(self) -> None:
        bad = json.loads(json.dumps(self.config_data))
        bad["adjudications"] = [
            {"index_id": "ux_identity_email", "path": "nope.json"}
        ]
        write_config(self.root / "bad4.json", bad)
        with self.assertRaisesRegex(ConfigError, "裁决文件不存在"):
            load_config(self.root / "bad4.json")

    def test_legacy_config_without_target_indexes_unchanged(self) -> None:
        legacy = json.loads(json.dumps(self.config_data))
        del legacy["target_indexes"]
        write_config(self.root / "legacy.json", legacy)
        config = load_config(self.root / "legacy.json")
        result = scan(config, load_sources(config))
        self.assertEqual(result.target_rehearsals, [])
        self.assertEqual(len(result.plan["steps"]), 7)
        self.assertEqual(result.plan["gate"]["target_indexes_configured"], 0)
        self.assertTrue(all("target_index_blocked" not in rule for rule in []))
        for rule in result.plan["rules"]:
            self.assertFalse(rule["target_index_blocked"])
        # existing per-rule collision behaviour is untouched
        self.assertEqual(result.plan["gate"]["fail_on"], "high")

    def test_duplicate_target_index_id_rejected(self) -> None:
        bad = json.loads(json.dumps(self.config_data))
        bad["target_indexes"][1]["id"] = bad["target_indexes"][0]["id"]
        write_config(self.root / "dup-index.json", bad)
        with self.assertRaisesRegex(ConfigError, "id 重复"):
            load_config(self.root / "dup-index.json")

    def test_adjudication_structure_failures_are_rejected(self) -> None:
        config, result = self.prime()
        members = [
            self._member(config, result, "email_a", "row:2"),
            self._member(config, result, "email_b", "row:1"),
        ]
        base_doc = {
            "schema_version": 1,
            "kind": "charorder.target_adjudications",
            "index_id": "ux_identity_email",
            "config_sha256": config.config_sha256,
            "input_sha256": {
                load.spec.id: load.sha256 for load in result.source_loads
            },
            "decisions": [
                {
                    "adjudication_id": "ADJ-STRUCT",
                    "target_key": "alice@x.com",
                    "decision": "merge",
                    "members": members,
                }
            ],
        }

        def attempt(mutate, pattern: str) -> None:
            attempt.counter = getattr(attempt, "counter", 0) + 1  # type: ignore[attr-defined]
            doc = json.loads(json.dumps(base_doc))
            mutate(doc)
            path = self.root / f"struct-{attempt.counter}.json"
            path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            bad = json.loads(json.dumps(self.config_data))
            bad["adjudications"] = [
                {"index_id": "ux_identity_email", "path": path.name}
            ]
            write_config(self.root / "struct-config.json", bad)
            with self.assertRaisesRegex(ConfigError, pattern):
                load_config(self.root / "struct-config.json")

        attempt(lambda d: d.pop("kind"), "kind 必须是")
        attempt(lambda d: d.update(config_sha256="abc"), "64 位十六进制")
        attempt(
            lambda d: d.update(expires_at="2026-13-99T00:00:00Z"),
            "不是 ISO-8601",
        )
        attempt(
            lambda d: d.update(expires_at="2026-12-31T00:00:00"),
            "必须带时区",
        )
        attempt(
            lambda d: d["decisions"][0].update(decision="rewrite"),
            "merge 或 split",
        )

        split_doc = json.loads(json.dumps(base_doc))
        split_doc["decisions"][0]["decision"] = "split"
        path = self.root / "struct-no-repl.json"
        path.write_text(json.dumps(split_doc, ensure_ascii=False), encoding="utf-8")
        bad = json.loads(json.dumps(self.config_data))
        bad["adjudications"] = [
            {"index_id": "ux_identity_email", "path": path.name}
        ]
        write_config(self.root / "struct-config2.json", bad)
        with self.assertRaisesRegex(ConfigError, "split 裁决必须提供替代键"):
            load_config(self.root / "struct-config2.json")

    def test_unknown_top_level_target_field_rejected(self) -> None:
        bad = json.loads(json.dumps(self.config_data))
        bad["target_indexes"][0]["bogus"] = 1
        write_config(self.root / "unknown-field.json", bad)
        with self.assertRaisesRegex(ConfigError, "含未知字段"):
            load_config(self.root / "unknown-field.json")


if __name__ == "__main__":
    unittest.main()
