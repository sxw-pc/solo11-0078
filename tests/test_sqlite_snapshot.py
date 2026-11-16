"""SQLite snapshot isolation and source-identity tests.

Covers the five acceptance points:
1. committed WAL rows are part of the evidence (the live main file is never
   hashed); uncommitted rows never enter the key results;
2. a commit landing while the snapshot is taken cannot produce a mixed
   version (deterministic pause/restart plus a threaded end-to-end check);
3. logical_content and physical_snapshot identities intentionally differ
   after a checkpoint / physical rearrangement with unchanged key inputs;
4. the canonical encoding keeps NULL, empty strings, value types and
   duplicate rows apart and is independent of SQLite return order;
5. CSV / JSONL sources keep their legacy whole-file identity behavior.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import compute_run_id, scan
from charorder.ingest import (
    LOGICAL_ENCODING_SCHEMA,
    encode_sqlite_logical,
    load_sources,
    sqlite_snapshot,
)

from tests.support import ci_key, minimal_config, write_config


class SqliteSnapshotTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _make_wal_db(self, path: Path, rows: list[tuple]) -> sqlite3.Connection:
        connection = sqlite3.connect(str(path))
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE records (id TEXT PRIMARY KEY, email TEXT)")
        connection.executemany("INSERT INTO records VALUES (?, ?)", rows)
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return connection

    def _source(self, *, identity: str | None = None) -> dict:
        source = {
            "id": "s1",
            "type": "sqlite",
            "path": "records.sqlite",
            "record_id_field": "id",
            "table": "records",
        }
        if identity is not None:
            source["identity"] = identity
        return source

    def _config(self, identity: str | None = None, extra_sources=None):
        config_data = minimal_config(
            source=self._source(identity=identity),
            keys=[ci_key(key_id="email_key", source_id="s1", columns=["email"])],
            extra_sources=extra_sources,
        )
        config_path = write_config(self.root / "config.json", config_data)
        return load_config(config_path)

    def _snapshot_digest(self, path: Path) -> str:
        target = self.root / "re-snapshot.sqlite"
        source = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            copy = sqlite3.connect(str(target))
            try:
                copy.execute("PRAGMA journal_mode=DELETE")
                source.backup(copy)
            finally:
                copy.close()
        finally:
            source.close()
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        target.unlink()
        return digest


class WalSnapshotTests(SqliteSnapshotTestBase):
    def test_uncheckpointed_wal_commit_is_in_snapshot_evidence(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(db, [("1", "one@example.com")])
        main_before = db.read_bytes()
        # Second committed row stays in the WAL (no checkpoint afterwards).
        writer.execute("INSERT INTO records VALUES (?, ?)", ("2", "two@example.com"))
        writer.commit()
        wal_path = db.with_name("records.sqlite-wal")
        self.assertTrue(wal_path.exists())
        self.assertEqual(db.read_bytes(), main_before)

        config = self._config(identity="logical_content")
        load = load_sources(config)[0]

        # Query results include the WAL row even though the main file is byte-identical.
        self.assertEqual([r.record_id for r in load.records], ["1", "2"])
        self.assertEqual(load.identity["snapshot"]["source_wal_present"], True)
        self.assertEqual(load.identity["snapshot"]["read_only"], True)
        self.assertEqual(load.identity["row_count"], 2)

        # The declared physical digest is a real snapshot digest (covers the
        # WAL row) and therefore cannot be the hash of the stale main file.
        physical = load.identity["physical_snapshot"]["sha256"]
        self.assertEqual(len(physical), 64)
        self.assertNotEqual(physical, hashlib.sha256(main_before).hexdigest())
        self.assertEqual(physical, self._snapshot_digest(db))

        # logical_content identity is what feeds run_id here.
        self.assertEqual(load.identity_mode, "logical_content")
        self.assertEqual(load.sha256, load.identity["logical_content"]["sha256"])

        # No private snapshot temp files are left behind.
        leftovers = [
            str(path)
            for path in Path(tempfile.gettempdir()).glob("charorder-snap-*")
        ]
        self.assertEqual(leftovers, [])
        writer.close()

    def test_uncommitted_rows_never_enter_the_snapshot(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(db, [("1", "one@example.com")])
        writer.execute("INSERT INTO records VALUES (?, ?)", ("2", "two@example.com"))
        writer.commit()
        writer.execute("BEGIN")
        writer.execute("INSERT INTO records VALUES (?, ?)", ("3", "ghost@example.com"))
        try:
            load = load_sources(self._config())[0]
            self.assertEqual([r.record_id for r in load.records], ["1", "2"])
            self.assertEqual(load.identity["row_count"], 2)
        finally:
            writer.rollback()
            writer.close()

    def test_wal_evidence_matches_manifest_ledger_and_keys_jsonl(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(db, [("1", "one@example.com")])
        writer.execute("INSERT INTO records VALUES (?, ?)", ("2", "two@example.com"))
        writer.commit()  # left un-checkpointed
        writer.close()

        result, manifest, output = execute(self._config(), self.root / "run")
        keys = [
            json.loads(line)
            for line in (output / "keys.jsonl").read_text("utf-8").splitlines()
        ]
        self.assertEqual(len(keys), 2)

        identity = next(
            item for item in manifest["source_identities"] if item["source_id"] == "s1"
        )
        self.assertEqual(identity["identity_mode"], "logical_content")
        self.assertFalse(identity["live_main_file_hashed"])
        self.assertFalse(identity["uncommitted_rows_included"])
        self.assertTrue(identity["snapshot_read_only"])
        self.assertEqual(identity["digest"], result.source_loads[0].sha256)
        self.assertIn("audit_semantics", identity)

        ledger = sqlite3.connect(
            (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        try:
            row = ledger.execute(
                "SELECT identity_mode, identity_json FROM sources WHERE source_id = 's1'"
            ).fetchone()
        finally:
            ledger.close()
        self.assertEqual(row[0], "logical_content")
        stored_identity = json.loads(row[1])
        self.assertEqual(
            stored_identity["logical_content"]["sha256"],
            identity["evidence"]["logical_content"]["sha256"],
        )
        self.assertEqual(
            stored_identity["physical_snapshot"]["sha256"],
            identity["evidence"]["physical_snapshot"]["sha256"],
        )
        self.assertEqual(manifest["run_id"], result.run_id)


class ConcurrentCommitTests(SqliteSnapshotTestBase):
    def _large_db(self, path: Path, count: int) -> None:
        connection = sqlite3.connect(str(path))
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE records (id TEXT PRIMARY KEY, email TEXT)")
        connection.executemany(
            "INSERT INTO records VALUES (?, ?)",
            [(str(i), f"user{i}@example.com") for i in range(count)],
        )
        connection.commit()
        connection.close()

    def test_commit_during_backup_yields_one_coherent_version(self) -> None:
        db = self.root / "records.sqlite"
        self._large_db(db, 5000)
        fired = threading.Event()
        release = threading.Event()

        from charorder import ingest

        original_copy = ingest._copy_database_snapshot

        def pausing_copy(source, target, **kwargs):
            def progress(_status, remaining, total):
                if not fired.is_set() and remaining < total:
                    fired.set()
                    release.wait(timeout=10)

            original_copy(
                source, target, pages=16, progress=progress, sleep=0.001
            )

        def writer() -> None:
            fired.wait(timeout=10)
            connection = sqlite3.connect(str(db))
            connection.executemany(
                "INSERT INTO records VALUES (?, ?)",
                [(f"W-{i}", f"new{i}@example.com") for i in range(200)],
            )
            connection.commit()
            connection.close()
            release.set()

        thread = threading.Thread(target=writer)
        thread.start()
        with mock.patch.object(ingest, "_copy_database_snapshot", pausing_copy):
            load = load_sources(self._config())[0]
        thread.join()
        # The backup restarted atomically on the commit: the snapshot is either
        # fully pre-commit or fully post-commit, never a splice of both.
        self.assertIn(len(load.records), (5000, 5200))
        self.assertEqual(load.identity["row_count"], len(load.records))
        self.assertTrue(release.is_set())

    def test_commit_after_snapshot_is_taken_is_never_read(self) -> None:
        db = self.root / "records.sqlite"
        self._large_db(db, 1000)
        config = self._config()
        spec = config.sources[0]
        with sqlite_snapshot(spec) as snapshot:
            before = snapshot.connection.execute(
                "SELECT COUNT(*) FROM records"
            ).fetchone()[0]
            writer = sqlite3.connect(str(db))
            writer.execute(
                "INSERT INTO records VALUES (?, ?)", ("late", "late@example.com")
            )
            writer.commit()
            writer.close()
            after = snapshot.connection.execute(
                "SELECT COUNT(*) FROM records"
            ).fetchone()[0]
        self.assertEqual(before, after)

        # A fresh load sees the new row, proving the earlier exclusion was the
        # frozen snapshot rather than a failed write.
        later = load_sources(self._config())[0]
        self.assertEqual(len(later.records), before + 1)

    def test_threaded_writer_during_full_scan_never_splits_a_batch(self) -> None:
        db = self.root / "records.sqlite"
        self._large_db(db, 8000)

        def writer() -> None:
            connection = sqlite3.connect(str(db))
            connection.executemany(
                "INSERT INTO records VALUES (?, ?)",
                [(f"W-{i}", f"new{i}@example.com") for i in range(200)],
            )
            connection.commit()
            connection.close()

        thread = threading.Timer(0.02, writer)
        thread.start()
        result = scan(self._config(), load_sources(self._config()))
        thread.join()
        late = [
            item
            for item in result.key_results
            if item.record_id and item.record_id.startswith("W-")
        ]
        # All 200 rows of the batch share one fate: all in or all out.
        self.assertIn(len(late), (0, 200))
        self.assertEqual(
            result.summary["record_count"],
            len(result.source_loads[0].records),
        )


class IdentityModeTests(SqliteSnapshotTestBase):
    def _load(self, identity: str):
        return load_sources(self._config(identity=identity))[0]

    def test_two_identity_modes_produce_different_run_ids(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(
            db, [("1", "a@example.com"), ("2", "b@example.com")]
        )
        writer.execute("INSERT INTO records VALUES (?, ?)", ("3", "c@example.com"))
        writer.commit()  # un-checkpointed WAL row
        writer.close()

        logical = self._load("logical_content")
        physical = self._load("physical_snapshot")

        self.assertEqual(
            logical.sha256, logical.identity["logical_content"]["sha256"]
        )
        self.assertEqual(
            physical.sha256, physical.identity["physical_snapshot"]["sha256"]
        )
        self.assertNotEqual(logical.sha256, physical.sha256)

        run_logical = compute_run_id(self._config("logical_content"), [logical])
        run_physical = compute_run_id(self._config("physical_snapshot"), [physical])
        self.assertNotEqual(run_logical, run_physical)

    def test_checkpoint_alone_keeps_logical_identity(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(db, [("1", "a@example.com")])
        writer.execute("INSERT INTO records VALUES (?, ?)", ("2", "b@example.com"))
        writer.commit()

        first = self._load("logical_content")
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        second = self._load("logical_content")
        writer.close()

        self.assertEqual(
            first.identity["logical_content"]["sha256"],
            second.identity["logical_content"]["sha256"],
        )
        self.assertEqual(
            compute_run_id(self._config("logical_content"), [first]),
            compute_run_id(self._config("logical_content"), [second]),
        )

    def test_physical_rearrangement_changes_physical_but_not_logical_identity(
        self,
    ) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(
            db, [(str(i), f"user{i}@example.com") for i in range(500)]
        )
        writer.commit()
        logical_before = self._load("logical_content")
        physical_before = self._load("physical_snapshot")

        # Same key inputs, different physical layout: churn an unselected table
        # and fragment/rebuild pages, then checkpoint.
        writer.execute("CREATE TABLE IF NOT EXISTS extra (id INTEGER, note TEXT)")
        writer.executemany(
            "INSERT INTO extra VALUES (?, ?)",
            [(i, "junk" * 40) for i in range(3000)],
        )
        writer.commit()
        writer.execute("DELETE FROM extra")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        logical_after = self._load("logical_content")
        physical_after = self._load("physical_snapshot")
        writer.close()

        self.assertEqual(
            logical_before.identity["logical_content"]["sha256"],
            logical_after.identity["logical_content"]["sha256"],
        )
        self.assertEqual(
            compute_run_id(self._config("logical_content"), [logical_before]),
            compute_run_id(self._config("logical_content"), [logical_after]),
        )
        self.assertNotEqual(
            physical_before.identity["physical_snapshot"]["sha256"],
            physical_after.identity["physical_snapshot"]["sha256"],
        )
        self.assertNotEqual(
            compute_run_id(self._config("physical_snapshot"), [physical_before]),
            compute_run_id(self._config("physical_snapshot"), [physical_after]),
        )

    def test_identity_is_deterministic_for_the_same_state(self) -> None:
        db = self.root / "records.sqlite"
        writer = self._make_wal_db(db, [("1", "a@example.com"), ("2", "b@example.com")])
        writer.close()
        first = self._load("logical_content")
        second = self._load("logical_content")
        self.assertEqual(
            first.identity["logical_content"]["sha256"],
            second.identity["logical_content"]["sha256"],
        )
        self.assertEqual(
            first.identity["physical_snapshot"]["sha256"],
            second.identity["physical_snapshot"]["sha256"],
        )


class CanonicalEncodingTests(unittest.TestCase):
    def _encode(self, rows: list[dict[str, tuple]]) -> bytes:
        return encode_sqlite_logical(
            table_name="records",
            select_columns=["id", "email"],
            typed_rows=rows,
        )

    def test_null_differs_from_empty_string(self) -> None:
        null_row = {"id": ("text", b"1"), "email": ("null", None)}
        empty_row = {"id": ("text", b"1"), "email": ("text", b"")}
        self.assertNotEqual(self._encode([null_row]), self._encode([empty_row]))

    def test_storage_types_do_not_collide(self) -> None:
        integer_row = {"id": ("integer", 1), "email": ("text", b"a@x.com")}
        text_row = {"id": ("text", b"1"), "email": ("text", b"a@x.com")}
        real_row = {"id": ("real", 1.0), "email": ("text", b"a@x.com")}
        blob_row = {"id": ("blob", b"1"), "email": ("text", b"a@x.com")}
        encodings = {
            self._encode([row])
            for row in (integer_row, text_row, real_row, blob_row)
        }
        self.assertEqual(len(encodings), 4)

    def test_blob_and_text_with_same_bytes_are_distinct(self) -> None:
        text_row = [{"id": ("text", b"x"), "email": ("null", None)}]
        blob_row = [{"id": ("blob", b"x"), "email": ("null", None)}]
        self.assertNotEqual(self._encode(text_row), self._encode(blob_row))

    def test_duplicate_rows_are_counted_not_deduplicated(self) -> None:
        row = {"id": ("text", b"1"), "email": ("text", b"a@x.com")}
        once = self._encode([row])
        twice = self._encode([dict(row), dict(row)])
        self.assertNotEqual(once, twice)
        distinct = self._encode(
            [
                {"id": ("text", b"1"), "email": ("text", b"a@x.com")},
                {"id": ("text", b"2"), "email": ("text", b"a@x.com")},
            ]
        )
        self.assertNotEqual(twice, distinct)

    def test_encoding_is_independent_of_row_order(self) -> None:
        rows_a = [
            {"id": ("text", b"1"), "email": ("text", b"a@x.com")},
            {"id": ("text", b"2"), "email": ("null", None)},
            {"id": ("text", b"3"), "email": ("text", b"")},
        ]
        rows_b = [rows_a[2], rows_a[0], rows_a[1]]
        self.assertEqual(self._encode(rows_a), self._encode(rows_b))

    def test_schema_tag_is_present(self) -> None:
        encoded = self._encode(
            [{"id": ("text", b"1"), "email": ("null", None)}]
        )
        self.assertTrue(encoded.startswith(len(LOGICAL_ENCODING_SCHEMA).to_bytes(8, "big")))

    def test_special_values_end_to_end_keep_distinct_logical_digests(
        self,
    ) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)

        def build(name: str, ordering: list[tuple]) -> Path:
            path = root / name
            connection = sqlite3.connect(str(path))
            connection.execute("CREATE TABLE records (id TEXT, email TEXT)")
            connection.executemany("INSERT INTO records VALUES (?, ?)", ordering)
            connection.commit()
            connection.close()
            return path

        rows = [
            ("1", None),
            ("2", ""),
            ("3", "same@example.com"),
            ("4", "same@example.com"),  # duplicate business row
        ]
        build("a.sqlite", rows)
        build("b.sqlite", list(reversed(rows)))

        def logical_of(path: Path) -> str:
            config_data = minimal_config(
                source={
                    "id": "s1",
                    "type": "sqlite",
                    "path": path.name,
                    "record_id_field": "id",
                    "table": "records",
                },
                keys=[ci_key(key_id="k", source_id="s1", columns=["email"])],
            )
            config = load_config(write_config(root / f"{path.stem}-config.json", config_data))
            return load_sources(config)[0].identity["logical_content"]["sha256"]

        self.assertEqual(logical_of(root / "a.sqlite"), logical_of(root / "b.sqlite"))

        null_path = root / "null.sqlite"
        empty_path = root / "empty.sqlite"
        for path, value in ((null_path, None), (empty_path, "")):
            connection = sqlite3.connect(str(path))
            connection.execute("CREATE TABLE records (id TEXT, email TEXT)")
            connection.execute("INSERT INTO records VALUES (?, ?)", ("1", value))
            connection.commit()
            connection.close()
        self.assertNotEqual(logical_of(null_path), logical_of(empty_path))


class WithoutRowidAndViewTests(SqliteSnapshotTestBase):
    def test_without_rowid_table_is_ingested_and_identity_stable(self) -> None:
        db = self.root / "records.sqlite"
        connection = sqlite3.connect(str(db))
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "CREATE TABLE records (id TEXT PRIMARY KEY, email TEXT) WITHOUT ROWID"
        )
        connection.executemany(
            "INSERT INTO records VALUES (?, ?)",
            [("1", "a@example.com"), ("2", "b@example.com")],
        )
        connection.commit()
        connection.close()

        first = load_sources(self._config())[0]
        self.assertEqual([r.record_id for r in first.records], ["1", "2"])
        second = load_sources(self._config())[0]
        self.assertEqual(
            first.identity["logical_content"]["sha256"],
            second.identity["logical_content"]["sha256"],
        )

    def test_view_source_is_read_through_the_snapshot(self) -> None:
        db = self.root / "records.sqlite"
        connection = sqlite3.connect(str(db))
        connection.execute("CREATE TABLE base (id TEXT, email TEXT, secret TEXT)")
        connection.executemany(
            "INSERT INTO base VALUES (?, ?, ?)",
            [("1", "a@example.com", "s1"), ("2", "b@example.com", "s2")],
        )
        connection.execute("CREATE VIEW records AS SELECT id, email FROM base")
        connection.commit()
        connection.close()

        load = load_sources(self._config())[0]
        self.assertEqual([r.record_id for r in load.records], ["1", "2"])
        # The unselected column never enters the logical identity.
        self.assertEqual(load.columns, ["id", "email"])
        self.assertNotIn("secret", load.identity["selected_columns"])

        # Changing only the unselected column / table leaves logical identity
        # untouched (same selected rows and record identity).
        writer = sqlite3.connect(str(db))
        writer.execute("UPDATE base SET secret = 'changed'")
        writer.commit()
        writer.close()
        later = load_sources(self._config())[0]
        self.assertEqual(
            load.identity["logical_content"]["sha256"],
            later.identity["logical_content"]["sha256"],
        )


class LegacySourceCompatibilityTests(SqliteSnapshotTestBase):
    def test_csv_and_jsonl_keep_file_bytes_identity(self) -> None:
        csv_path = self.root / "records.csv"
        csv_path.write_text("id,email\n1,a@example.com\n", encoding="utf-8")
        jsonl_path = self.root / "records.jsonl"
        jsonl_path.write_text(
            '{"id":"1","email":"a@example.com"}\n', encoding="utf-8"
        )
        config_data = minimal_config(
            source={
                "id": "csv1",
                "type": "csv",
                "path": "records.csv",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="k1", source_id="csv1", columns=["email"])],
            extra_sources=[
                {
                    "id": "jsonl1",
                    "type": "jsonl",
                    "path": "records.jsonl",
                    "record_id_field": "id",
                }
            ],
        )
        config_data["keys"].append(
            ci_key(key_id="k2", source_id="jsonl1", columns=["email"])
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        loads = load_sources(config)
        for load, path in ((loads[0], csv_path), (loads[1], jsonl_path)):
            self.assertEqual(load.identity_mode, "file_bytes")
            self.assertEqual(
                load.sha256, hashlib.sha256(path.read_bytes()).hexdigest()
            )
            self.assertEqual(load.identity["digest"], load.sha256)

        first = compute_run_id(config, loads)
        second = compute_run_id(config, load_sources(config))
        self.assertEqual(first, second)

        _, manifest, output = execute(config, self.root / "run")
        modes = {item["source_id"]: item["identity_mode"] for item in manifest["source_identities"]}
        self.assertEqual(modes, {"csv1": "file_bytes", "jsonl1": "file_bytes"})
        # The full verification path still accepts the legacy-shaped evidence.
        from charorder.verify import verify_run

        report = verify_run(output)
        self.assertEqual(report["run_id"], manifest["run_id"])


if __name__ == "__main__":
    unittest.main()
