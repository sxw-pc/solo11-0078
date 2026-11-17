"""SQLite audit-ledger writer."""

from __future__ import annotations

import json
import sqlite3
import hashlib
import uuid
from pathlib import Path
from typing import Any

from . import APP_NAME, APP_SLUG, UNICODE_VERSION, __version__
from .errors import OutputError
from .models import ScanResult


def write_ledger(result: ScanResult, path: Path) -> None:
    """Write a standalone, queryable audit ledger using a temporary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        connection = sqlite3.connect(str(temp_path))
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            _create_schema(connection)
            _insert_all(connection, result)
            connection.commit()
        finally:
            connection.close()
        temp_path.replace(path)
    except (sqlite3.Error, OSError) as exc:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise OutputError(f"无法写入 SQLite 台账 {path}：{exc}") from exc


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA user_version = 1;
        CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            app TEXT NOT NULL,
            slug TEXT NOT NULL,
            version TEXT NOT NULL,
            unicode_version TEXT NOT NULL,
            project TEXT NOT NULL,
            target TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            config_path TEXT NOT NULL,
            config_sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            key_result_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            collision_count INTEGER NOT NULL
        );
        CREATE TABLE sources (
            source_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            encoding TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            key_result_count INTEGER NOT NULL,
            source_finding_count INTEGER NOT NULL,
            columns_json TEXT NOT NULL,
            decode_note_json TEXT NOT NULL
        );
        CREATE TABLE rules (
            rule_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            source_id TEXT NOT NULL,
            columns_json TEXT NOT NULL,
            destination TEXT NOT NULL,
            transform_json TEXT NOT NULL,
            is_unique INTEGER NOT NULL,
            is_required INTEGER NOT NULL,
            max_bytes INTEGER,
            max_chars INTEGER,
            description TEXT NOT NULL
        );
        CREATE TABLE records (
            record_pk TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            UNIQUE (source_id, record_ref)
        );
        CREATE TABLE key_results (
            key_result_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            raw_values_json TEXT NOT NULL,
            raw_display TEXT NOT NULL,
            target_key TEXT,
            target_key_escaped TEXT,
            key_sha256 TEXT,
            key_bytes INTEGER NOT NULL,
            key_chars INTEGER NOT NULL,
            changed INTEGER NOT NULL,
            collision_group_id TEXT,
            defects_json TEXT NOT NULL,
            versioned_key TEXT,
            versioned_key_escaped TEXT,
            versioned_key_sha256 TEXT,
            versioned_key_bytes INTEGER NOT NULL DEFAULT 0,
            versioned_key_chars INTEGER NOT NULL DEFAULT 0,
            versioned_roundtrip_ok INTEGER
        );
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            code TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            source_id TEXT,
            rule_id TEXT,
            record_ref TEXT,
            record_id TEXT,
            column_name TEXT,
            details_json TEXT NOT NULL
        );
        CREATE TABLE collisions (
            group_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            target_key TEXT NOT NULL,
            target_key_escaped TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            distinct_raw_count INTEGER NOT NULL,
            raw_variants_json TEXT NOT NULL
        );
        CREATE TABLE collision_members (
            group_id TEXT NOT NULL,
            key_result_id TEXT NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            PRIMARY KEY (group_id, key_result_id)
        );
        CREATE TABLE composite_rehearsals (
            rehearsal_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            encoding TEXT NOT NULL,
            frame_version TEXT NOT NULL,
            frame_prefix_escaped TEXT NOT NULL,
            columns_json TEXT NOT NULL,
            transform_json TEXT NOT NULL,
            is_unique INTEGER NOT NULL,
            is_required INTEGER NOT NULL,
            max_bytes INTEGER,
            max_chars INTEGER,
            row_count INTEGER NOT NULL,
            legacy_contract TEXT NOT NULL,
            legacy_contract_blockers_json TEXT NOT NULL,
            blocked_record_refs_json TEXT NOT NULL,
            versioned_contract TEXT NOT NULL,
            versioned_contract_blockers_json TEXT NOT NULL,
            versioned_collision_count INTEGER NOT NULL,
            versioned_empty_record_refs_json TEXT NOT NULL,
            versioned_overlength_record_refs_json TEXT NOT NULL,
            payload_control_record_refs_json TEXT NOT NULL,
            inventory_size INTEGER NOT NULL,
            index_encoding_mix INTEGER NOT NULL,
            unattributable_inventory_keys_json TEXT NOT NULL,
            inventory_versioned_collisions_json TEXT NOT NULL,
            legacy_ambiguous_strings_json TEXT NOT NULL,
            rollback_json TEXT NOT NULL
        );
        CREATE TABLE composite_rehearsal_rows (
            rehearsal_id TEXT NOT NULL,
            key_result_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            source_components_json TEXT NOT NULL,
            transformed_components_json TEXT NOT NULL,
            legacy_key TEXT,
            legacy_key_sha256 TEXT,
            legacy_key_bytes INTEGER NOT NULL,
            versioned_key TEXT,
            versioned_key_escaped TEXT,
            versioned_key_sha256 TEXT,
            versioned_key_bytes INTEGER NOT NULL,
            versioned_key_chars INTEGER NOT NULL,
            roundtrip_ok INTEGER,
            blockers_json TEXT NOT NULL,
            notes_json TEXT NOT NULL,
            PRIMARY KEY (rehearsal_id, key_result_id)
        );
        CREATE INDEX ix_key_results_rule ON key_results (rule_id, target_key);
        CREATE INDEX ix_key_results_source ON key_results (source_id, record_ref);
        CREATE INDEX ix_findings_severity ON findings (severity, code);
        CREATE INDEX ix_findings_source ON findings (source_id);
        CREATE INDEX ix_findings_rule ON findings (rule_id);
        CREATE INDEX ix_collisions_rule ON collisions (rule_id);
        CREATE INDEX ix_collision_members_record ON collision_members (record_ref);
        CREATE INDEX ix_rehearsals_rule ON composite_rehearsals (rule_id);
        CREATE INDEX ix_rehearsal_rows_record ON composite_rehearsal_rows (record_ref);
        CREATE VIEW finding_counts AS
            SELECT code, severity, COUNT(*) AS finding_count
            FROM findings
            GROUP BY code, severity
            ORDER BY severity, code;
        CREATE VIEW collision_summary AS
            SELECT rule_id, source_id, reason_code, COUNT(*) AS group_count,
                   SUM(record_count) AS record_count
            FROM collisions
            GROUP BY rule_id, source_id, reason_code
            ORDER BY rule_id;
        """
    )


def _insert_all(connection: sqlite3.Connection, result: ScanResult) -> None:
    connection.executemany(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        [
            ("app", APP_NAME),
            ("slug", APP_SLUG),
            ("version", __version__),
            ("schema_version", "1"),
            ("run_id", result.run_id),
            ("ledger_written_at", result.generated_at),
        ],
    )
    summary = result.summary
    source_summary = {item["source_id"]: item for item in summary["sources"]}
    connection.execute(
        """
        INSERT INTO runs (
            run_id, app, slug, version, unicode_version, project, target,
            generated_at, config_path, config_sha256, verdict, record_count,
            key_result_count, finding_count, collision_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.run_id,
            APP_NAME,
            APP_SLUG,
            __version__,
            UNICODE_VERSION,
            result.config.project.name,
            result.config.project.target,
            result.generated_at,
            str(result.config.config_path),
            result.config.config_sha256,
            result.verdict,
            summary["record_count"],
            summary["keys_evaluated"],
            summary["findings_total"],
            summary["collision_groups"],
        ),
    )

    for load in result.source_loads:
        stats = source_summary[load.spec.id]
        connection.execute(
            """
            INSERT INTO sources (
                source_id, kind, path, sha256, size_bytes, encoding,
                record_count, key_result_count, source_finding_count,
                columns_json, decode_note_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                load.spec.id,
                load.spec.kind,
                load.spec.display_path,
                load.sha256,
                load.size_bytes,
                load.spec.encoding,
                len(load.records),
                stats["key_results"],
                stats["source_findings"],
                _json(list(load.columns)),
                _json(load.decode_note or {}),
            ),
        )

    for rule in result.config.keys:
        connection.execute(
            """
            INSERT INTO rules (
                rule_id, label, source_id, columns_json, destination,
                transform_json, is_unique, is_required, max_bytes, max_chars,
                description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.id,
                rule.label,
                rule.source_id,
                _json(list(rule.columns)),
                rule.destination,
                _json(rule.transform.as_dict()),
                int(rule.unique),
                int(rule.required),
                rule.max_bytes,
                rule.max_chars,
                rule.description,
            ),
        )

    connection.executemany(
        """
        INSERT INTO records (
            record_pk, run_id, source_id, ordinal, record_ref, record_id
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                _record_pk(result.run_id, record.source_id, record.record_ref),
                result.run_id,
                record.source_id,
                record.ordinal,
                record.record_ref,
                record.record_id,
            )
            for record in result.records
        ],
    )

    connection.executemany(
        """
        INSERT INTO key_results (
            key_result_id, run_id, source_id, rule_id, ordinal, record_ref,
            record_id, raw_values_json, raw_display, target_key,
            target_key_escaped, key_sha256, key_bytes, key_chars, changed,
            collision_group_id, defects_json, versioned_key,
            versioned_key_escaped, versioned_key_sha256, versioned_key_bytes,
            versioned_key_chars, versioned_roundtrip_ok
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item.key_result_id,
                result.run_id,
                item.source_id,
                item.rule_id,
                item.ordinal,
                item.record_ref,
                item.record_id,
                _json(list(item.raw_values)),
                item.raw_display,
                item.target_key,
                item.target_key_escaped,
                item.key_sha256,
                item.key_bytes,
                item.key_chars,
                int(item.changed),
                item.collision_group_id,
                _json(
                    [
                        {
                            "code": defect.code,
                            "severity": defect.severity,
                            "column": defect.column,
                            "message": defect.message,
                            "details": defect.details,
                        }
                        for defect in item.defects
                    ]
                ),
                item.versioned_key,
                item.versioned_key_escaped,
                item.versioned_key_sha256,
                item.versioned_key_bytes,
                item.versioned_key_chars,
                None
                if item.versioned_roundtrip_ok is None
                else int(item.versioned_roundtrip_ok),
            )
            for item in result.key_results
        ],
    )

    connection.executemany(
        """
        INSERT INTO findings (
            finding_id, run_id, code, severity, message, source_id, rule_id,
            record_ref, record_id, column_name, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                finding.finding_id,
                result.run_id,
                finding.code,
                finding.severity,
                finding.message,
                finding.source_id,
                finding.rule_id,
                finding.record_ref,
                finding.record_id,
                finding.column,
                _json(finding.details),
            )
            for finding in result.findings
        ],
    )

    connection.executemany(
        """
        INSERT INTO collisions (
            group_id, run_id, rule_id, source_id, target_key, target_key_escaped,
            reason_code, record_count, distinct_raw_count, raw_variants_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                group.group_id,
                result.run_id,
                group.rule_id,
                group.source_id,
                group.target_key,
                group.target_key_escaped,
                group.reason_code,
                len(group.participants),
                len(group.raw_variants),
                _json(group.raw_variants),
            )
            for group in result.collisions
        ],
    )
    connection.executemany(
        """
        INSERT INTO collision_members (
            group_id, key_result_id, record_ref, record_id
        ) VALUES (?, ?, ?, ?)
        """,
        [
            (
                group.group_id,
                participant.key_result_id,
                participant.record_ref,
                participant.record_id,
            )
            for group in result.collisions
            for participant in group.participants
        ],
    )

    for rehearsal in result.rehearsals:
        connection.execute(
            """
            INSERT INTO composite_rehearsals (
                rehearsal_id, run_id, rule_id, source_id, encoding,
                frame_version, frame_prefix_escaped, columns_json,
                transform_json, is_unique, is_required, max_bytes, max_chars,
                row_count, legacy_contract, legacy_contract_blockers_json,
                blocked_record_refs_json, versioned_contract,
                versioned_contract_blockers_json, versioned_collision_count,
                versioned_empty_record_refs_json,
                versioned_overlength_record_refs_json,
                payload_control_record_refs_json, inventory_size,
                index_encoding_mix, unattributable_inventory_keys_json,
                inventory_versioned_collisions_json,
                legacy_ambiguous_strings_json, rollback_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rehearsal.rehearsal_id,
                result.run_id,
                rehearsal.rule_id,
                rehearsal.source_id,
                rehearsal.encoding,
                rehearsal.frame_version,
                rehearsal.frame_prefix_escaped,
                _json(rehearsal.columns),
                _json(rehearsal.transform),
                int(rehearsal.unique),
                int(rehearsal.required),
                rehearsal.max_bytes,
                rehearsal.max_chars,
                len(rehearsal.rows),
                rehearsal.legacy_contract,
                _json(rehearsal.legacy_contract_blockers),
                _json(rehearsal.blocked_record_refs),
                rehearsal.versioned_contract,
                _json(rehearsal.versioned_contract_blockers),
                len(rehearsal.versioned_collision_groups),
                _json(rehearsal.versioned_empty_record_refs),
                _json(rehearsal.versioned_overlength_record_refs),
                _json(rehearsal.payload_control_record_refs),
                rehearsal.inventory_size,
                int(rehearsal.index_encoding_mix),
                _json(rehearsal.unattributable_inventory_keys),
                _json(rehearsal.inventory_versioned_collisions),
                _json(rehearsal.legacy_ambiguous_strings),
                _json(rehearsal.rollback),
            ),
        )
        connection.executemany(
            """
            INSERT INTO composite_rehearsal_rows (
                rehearsal_id, key_result_id, run_id, rule_id, ordinal,
                record_ref, record_id, source_components_json,
                transformed_components_json, legacy_key, legacy_key_sha256,
                legacy_key_bytes, versioned_key, versioned_key_escaped,
                versioned_key_sha256, versioned_key_bytes,
                versioned_key_chars, roundtrip_ok, blockers_json, notes_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    rehearsal.rehearsal_id,
                    row.key_result_id,
                    result.run_id,
                    rehearsal.rule_id,
                    row.ordinal,
                    row.record_ref,
                    row.record_id,
                    _json(row.source_components),
                    _json(row.transformed_components if row.transformed_components is not None else []),
                    row.legacy_key,
                    row.legacy_key_sha256,
                    row.legacy_key_bytes,
                    row.versioned_key,
                    row.versioned_key_escaped,
                    row.versioned_key_sha256,
                    row.versioned_key_bytes,
                    row.versioned_key_chars,
                    None if row.roundtrip_ok is None else int(row.roundtrip_ok),
                    _json(row.blockers),
                    _json(row.notes),
                )
                for row in rehearsal.rows
            ],
        )


def _record_pk(run_id: str, source_id: str, record_ref: str) -> str:
    digest = hashlib.sha256(
        f"{run_id}|{source_id}|{record_ref}".encode("utf-8")
    ).hexdigest()
    return "R-" + digest[:16]


def _json(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    try:
        rendered.encode("utf-8")
        return rendered
    except UnicodeEncodeError:
        return rendered.encode("utf-8", errors="replace").decode("utf-8")
