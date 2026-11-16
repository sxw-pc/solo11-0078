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
from .target_index import rule_digest


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
            collision_count INTEGER NOT NULL,
            target_index_count INTEGER NOT NULL DEFAULT 0,
            target_index_blocked_count INTEGER NOT NULL DEFAULT 0
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
            defects_json TEXT NOT NULL
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
        CREATE INDEX ix_key_results_rule ON key_results (rule_id, target_key);
        CREATE INDEX ix_key_results_source ON key_results (source_id, record_ref);
        CREATE INDEX ix_findings_severity ON findings (severity, code);
        CREATE INDEX ix_findings_source ON findings (source_id);
        CREATE INDEX ix_findings_rule ON findings (rule_id);
        CREATE INDEX ix_collisions_rule ON collisions (rule_id);
        CREATE INDEX ix_collision_members_record ON collision_members (record_ref);
        CREATE TABLE target_indexes (
            index_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            label TEXT NOT NULL,
            destination TEXT NOT NULL,
            rule_ids_json TEXT NOT NULL,
            max_bytes INTEGER,
            max_chars INTEGER,
            blocked INTEGER NOT NULL,
            stale INTEGER NOT NULL,
            collision_group_count INTEGER NOT NULL,
            collision_record_count INTEGER NOT NULL,
            projected_row_count INTEGER NOT NULL,
            block_reasons_json TEXT NOT NULL,
            evaluated_at TEXT NOT NULL
        );
        CREATE TABLE target_collisions (
            group_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            index_id TEXT NOT NULL,
            target_key TEXT NOT NULL,
            target_key_escaped TEXT NOT NULL,
            target_key_bytes INTEGER NOT NULL,
            reason_code TEXT NOT NULL,
            decision TEXT NOT NULL,
            adjudication_id TEXT,
            record_count INTEGER NOT NULL,
            distinct_raw_count INTEGER NOT NULL,
            sources_json TEXT NOT NULL,
            rule_ids_json TEXT NOT NULL,
            raw_variants_json TEXT NOT NULL,
            block_reasons_json TEXT NOT NULL,
            PRIMARY KEY (run_id, group_id)
        );
        CREATE TABLE target_collision_members (
            run_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            index_id TEXT NOT NULL,
            key_result_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            raw_display TEXT NOT NULL,
            target_key TEXT,
            rule_digest TEXT NOT NULL,
            PRIMARY KEY (run_id, group_id, key_result_id)
        );
        CREATE TABLE target_projection (
            run_id TEXT NOT NULL,
            index_id TEXT NOT NULL,
            target_key TEXT NOT NULL,
            target_key_escaped TEXT NOT NULL,
            key_bytes INTEGER NOT NULL,
            key_chars INTEGER NOT NULL,
            origin TEXT NOT NULL,
            collision_group_id TEXT,
            adjudication_id TEXT,
            over_bytes INTEGER NOT NULL,
            over_chars INTEGER NOT NULL,
            provenance_json TEXT NOT NULL
        );
        CREATE TABLE adjudications (
            run_id TEXT NOT NULL,
            index_id TEXT NOT NULL,
            adjudication_id TEXT NOT NULL,
            target_key_escaped TEXT NOT NULL,
            decision TEXT NOT NULL,
            reviewed_by TEXT NOT NULL,
            reviewed_at TEXT NOT NULL,
            expires_at TEXT,
            doc_sha256 TEXT NOT NULL,
            stale INTEGER NOT NULL,
            member_count INTEGER NOT NULL,
            replacement_count INTEGER NOT NULL,
            applied INTEGER NOT NULL,
            group_id TEXT,
            block_reasons_json TEXT NOT NULL,
            PRIMARY KEY (run_id, index_id, adjudication_id)
        );
        CREATE INDEX ix_target_projection_key ON target_projection (index_id, target_key);
        CREATE INDEX ix_target_collisions_index ON target_collisions (index_id);
        CREATE INDEX ix_target_members_record
            ON target_collision_members (source_id, record_ref);
        CREATE VIEW target_projection_summary AS
            SELECT index_id, origin, COUNT(*) AS row_count
            FROM target_projection
            GROUP BY index_id, origin
            ORDER BY index_id, origin;
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
            key_result_count, finding_count, collision_count,
            target_index_count, target_index_blocked_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            len(result.target_rehearsals),
            sum(1 for rehearsal in result.target_rehearsals if rehearsal.blocked),
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
            collision_group_id, defects_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    _insert_target_indexes(connection, result)


def _insert_target_indexes(
    connection: sqlite3.Connection, result: ScanResult
) -> None:
    digests = {rule.id: rule_digest(rule) for rule in result.config.keys}
    for rehearsal in result.target_rehearsals:
        spec = rehearsal.spec
        connection.execute(
            """
            INSERT INTO target_indexes (
                index_id, run_id, label, destination, rule_ids_json, max_bytes,
                max_chars, blocked, stale, collision_group_count,
                collision_record_count, projected_row_count, block_reasons_json,
                evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                spec.id,
                result.run_id,
                spec.label,
                spec.destination,
                _json(list(spec.rule_ids)),
                spec.max_bytes,
                spec.max_chars,
                int(rehearsal.blocked),
                int(rehearsal.stale),
                len(rehearsal.groups),
                sum(len(group.participants) for group in rehearsal.groups),
                rehearsal.projected_row_count,
                _json(rehearsal.block_reasons),
                rehearsal.evaluated_at,
            ),
        )
        for group in rehearsal.groups:
            connection.execute(
                """
                INSERT INTO target_collisions (
                    group_id, run_id, index_id, target_key, target_key_escaped,
                    target_key_bytes, reason_code, decision, adjudication_id,
                    record_count, distinct_raw_count, sources_json, rule_ids_json,
                    raw_variants_json, block_reasons_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group.group_id,
                    result.run_id,
                    spec.id,
                    group.target_key,
                    group.target_key_escaped,
                    group.target_key_bytes,
                    group.reason_code,
                    group.decision,
                    group.adjudication_id,
                    len(group.participants),
                    len(group.raw_variants),
                    _json(group.sources),
                    _json(group.rule_ids),
                    _json(group.raw_variants),
                    _json(group.block_reasons),
                ),
            )
            connection.executemany(
                """
                INSERT INTO target_collision_members (
                    run_id, group_id, index_id, key_result_id, source_id, rule_id,
                    record_ref, record_id, raw_display, target_key, rule_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        result.run_id,
                        group.group_id,
                        spec.id,
                        participant.key_result_id,
                        participant.source_id,
                        participant.rule_id,
                        participant.record_ref,
                        participant.record_id,
                        participant.raw_display,
                        participant.target_key,
                        digests.get(participant.rule_id),
                    )
                    for participant in group.participants
                ],
            )
        connection.executemany(
            """
            INSERT INTO target_projection (
                run_id, index_id, target_key, target_key_escaped, key_bytes,
                key_chars, origin, collision_group_id, adjudication_id,
                over_bytes, over_chars, provenance_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    result.run_id,
                    spec.id,
                    row.target_key,
                    row.target_key_escaped,
                    row.key_bytes,
                    row.key_chars,
                    row.origin,
                    row.collision_group_id,
                    row.adjudication_id,
                    int(row.over_bytes),
                    int(row.over_chars),
                    _json(row.provenance),
                )
                for row in rehearsal.projection
            ],
        )
        connection.executemany(
            """
            INSERT INTO adjudications (
                run_id, index_id, adjudication_id, target_key_escaped, decision,
                reviewed_by, reviewed_at, expires_at, doc_sha256, stale,
                member_count, replacement_count, applied, group_id,
                block_reasons_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    result.run_id,
                    spec.id,
                    entry["adjudication_id"],
                    entry["target_key_escaped"],
                    entry["decision"],
                    entry["reviewed_by"],
                    entry["reviewed_at"],
                    entry["expires_at"],
                    entry["doc_sha256"],
                    int(entry["stale"]),
                    entry["member_count"],
                    entry["replacement_count"],
                    int(entry["applied"]),
                    entry["group_id"],
                    _json(entry["block_reasons"]),
                )
                for entry in rehearsal.adjudication_register
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
