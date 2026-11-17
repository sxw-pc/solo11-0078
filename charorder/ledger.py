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
from .transforms import sanitize_text


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
        CREATE TABLE preflight_runs (
            run_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            stale INTEGER NOT NULL,
            stale_reasons_json TEXT NOT NULL,
            config_sha256 TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            rules_sha256 TEXT NOT NULL,
            constraint_digest TEXT NOT NULL,
            evidence_verified INTEGER NOT NULL,
            candidate_rule_ids_json TEXT NOT NULL,
            total_combinations INTEGER NOT NULL,
            examined_combinations INTEGER NOT NULL,
            budget_exhausted INTEGER NOT NULL,
            relation_summary_json TEXT NOT NULL,
            witness_json TEXT,
            notes_json TEXT NOT NULL,
            config_summary_json TEXT NOT NULL
        );
        CREATE TABLE preflight_objectives (
            objective TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_code INTEGER NOT NULL,
            provisional INTEGER NOT NULL,
            exhaustive INTEGER NOT NULL,
            combination_rank INTEGER NOT NULL,
            changed_records INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            selected_transforms_json TEXT NOT NULL,
            checks_json TEXT NOT NULL,
            proof_json TEXT NOT NULL
        );
        CREATE TABLE preflight_rule_selections (
            objective TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            transform_json TEXT NOT NULL,
            PRIMARY KEY (objective, rule_id)
        );
        CREATE TABLE preflight_key_results (
            objective TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            old_key TEXT,
            old_bytes INTEGER NOT NULL,
            new_key TEXT,
            new_bytes INTEGER NOT NULL,
            changed INTEGER NOT NULL,
            transform_json TEXT NOT NULL,
            defects_json TEXT NOT NULL,
            PRIMARY KEY (objective, rule_id, record_ref)
        );
        CREATE TABLE preflight_relations (
            relation_kind TEXT NOT NULL,
            relation_id TEXT NOT NULL,
            objective TEXT NOT NULL,
            status TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            PRIMARY KEY (relation_kind, relation_id, objective)
        );
        CREATE INDEX ix_key_results_rule ON key_results (rule_id, target_key);
        CREATE INDEX ix_key_results_source ON key_results (source_id, record_ref);
        CREATE INDEX ix_findings_severity ON findings (severity, code);
        CREATE INDEX ix_findings_source ON findings (source_id);
        CREATE INDEX ix_findings_rule ON findings (rule_id);
        CREATE INDEX ix_collisions_rule ON collisions (rule_id);
        CREATE INDEX ix_collision_members_record ON collision_members (record_ref);
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
        CREATE VIEW preflight_objective_summary AS
            SELECT o.objective, o.status, o.provisional, o.changed_records,
                   o.total_bytes, r.examined_combinations, r.state, r.stale
            FROM preflight_objectives o
            JOIN preflight_runs r ON r.run_id = o.run_id
            ORDER BY o.objective;
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
    preflight = result.preflight
    if preflight is not None:
        _insert_preflight(connection, result, preflight)


def _insert_preflight(
    connection: sqlite3.Connection,
    result: ScanResult,
    preflight: Any,
) -> None:
    connection.execute(
        """
        INSERT INTO preflight_runs (
            run_id, state, stale, stale_reasons_json, config_sha256,
            source_digest, rules_sha256, constraint_digest, evidence_verified,
            candidate_rule_ids_json, total_combinations, examined_combinations,
            budget_exhausted, relation_summary_json, witness_json, notes_json,
            config_summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.run_id,
            preflight.state,
            int(preflight.stale),
            _json(preflight.stale_reasons),
            preflight.config_sha256,
            preflight.source_digest,
            preflight.rules_sha256,
            preflight.constraint_digest,
            int(preflight.evidence_verified),
            _json(preflight.candidate_rule_ids),
            preflight.total_combinations,
            preflight.examined_combinations,
            int(preflight.budget_exhausted),
            _json(preflight.relation_summary),
            None if preflight.witness is None else _json(preflight.witness),
            _json(preflight.notes),
            _json(preflight.config_summary),
        ),
    )
    for objective, evaluation in preflight.objective_results.items():
        if evaluation is None:
            continue
        connection.execute(
            """
            INSERT INTO preflight_objectives (
                objective, run_id, status, exit_code, provisional, exhaustive,
                combination_rank, changed_records, total_bytes,
                selected_transforms_json, checks_json, proof_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                objective,
                result.run_id,
                evaluation.status,
                evaluation.exit_code,
                int(evaluation.provisional),
                int(evaluation.exhaustive),
                evaluation.combination_rank,
                evaluation.changed_records,
                evaluation.total_bytes,
                _json(
                    {
                        rule_id: spec.as_dict()
                        for rule_id, spec in evaluation.selected_transforms.items()
                    }
                ),
                _json(evaluation.checks),
                _json(evaluation.proof),
            ),
        )
        connection.executemany(
            """
            INSERT INTO preflight_rule_selections (
                objective, rule_id, transform_json
            ) VALUES (?, ?, ?)
            """,
            [
                (objective, rule_id, _json(spec.as_dict()))
                for rule_id, spec in evaluation.selected_transforms.items()
            ],
        )
        connection.executemany(
            """
            INSERT INTO preflight_key_results (
                objective, rule_id, source_id, record_ref, record_id,
                old_key, old_bytes, new_key, new_bytes, changed,
                transform_json, defects_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    objective,
                    item.rule_id,
                    item.source_id,
                    item.record_ref,
                    item.record_id,
                    None if item.old_key is None else sanitize_text(item.old_key),
                    item.old_bytes,
                    None if item.new_key is None else sanitize_text(item.new_key),
                    item.new_bytes,
                    int(item.changed),
                    _json(item.transform.as_dict()),
                    _json(item.defects),
                )
                for item in evaluation.key_evidence
            ],
        )
        relations = evaluation.checks.get("relations", {})
        for relation_kind, relation_id, status in _relation_rows(
            preflight, evaluation
        ):
            connection.execute(
                """
                INSERT OR REPLACE INTO preflight_relations (
                    relation_kind, relation_id, objective, status, detail_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    relation_kind,
                    relation_id,
                    objective,
                    status,
                    _json(relations),
                ),
            )


def _relation_rows(preflight: Any, evaluation: Any):
    spec = preflight.relation_summary or {}
    checks = evaluation.checks.get("relations", {})
    for link_id in spec.get("authorized_link_ids", []):
        yield (
            "authorized_link",
            link_id,
            "satisfied" if checks.get("authorized_links_satisfied") else "violated",
        )
    for pair_id in spec.get("forbidden_pair_ids", []):
        yield (
            "forbidden_pair",
            pair_id,
            "clear" if checks.get("forbidden_pairs_clear") else "violated",
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
