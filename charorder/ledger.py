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
        PRAGMA user_version = 2;
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
            visual_candidate_count INTEGER NOT NULL,
            visual_pending_reviews INTEGER NOT NULL,
            visual_unknown_coverage INTEGER NOT NULL
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
            description TEXT NOT NULL,
            script_policy_json TEXT NOT NULL
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
            visual_profile_json TEXT,
            visual_candidate_ids_json TEXT NOT NULL
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
        CREATE TABLE visual_candidates (
            candidate_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            skeleton TEXT NOT NULL,
            skeleton_escaped TEXT NOT NULL,
            skeleton_sha256 TEXT NOT NULL,
            skeleton_version TEXT NOT NULL,
            map_version TEXT NOT NULL,
            policy_mode TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            cross_script INTEGER NOT NULL,
            unknown_coverage INTEGER NOT NULL,
            conclusion TEXT,
            reviewer TEXT,
            review_note TEXT,
            decided_at TEXT,
            record_count INTEGER NOT NULL
        );
        CREATE TABLE visual_candidate_members (
            candidate_id TEXT NOT NULL,
            key_result_id TEXT NOT NULL,
            record_ref TEXT NOT NULL,
            record_id TEXT,
            target_key TEXT NOT NULL,
            target_key_escaped TEXT NOT NULL,
            target_key_sha256 TEXT NOT NULL,
            skeleton TEXT NOT NULL,
            scripts_json TEXT NOT NULL,
            codepoints_json TEXT NOT NULL,
            coverage TEXT NOT NULL,
            mapping_chain_json TEXT NOT NULL,
            PRIMARY KEY (candidate_id, key_result_id)
        );
        CREATE TABLE visual_reviews (
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            skeleton_sha256 TEXT NOT NULL,
            conclusion TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            note TEXT NOT NULL,
            decided_at TEXT NOT NULL,
            map_version TEXT NOT NULL,
            skeleton_version TEXT NOT NULL,
            applied INTEGER NOT NULL,
            coverage_unknown INTEGER NOT NULL,
            PRIMARY KEY (run_id, rule_id, skeleton_sha256)
        );
        CREATE INDEX ix_key_results_rule ON key_results (rule_id, target_key);
        CREATE INDEX ix_key_results_source ON key_results (source_id, record_ref);
        CREATE INDEX ix_findings_severity ON findings (severity, code);
        CREATE INDEX ix_findings_source ON findings (source_id);
        CREATE INDEX ix_findings_rule ON findings (rule_id);
        CREATE INDEX ix_collisions_rule ON collisions (rule_id);
        CREATE INDEX ix_collision_members_record ON collision_members (record_ref);
        CREATE INDEX ix_visual_candidates_rule ON visual_candidates (rule_id, status);
        CREATE INDEX ix_visual_members_key ON visual_candidate_members (key_result_id);
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
        CREATE VIEW visual_candidate_summary AS
            SELECT rule_id, source_id, status, risk_level, unknown_coverage,
                   COUNT(*) AS group_count, SUM(record_count) AS record_count
            FROM visual_candidates
            GROUP BY rule_id, source_id, status, risk_level, unknown_coverage
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
            ("schema_version", "2"),
            ("run_id", result.run_id),
            ("ledger_written_at", result.generated_at),
            (
                "visual_skeleton_version",
                result.summary["visual_confusable_map"]["skeleton_version"],
            ),
            (
                "visual_map_version",
                result.summary["visual_confusable_map"]["map_version"],
            ),
            (
                "visual_map_sha256",
                result.summary["visual_confusable_map"]["map_sha256"],
            ),
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
            visual_candidate_count, visual_pending_reviews, visual_unknown_coverage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            summary["visual_candidate_groups"],
            summary["visual_pending_reviews"],
            summary["visual_unknown_coverage"],
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
                description, script_policy_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _json(rule.script_policy.as_dict() if rule.script_policy else None),
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
            collision_group_id, defects_json, visual_profile_json,
            visual_candidate_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _json(item.visual_profile) if item.visual_profile else None,
                _json(list(item.visual_candidate_ids)),
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

    connection.executemany(
        """
        INSERT INTO visual_candidates (
            candidate_id, run_id, rule_id, source_id, skeleton, skeleton_escaped,
            skeleton_sha256, skeleton_version, map_version, policy_mode, status,
            risk_level, cross_script, unknown_coverage, conclusion, reviewer,
            review_note, decided_at, record_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                candidate.candidate_id,
                result.run_id,
                candidate.rule_id,
                candidate.source_id,
                candidate.skeleton,
                candidate.skeleton_escaped,
                candidate.skeleton_sha256,
                candidate.skeleton_version,
                candidate.map_version,
                candidate.policy_mode,
                candidate.status,
                candidate.risk_level,
                int(candidate.cross_script),
                int(candidate.unknown_coverage),
                candidate.conclusion,
                candidate.reviewer,
                candidate.review_note,
                candidate.decided_at,
                len(candidate.members),
            )
            for candidate in result.visual_candidates
        ],
    )
    connection.executemany(
        """
        INSERT INTO visual_candidate_members (
            candidate_id, key_result_id, record_ref, record_id, target_key,
            target_key_escaped, target_key_sha256, skeleton, scripts_json,
            codepoints_json, coverage, mapping_chain_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                candidate.candidate_id,
                member["key_result_id"],
                member["record_ref"],
                member["record_id"],
                member["target_key"],
                member["target_key_escaped"],
                member["target_key_sha256"],
                member["skeleton_escaped"],
                _json(member["scripts"]),
                _json(member["codepoints"]),
                member["coverage"],
                _json(member.get("mapping_chain", [])),
            )
            for candidate in result.visual_candidates
            for member in candidate.members
        ],
    )
    applied = {
        (candidate.rule_id, candidate.skeleton_sha256)
        for candidate in result.visual_candidates
        if candidate.status == "reviewed"
    }
    connection.executemany(
        """
        INSERT INTO visual_reviews (
            run_id, rule_id, skeleton_sha256, conclusion, reviewer, note,
            decided_at, map_version, skeleton_version, applied, coverage_unknown
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                result.run_id,
                review.rule_id,
                review.skeleton_sha256,
                review.conclusion,
                review.reviewer,
                review.note,
                review.decided_at,
                review.map_version,
                review.skeleton_version,
                int((review.rule_id, review.skeleton_sha256) in applied),
                _coverage_unknown_for_rule(result, review.rule_id),
            )
            for review in result.config.visual_reviews
        ],
    )


def _coverage_unknown_for_rule(result: ScanResult, rule_id: str) -> int:
    """1 when the given rule has at least one map-coverage-unknown finding.

    Reviewing a candidate cannot certify a rule whose components contain
    characters the bundled map cannot classify.
    """

    return int(
        any(
            finding.code == "VISUAL_COVERAGE_UNKNOWN" and finding.rule_id == rule_id
            for finding in result.findings
        )
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
