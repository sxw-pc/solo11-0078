"""Scanning engine: evaluate declarative keys, defects, and collisions."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from . import APP_SLUG, UNICODE_VERSION, __version__
from .models import (
    AppConfig,
    CollisionGroup,
    Defect,
    Finding,
    KeyResult,
    KeyRule,
    ScanResult,
    SEVERITIES,
    SEVERITY_RANK,
    SourceLoad,
    SourceRecord,
)
from .planner import build_plan
from .transforms import (
    UNIT_SEPARATOR,
    analyze_text,
    apply_transform,
    escaped_text,
    format_raw_values,
    has_unit_separator,
    sanitize_text,
    sha256_text,
    utf8_bytes,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def compute_run_id(config: AppConfig, loads: Iterable[SourceLoad]) -> str:
    payload = {
        "schema": "charorder/run/v1",
        "tool_version": __version__,
        "unicode_version": UNICODE_VERSION,
        "config_sha256": config.config_sha256,
        "sources": [
            {
                "id": load.spec.id,
                "kind": load.spec.kind,
                "sha256": load.sha256,
                "size_bytes": load.size_bytes,
            }
            for load in loads
        ],
    }
    digest = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return "r-" + digest[:20]


def scan(config: AppConfig, source_loads: list[SourceLoad]) -> ScanResult:
    run_id = compute_run_id(config, source_loads)
    generated_at = now_iso()
    source_order = {source.id: index for index, source in enumerate(config.sources)}
    rule_order = {rule.id: index for index, rule in enumerate(config.keys)}
    findings: list[Finding] = []
    seen_finding_ids: set[str] = set()

    def add_finding(
        code: str,
        message: str,
        *,
        source_id: str | None = None,
        rule_id: str | None = None,
        record_ref: str | None = None,
        record_id: str | None = None,
        column: str | None = None,
        details: dict[str, Any] | None = None,
        severity: str | None = None,
    ) -> Finding:
        parsed_details = details or {}
        fid = _finding_id(
            run_id,
            code,
            source_id,
            rule_id,
            record_ref,
            column,
            parsed_details,
        )
        if fid in seen_finding_ids:
            return Finding(
                finding_id=fid,
                code=code,
                severity=severity or config.severity_for(code),
                message=message,
                source_id=source_id,
                rule_id=rule_id,
                record_ref=record_ref,
                record_id=record_id,
                column=column,
                details=parsed_details,
            )
        seen_finding_ids.add(fid)
        finding = Finding(
            finding_id=fid,
            code=code,
            severity=severity or config.severity_for(code),
            message=message,
            source_id=source_id,
            rule_id=rule_id,
            record_ref=record_ref,
            record_id=sanitize_text(record_id) if record_id else record_id,
            column=column,
            details=parsed_details,
        )
        findings.append(finding)
        return finding

    for load in source_loads:
        for defect in load.issues:
            add_finding(
                defect.code,
                defect.message,
                source_id=load.spec.id,
                column=defect.column,
                details=defect.details,
                severity=defect.severity,
            )

        duplicates = _duplicate_record_ids(load.records)
        for record_id, refs in duplicates.items():
            add_finding(
                "DUPLICATE_RECORD_ID",
                f"记录标识 {record_id!r} 在源内重复 {len(refs)} 次，碰撞归属不可靠",
                source_id=load.spec.id,
                record_id=record_id,
                details={"record_id": record_id, "record_refs": refs},
            )

        for record in load.records:
            for defect in record.defects:
                add_finding(
                    defect.code,
                    defect.message,
                    source_id=load.spec.id,
                    record_ref=record.record_ref,
                    record_id=record.record_id,
                    column=defect.column,
                    details={"record_ref": record.record_ref, **defect.details},
                    severity=defect.severity,
                )

    records = [
        record
        for load in source_loads
        for record in load.records
    ]
    key_results: list[KeyResult] = []
    rule_lookup = config.key_map
    loads_by_source = {load.spec.id: load for load in source_loads}

    for load in source_loads:
        source_rules = [rule for rule in config.keys if rule.source_id == load.spec.id]
        for record in load.records:
            for rule in source_rules:
                result = _evaluate_key(config, run_id, rule, record)
                key_results.append(result)
                for defect in result.defects:
                    add_finding(
                        defect.code,
                        defect.message,
                        source_id=rule.source_id,
                        rule_id=rule.id,
                        record_ref=record.record_ref,
                        record_id=record.record_id,
                        column=defect.column,
                        details={
                            "record_ref": record.record_ref,
                            "rule_id": rule.id,
                            "key_result_id": result.key_result_id,
                            **defect.details,
                        },
                        severity=defect.severity,
                    )

    key_results.sort(
        key=lambda item: (
            source_order.get(item.source_id, 999),
            item.ordinal,
            rule_order.get(item.rule_id, 999),
        )
    )

    # Aggregate tainted keys into one finding per (source, rule) so reviewers
    # see exactly which key rules lost certainty, without flooding the list.
    uncertain_by_rule: dict[tuple[str, str], list[KeyResult]] = defaultdict(list)
    for result in key_results:
        if result.confidence == "uncertain":
            uncertain_by_rule[(result.source_id, result.rule_id)].append(result)
    for (source_id, rule_id), tainted_results in sorted(
        uncertain_by_rule.items(),
        key=lambda item: (
            source_order.get(item[0][0], 999),
            rule_order.get(item[0][1], 999),
        ),
    ):
        scopes = {result.taint_scope for result in tainted_results}
        add_finding(
            "UNCERTAIN_KEY",
            (
                f"规则 {rule_id} 有 {len(tainted_results)} 个目标键受源替换解码污染，"
                "键判定不确定；修复源数据并复跑确认前不得据此放行或仲裁"
            ),
            source_id=source_id,
            rule_id=rule_id,
            details={
                "uncertain_keys": len(tainted_results),
                "taint_scope": sorted(scope for scope in scopes if scope),
                "sample": [
                    {
                        "record_ref": result.record_ref,
                        "record_id": result.record_id,
                        "key_result_id": result.key_result_id,
                        "tainted_columns": list(result.tainted_columns),
                    }
                    for result in tainted_results[:20]
                ],
            },
            severity=config.severity_for("UNCERTAIN_KEY"),
        )

    collisions: list[CollisionGroup] = []
    by_rule_key: dict[tuple[str, str], list[KeyResult]] = defaultdict(list)
    for result in key_results:
        if rule_lookup[result.rule_id].unique and result.target_key is not None:
            by_rule_key[(result.rule_id, result.target_key)].append(result)

    for (rule_id, target_key), participants in sorted(
        by_rule_key.items(),
        key=lambda item: (
            source_order.get(rule_lookup[item[0][0]].source_id, 999),
            rule_order.get(item[0][0], 999),
            item[0][1],
        ),
    ):
        if len(participants) < 2:
            continue
        participants.sort(key=lambda item: item.ordinal)
        rule = rule_lookup[rule_id]
        raw_variants_set: set[tuple[str | None, ...]] = {
            tuple(participant.raw_values) for participant in participants
        }
        reason = (
            "NORMALIZATION_COLLISION"
            if len(raw_variants_set) > 1
            else "DUPLICATE_KEY"
        )
        uncertain_members = [
            participant
            for participant in participants
            if participant.confidence == "uncertain"
        ]
        confidence = "uncertain" if uncertain_members else "certain"
        group_id = _collision_id(run_id, rule_id, target_key)
        for participant in participants:
            participant.collision_group_id = group_id
        group = CollisionGroup(
            group_id=group_id,
            rule_id=rule_id,
            source_id=rule.source_id,
            target_key=sanitize_text(target_key),
            target_key_escaped=escaped_text(sanitize_text(target_key)),
            reason_code=reason,
            participants=participants,
            raw_variants=sorted(
                {
                    format_raw_values(participant.raw_values)
                    for participant in participants
                }
            ),
            confidence=confidence,
        )
        collisions.append(group)
        if confidence == "uncertain":
            # Replacement decoding may have manufactured or masked this
            # group; it must never be presented as a real arbitration object.
            add_finding(
                "UNCERTAIN_COLLISION",
                (
                    f"唯一键 {rule_id} 有 {len(participants)} 条记录映射到目标键 "
                    f"{group.target_key_escaped}，其中 {len(uncertain_members)} 条记录的键"
                    "受替换解码污染，碰撞无法确认；不得据此仲裁，需修复源数据后复跑"
                ),
                source_id=rule.source_id,
                rule_id=rule_id,
                details={
                    "group_id": group_id,
                    "confidence": "uncertain",
                    "uncertain_participants": len(uncertain_members),
                    "target_key_sha256": sha256_text(target_key),
                    "target_key_escaped": group.target_key_escaped,
                    "record_count": len(participants),
                    "distinct_raw_count": len(raw_variants_set),
                    "sample_participants": [
                        {
                            "record_ref": participant.record_ref,
                            "record_id": participant.record_id,
                            "raw_display": participant.raw_display,
                            "confidence": participant.confidence,
                        }
                        for participant in participants[:20]
                    ],
                },
                severity=config.severity_for("UNCERTAIN_COLLISION"),
            )
            continue
        add_finding(
            reason,
            (
                f"唯一键 {rule_id} 有 {len(participants)} 条记录映射到同一目标键 "
                f"{group.target_key_escaped}，需业务仲裁后再建唯一索引"
            ),
            source_id=rule.source_id,
            rule_id=rule_id,
            details={
                "group_id": group_id,
                "confidence": "certain",
                "target_key_sha256": sha256_text(target_key),
                "target_key_escaped": group.target_key_escaped,
                "record_count": len(participants),
                "distinct_raw_count": len(raw_variants_set),
                "sample_participants": [
                    {
                        "record_ref": participant.record_ref,
                        "record_id": participant.record_id,
                        "raw_display": participant.raw_display,
                    }
                    for participant in participants[:20]
                ],
            },
            severity=config.severity_for(reason),
        )

    findings.sort(
        key=lambda finding: (
            SEVERITY_RANK.get(finding.severity, 9),
            source_order.get(finding.source_id or "", 999),
            rule_order.get(finding.rule_id or "", 999),
            finding.record_ref or "",
            finding.code,
            finding.finding_id,
        )
    )

    summary = _summarize(
        config,
        source_loads,
        records,
        key_results,
        findings,
        collisions,
    )
    verdict = _verdict(summary)
    result = ScanResult(
        config=config,
        run_id=run_id,
        generated_at=generated_at,
        source_loads=source_loads,
        records=records,
        key_results=key_results,
        findings=findings,
        collisions=collisions,
        summary=summary,
        verdict=verdict,
        plan={},
    )
    result.plan = build_plan(result)
    return result


def _evaluate_key(
    config: AppConfig, run_id: str, rule: KeyRule, record: SourceRecord
) -> KeyResult:
    defects: list[Defect] = []
    raw_components: list[str | None] = []
    missing_columns: list[str] = []
    tainted_columns = tuple(
        column for column in rule.columns if column in record.tainted_columns
    )
    uncertain = record.taint_unknown or bool(tainted_columns)

    for column in rule.columns:
        raw = record.values.get(column)
        if raw is None:
            missing_columns.append(column)
        raw_str = None if raw is None else str(raw)
        raw_components.append(raw_str)
        if raw_str is not None:
            for issue in analyze_text(raw_str, column=column):
                details = dict(issue.details)
                if issue.code == "REPLACEMENT_CHARACTER":
                    # Distinguish decoder-inserted U+FFFD from legitimate
                    # U+FFFD that was already encoded in the source bytes.
                    if column in record.tainted_columns:
                        details["replacement_origin"] = "decoder_inserted"
                    elif record.taint_unknown:
                        details["replacement_origin"] = "unknown_record_tainted"
                    else:
                        details["replacement_origin"] = "preexisting_in_source"
                defects.append(
                    Defect(
                        code=issue.code,
                        severity=config.severity_for(issue.code),
                        message=issue.message,
                        details=details,
                        column=issue.column,
                    )
                )

    if missing_columns:
        if rule.required:
            defects.append(
                Defect(
                    code="REQUIRED_VALUE_MISSING",
                    severity=config.severity_for("REQUIRED_VALUE_MISSING"),
                    message=(
                        f"必需键 {rule.id} 的分量缺失：{', '.join(missing_columns)}"
                    ),
                    details={"columns": missing_columns},
                    column=missing_columns[0] if len(missing_columns) == 1 else None,
                )
            )

    target_key: str | None = None
    target_escaped: str | None = None
    key_hash: str | None = None
    key_bytes = 0
    key_chars = 0
    changed = False

    if not missing_columns:
        assert all(component is not None for component in raw_components)
        components = [component for component in raw_components if component is not None]
        transformed = [apply_transform(component, rule.transform) for component in components]
        changed = any(before != after for before, after in zip(components, transformed))
        for column, transformed_value in zip(rule.columns, transformed):
            if has_unit_separator(transformed_value):
                defects.append(
                    Defect(
                        code="COMPOSITE_SEPARATOR",
                        severity=config.severity_for("COMPOSITE_SEPARATOR"),
                        message=(
                            "变换后的分量包含 U+001F 单元分隔符，复合键边界将产生歧义"
                        ),
                        details={"column": column, "codepoint": "U+001F"},
                        column=column,
                    )
                )
        target_key = UNIT_SEPARATOR.join(transformed)
        if target_key == "" or all(component == "" for component in transformed):
            defects.append(
                Defect(
                    code="EMPTY_KEY",
                    severity=config.severity_for("EMPTY_KEY"),
                    message=f"键 {rule.id} 的目标值为空",
                    details={"transformed_empty": True},
                    column=rule.columns[0] if len(rule.columns) == 1 else None,
                )
            )
        safe_key = sanitize_text(target_key)
        target_key = safe_key
        target_escaped = escaped_text(safe_key)
        key_hash = sha256_text(safe_key)
        key_bytes = len(utf8_bytes(safe_key))
        key_chars = len(safe_key)
        if rule.max_bytes is not None and key_bytes > rule.max_bytes:
            defects.append(
                Defect(
                    code="KEY_TOO_LONG_BYTES",
                    severity=config.severity_for("KEY_TOO_LONG_BYTES"),
                    message=(
                        f"目标键 {key_bytes} UTF-8 字节，超过声明上限 {rule.max_bytes}"
                    ),
                    details={
                        "actual_bytes": key_bytes,
                        "limit_bytes": rule.max_bytes,
                    },
                )
            )
        if rule.max_chars is not None and key_chars > rule.max_chars:
            defects.append(
                Defect(
                    code="KEY_TOO_LONG_CHARS",
                    severity=config.severity_for("KEY_TOO_LONG_CHARS"),
                    message=(
                        f"目标键 {key_chars} 字符，超过声明上限 {rule.max_chars}"
                    ),
                    details={
                        "actual_chars": key_chars,
                        "limit_chars": rule.max_chars,
                    },
                )
            )

    safe_raw_values = tuple(
        None if value is None else sanitize_text(value) for value in raw_components
    )
    return KeyResult(
        key_result_id=_key_result_id(
            run_id, rule.source_id, rule.id, record.record_ref
        ),
        source_id=rule.source_id,
        rule_id=rule.id,
        ordinal=record.ordinal,
        record_ref=record.record_ref,
        record_id=record.record_id,
        raw_values=safe_raw_values,
        raw_display=format_raw_values(safe_raw_values),
        target_key=target_key,
        target_key_escaped=target_escaped,
        key_sha256=key_hash,
        key_bytes=key_bytes,
        key_chars=key_chars,
        changed=changed,
        defects=defects,
        confidence="uncertain" if uncertain else "certain",
        taint_scope=record.taint_scope if uncertain else None,
        tainted_columns=tainted_columns,
    )


def _duplicate_record_ids(records: list[SourceRecord]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for record in records:
        if record.record_id:
            grouped[record.record_id].append(record.record_ref)
    return {
        record_id: refs
        for record_id, refs in sorted(grouped.items())
        if len(refs) > 1
    }


def _summarize(
    config: AppConfig,
    loads: list[SourceLoad],
    records: list[SourceRecord],
    results: list[KeyResult],
    findings: list[Finding],
    collisions: list[CollisionGroup],
) -> dict[str, Any]:
    severity_counts = Counter(finding.severity for finding in findings)
    code_counts = Counter(finding.code for finding in findings)
    source_order = {source.id: index for index, source in enumerate(config.sources)}
    certain_collisions = [
        group for group in collisions if group.confidence == "certain"
    ]
    uncertain_collisions = [
        group for group in collisions if group.confidence == "uncertain"
    ]

    rule_summaries: list[dict[str, Any]] = []
    for rule in config.keys:
        related_results = [result for result in results if result.rule_id == rule.id]
        related_findings = [finding for finding in findings if finding.rule_id == rule.id]
        rule_collisions = [
            collision for collision in certain_collisions if collision.rule_id == rule.id
        ]
        rule_uncertain_collisions = [
            collision
            for collision in uncertain_collisions
            if collision.rule_id == rule.id
        ]
        rule_severity = Counter(finding.severity for finding in related_findings)
        rule_summaries.append(
            {
                "rule_id": rule.id,
                "label": rule.label,
                "source_id": rule.source_id,
                "records": len(related_results),
                "non_null_keys": sum(
                    1 for result in related_results if result.target_key is not None
                ),
                "changed_keys": sum(1 for result in related_results if result.changed),
                "uncertain_keys": sum(
                    1
                    for result in related_results
                    if result.confidence == "uncertain"
                ),
                "collision_groups": len(rule_collisions),
                "collision_records": sum(
                    len(collision.participants) for collision in rule_collisions
                ),
                "uncertain_collision_groups": len(rule_uncertain_collisions),
                "uncertain_collision_records": sum(
                    len(collision.participants)
                    for collision in rule_uncertain_collisions
                ),
                "overlength": sum(
                    1
                    for result in related_results
                    if any(
                        defect.code in {"KEY_TOO_LONG_BYTES", "KEY_TOO_LONG_CHARS"}
                        for defect in result.defects
                    )
                ),
                "findings": len(related_findings),
                "findings_by_severity": {
                    severity: rule_severity.get(severity, 0)
                    for severity in SEVERITIES
                },
            }
        )

    source_summaries: list[dict[str, Any]] = []
    for load in loads:
        source_findings = [
            finding
            for finding in findings
            if finding.source_id == load.spec.id and finding.rule_id is None
        ]
        source_results = [
            result for result in results if result.source_id == load.spec.id
        ]
        source_severity = Counter(
            finding.severity
            for finding in findings
            if finding.source_id == load.spec.id
        )
        source_summaries.append(
            {
                "source_id": load.spec.id,
                "kind": load.spec.kind,
                "path": load.spec.display_path,
                "sha256": load.sha256,
                "size_bytes": load.size_bytes,
                "encoding": load.spec.encoding,
                "records": len(load.records),
                "columns": list(load.columns),
                "key_results": len(source_results),
                "tainted_records": sum(
                    1 for record in load.records if record.taint_scope != "none"
                ),
                "uncertain_keys": sum(
                    1 for result in source_results if result.confidence == "uncertain"
                ),
                "source_findings": len(source_findings),
                "findings": sum(
                    1
                    for finding in findings
                    if finding.source_id == load.spec.id
                ),
                "findings_by_severity": {
                    severity: source_severity.get(severity, 0)
                    for severity in SEVERITIES
                },
            }
        )

    source_summaries.sort(key=lambda item: source_order.get(item["source_id"], 999))

    return {
        "source_count": len(loads),
        "record_count": len(records),
        "key_rule_count": len(config.keys),
        "keys_evaluated": len(results),
        "non_null_keys": sum(1 for result in results if result.target_key is not None),
        "changed_keys": sum(1 for result in results if result.changed),
        "uncertain_keys": sum(
            1 for result in results if result.confidence == "uncertain"
        ),
        "findings_total": len(findings),
        "findings_by_severity": {
            severity: severity_counts.get(severity, 0) for severity in SEVERITIES
        },
        "findings_by_code": dict(sorted(code_counts.items())),
        "collision_groups": len(certain_collisions),
        "collision_records": sum(len(group.participants) for group in certain_collisions),
        "uncertain_collision_groups": len(uncertain_collisions),
        "uncertain_collision_records": sum(
            len(group.participants) for group in uncertain_collisions
        ),
        "overlength_keys": sum(
            1
            for result in results
            if any(
                defect.code in {"KEY_TOO_LONG_BYTES", "KEY_TOO_LONG_CHARS"}
                for defect in result.defects
            )
        ),
        "sources": source_summaries,
        "rules": rule_summaries,
        "unicode_version": UNICODE_VERSION,
        "input_sha256": {
            load.spec.id: load.sha256 for load in loads
        },
    }


def _verdict(summary: dict[str, Any]) -> str:
    severity = summary["findings_by_severity"]
    if severity.get("high", 0):
        return "blocked"
    if severity.get("medium", 0):
        return "review"
    if severity.get("low", 0):
        return "pass_with_notes"
    return "pass"


def _finding_id(
    run_id: str,
    code: str,
    source_id: str | None,
    rule_id: str | None,
    record_ref: str | None,
    column: str | None,
    details: dict[str, Any],
) -> str:
    raw = {
        "run_id": run_id,
        "code": code,
        "source_id": source_id,
        "rule_id": rule_id,
        "record_ref": record_ref,
        "column": column,
        "details": details,
    }
    digest = hashlib.sha256(
        json.dumps(
            raw, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
    ).hexdigest()
    return "F-" + digest[:16]


def _key_result_id(
    run_id: str, source_id: str, rule_id: str, record_ref: str
) -> str:
    digest = hashlib.sha256(
        f"{APP_SLUG}|{run_id}|{source_id}|{rule_id}|{record_ref}".encode("utf-8")
    ).hexdigest()
    return "K-" + digest[:16]


def _collision_id(run_id: str, rule_id: str, target_key: str) -> str:
    digest = hashlib.sha256(
        b"collision|"
        + run_id.encode("ascii")
        + b"|"
        + rule_id.encode("utf-8")
        + b"|"
        + utf8_bytes(target_key)
    ).hexdigest()
    return "C-" + digest[:16]
