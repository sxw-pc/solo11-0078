"""Scanning engine: evaluate declarative keys, defects, and collisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import replace
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
    TURKIC_LANGUAGES,
    analyze_text,
    apply_transform_traced,
    contains_turkic_sensitive_codepoints,
    escaped_text,
    format_raw_values,
    has_unit_separator,
    sanitize_text,
    sha256_text,
    utf8_bytes,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _resolve_language(
    rule: KeyRule, record: SourceRecord
) -> tuple[str | None, str]:
    """Resolve the verifiable language tag for one record.

    Returns ``(primary_subtag_or_None, status)`` where status is one of
    ``declared`` (unified source), ``resolved`` (record field), ``missing``,
    ``invalid`` or ``unsupported``. A rule without a language policy returns
    ``(None, "not_configured")`` and never blocks the legacy pipeline.
    """

    policy = rule.transform.language_policy
    if policy is None:
        return None, "not_configured"

    if policy.default_language is not None:
        return policy.default_language, "declared"

    raw = record.values.get(policy.tag_field)
    if raw is None:
        return None, "missing"
    text = str(raw).strip()
    if not text:
        return None, "missing"
    if not re.fullmatch(r"[a-zA-Z]{2,3}(?:-[A-Za-z0-9]+)*", text):
        return None, "invalid"
    primary = text.split("-", 1)[0].lower()
    if primary not in policy.supported_languages:
        return primary, "unsupported"
    return primary, "resolved"


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
        # Language tags never hide a collision: records sharing one target key
        # are grouped regardless of their declared language.
        languages = sorted(
            {
                participant.language_tag or "unknown"
                for participant in participants
            }
        )
        cross_language = len(languages) > 1
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
            languages=languages,
            cross_language=cross_language,
        )
        collisions.append(group)
        add_finding(
            reason,
            (
                f"唯一键 {rule_id} 有 {len(participants)} 条记录映射到同一目标键 "
                f"{group.target_key_escaped}，需业务仲裁后再建唯一索引"
                + (
                    f"；该碰撞跨语言标签 {languages}，语言身份不得掩盖跨语言同键"
                    if cross_language
                    else ""
                )
            ),
            source_id=rule.source_id,
            rule_id=rule_id,
            details={
                "group_id": group_id,
                "target_key_sha256": sha256_text(target_key),
                "target_key_escaped": group.target_key_escaped,
                "record_count": len(participants),
                "distinct_raw_count": len(raw_variants_set),
                "languages": languages,
                "cross_language": cross_language,
                "sample_participants": [
                    {
                        "record_ref": participant.record_ref,
                        "record_id": participant.record_id,
                        "language_tag": participant.language_tag,
                        "language_status": participant.language_status,
                        "case_contract": participant.case_contract,
                        "raw_display": participant.raw_display,
                    }
                    for participant in participants[:20]
                ],
            },
            severity=config.severity_for(reason),
        )
        if cross_language:
            add_finding(
                "CROSS_LANGUAGE_COLLISION",
                (
                    f"唯一键 {rule_id} 的目标键 {group.target_key_escaped} "
                    f"被不同语言标签的记录共享：{languages}；"
                    "共享目标索引内的跨语言碰撞必须按真实碰撞处理"
                ),
                source_id=rule.source_id,
                rule_id=rule_id,
                details={
                    "group_id": group_id,
                    "target_key_escaped": group.target_key_escaped,
                    "languages": languages,
                    "record_count": len(participants),
                },
                severity=config.severity_for("CROSS_LANGUAGE_COLLISION"),
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

    for column in rule.columns:
        raw = record.values.get(column)
        if raw is None:
            missing_columns.append(column)
        raw_str = None if raw is None else str(raw)
        raw_components.append(raw_str)
        if raw_str is not None:
            for issue in analyze_text(raw_str, column=column):
                defects.append(
                    Defect(
                        code=issue.code,
                        severity=config.severity_for(issue.code),
                        message=issue.message,
                        details=issue.details,
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

    # --- Language identity preflight (explicit opt-in) --------------------
    language_tag, language_status = _resolve_language(rule, record)
    policy = rule.transform.language_policy
    use_turkic_mapping = False
    present_components = [
        component for component in raw_components if component is not None
    ]
    value_is_turkic_sensitive = any(
        contains_turkic_sensitive_codepoints(component)
        for component in present_components
    )

    if policy is not None:
        if language_status in {"missing", "invalid"}:
            code = (
                "LANGUAGE_TAG_MISSING"
                if language_status == "missing"
                else "LANGUAGE_TAG_INVALID"
            )
            source_desc = (
                f"记录字段 {policy.tag_field}"
                if policy.tag_field
                else f"统一声明 {policy.default_language}"
            )
            defects.append(
                Defect(
                    code=code,
                    severity=config.severity_for(code),
                    message=(
                        f"键 {rule.id} 的语言身份标签"
                        + ("缺失" if language_status == "missing" else "格式非法")
                        + f"（来源：{source_desc}）；不得猜测 Turkic 键等价类，"
                        "该记录按语言中性映射保留并阻断迁移"
                    ),
                    details={
                        "tag_field": policy.tag_field,
                        "default_language": policy.default_language,
                        "contract": policy.contract,
                    },
                    column=policy.tag_field,
                )
            )
        elif language_status == "unsupported":
            if value_is_turkic_sensitive:
                defects.append(
                    Defect(
                        code="LANGUAGE_TAG_UNSUPPORTED",
                        severity=config.severity_for("LANGUAGE_TAG_UNSUPPORTED"),
                        message=(
                            f"键 {rule.id} 的记录语言标签 {language_tag!r} 不在声明支持范围 "
                            f"{sorted(policy.supported_languages)} 内，且原值含 I/İ/ı/i 或 "
                            "U+0307；无合同可证其大小写等价类，按语言中性映射保留并阻断迁移"
                        ),
                        details={
                            "language_tag": language_tag,
                            "supported_languages": list(policy.supported_languages),
                            "contract": policy.contract,
                        },
                        column=policy.tag_field,
                    )
                )
        elif language_status in {"resolved", "declared"} and language_tag in TURKIC_LANGUAGES:
            if policy.contract == "neutral_only":
                if value_is_turkic_sensitive:
                    defects.append(
                        Defect(
                            code="TURKIC_CASE_GOVERNANCE_REQUIRED",
                            severity=config.severity_for(
                                "TURKIC_CASE_GOVERNANCE_REQUIRED"
                            ),
                            message=(
                                f"记录声明语言 {language_tag}，原值含 I/İ/ı/i 或 U+0307；"
                                f"neutral_only 合同不放行 locale-neutral 小写结果，"
                                "须先在源系统完成 Turkic 大小写治理，或改用 language_aware 合同"
                            ),
                            details={
                                "language_tag": language_tag,
                                "contract": policy.contract,
                                "sensitive_codepoints": sorted(
                                    {
                                        f"U+{ord(ch):04X}"
                                        for component in present_components
                                        for ch in component
                                        if contains_turkic_sensitive_codepoints(ch)
                                    }
                                ),
                            },
                        )
                    )
            else:  # language_aware with a verifiable tr/az tag
                use_turkic_mapping = True

    target_key: str | None = None
    target_escaped: str | None = None
    key_hash: str | None = None
    key_bytes = 0
    key_chars = 0
    changed = False
    traces: list[Any] = []
    case_contract = "neutral"

    if not missing_columns:
        assert all(component is not None for component in raw_components)
        components = [component for component in raw_components if component is not None]
        mapping_language = language_tag if use_turkic_mapping else None
        transformed: list[str] = []
        for component_index, component in enumerate(components):
            mapped, trace = apply_transform_traced(
                component, rule.transform, language=mapping_language
            )
            # The trace index is positional relative to the key components.
            traces.append(
                replace(trace, component_index=component_index)
            )
            transformed.append(mapped)
        case_contract = traces[0].case_contract if traces else "neutral"
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
        language_tag=language_tag,
        language_status=language_status,
        case_contract=case_contract,
        traces=traces,
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

    rule_summaries: list[dict[str, Any]] = []
    for rule in config.keys:
        related_results = [result for result in results if result.rule_id == rule.id]
        related_findings = [finding for finding in findings if finding.rule_id == rule.id]
        rule_collisions = [
            collision for collision in collisions if collision.rule_id == rule.id
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
                "collision_groups": len(rule_collisions),
                "collision_records": sum(
                    len(collision.participants) for collision in rule_collisions
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
        "findings_total": len(findings),
        "findings_by_severity": {
            severity: severity_counts.get(severity, 0) for severity in SEVERITIES
        },
        "findings_by_code": dict(sorted(code_counts.items())),
        "collision_groups": len(collisions),
        "collision_records": sum(len(group.participants) for group in collisions),
        "cross_language_collision_groups": sum(
            1 for group in collisions if group.cross_language
        ),
        "language_preflight": _language_preflight_summary(config, results),
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


def _language_preflight_summary(
    config: AppConfig, results: list[KeyResult]
) -> dict[str, Any]:
    """Per-rule language contract statistics over the whole record set."""

    rules: dict[str, Any] = {}
    totals = Counter()
    for result in results:
        rule = config.key_map[result.rule_id]
        policy = rule.transform.language_policy
        if policy is None:
            continue
        bucket = rules.setdefault(
            result.rule_id,
            {
                "contract": policy.contract,
                "tag_field": policy.tag_field,
                "default_language": policy.default_language,
                "supported_languages": list(policy.supported_languages),
                "records": 0,
                "by_status": Counter(),
                "by_language": Counter(),
                "turkic_mapped": 0,
                "neutral_mapped": 0,
                "blocked_by_language": 0,
                "migratable": 0,
            },
        )
        bucket["records"] += 1
        bucket["by_status"][result.language_status] += 1
        totals[result.language_status] += 1
        if result.language_tag:
            bucket["by_language"][result.language_tag] += 1
        if result.case_contract in {"turkic_tr", "turkic_az"}:
            bucket["turkic_mapped"] += 1
        else:
            bucket["neutral_mapped"] += 1
        language_blocks = {
            "LANGUAGE_TAG_MISSING",
            "LANGUAGE_TAG_INVALID",
            "LANGUAGE_TAG_UNSUPPORTED",
            "TURKIC_CASE_GOVERNANCE_REQUIRED",
        }
        blocked = any(defect.code in language_blocks for defect in result.defects)
        if blocked:
            bucket["blocked_by_language"] += 1
        elif result.target_key is not None:
            bucket["migratable"] += 1

    serialized: dict[str, Any] = {}
    for rule_id, bucket in sorted(rules.items()):
        serialized[rule_id] = {
            **{key: value for key, value in bucket.items() if not isinstance(value, Counter)},
            "by_status": dict(sorted(bucket["by_status"].items())),
            "by_language": dict(sorted(bucket["by_language"].items())),
        }
    return {
        "totals_by_status": dict(sorted(totals.items())),
        "rules": serialized,
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
