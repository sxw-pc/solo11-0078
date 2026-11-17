"""Deterministic migration-plan generation."""

from __future__ import annotations

from collections import Counter
from typing import Any, TYPE_CHECKING

from . import APP_NAME, APP_SLUG, UNICODE_VERSION, __version__
from .models import (
    CERT_LICENSE_LABEL,
    CERT_STATUS_LABEL,
    SEVERITIES,
    SNAPSHOT_ORDER_LABEL,
)

if TYPE_CHECKING:  # pragma: no cover
    from .models import OrderingCertificate, ScanResult, SnapshotOrderObservation


def build_plan(result: "ScanResult") -> dict[str, Any]:
    """Build a content-derived plan. It deliberately contains no wall-clock time."""

    config = result.config
    summary = result.summary
    high = summary["findings_by_severity"].get("high", 0)
    medium = summary["findings_by_severity"].get("medium", 0)
    low = summary["findings_by_severity"].get("low", 0)

    high_findings = [finding for finding in result.findings if finding.severity == "high"]
    blocking_codes = Counter(finding.code for finding in high_findings)
    rule_stats = {item["rule_id"]: item for item in summary["rules"]}
    certificates = {
        certificate.rule_id: certificate for certificate in result.ordering_certificates
    }
    snapshots = {
        observation.rule_id: observation
        for observation in result.snapshot_observations
    }

    rules: list[dict[str, Any]] = []
    for rule in config.keys:
        stats = rule_stats[rule.id]
        rule_high = stats["findings_by_severity"].get("high", 0)
        rule_medium = stats["findings_by_severity"].get("medium", 0)
        if stats["records"] == 0:
            status = "no_records"
        elif rule_high:
            status = "blocked"
        elif rule_medium:
            status = "review"
        else:
            status = "ready"
        cutover = _rule_cutover_permission(
            rule,
            stats,
            certificates.get(rule.id),
        )
        snapshot = snapshots.get(rule.id)
        rules.append(
            {
                "rule_id": rule.id,
                "label": rule.label,
                "source_id": rule.source_id,
                "columns": list(rule.columns),
                "destination": rule.destination,
                "unique": rule.unique,
                "required": rule.required,
                "max_bytes": rule.max_bytes,
                "max_chars": rule.max_chars,
                "transform": rule.transform.as_dict(),
                "transform_text": rule.transform.describe(),
                "status": status,
                "records": stats["records"],
                "non_null_keys": stats["non_null_keys"],
                "changed_keys": stats["changed_keys"],
                "collision_groups": stats["collision_groups"],
                "collision_records": stats["collision_records"],
                "overlength": stats["overlength"],
                "findings_by_severity": stats["findings_by_severity"],
                "blocking_codes": sorted(
                    {
                        finding.code
                        for finding in high_findings
                        if finding.rule_id == rule.id
                    }
                ),
                "snapshot_order": _snapshot_block(snapshot),
                "ordering_certificate": _certificate_block(certificates.get(rule.id)),
                "cutover_permission": cutover,
            }
        )

    collision_steps = []
    for collision in result.collisions[:20]:
        collision_steps.append(
            {
                "group_id": collision.group_id,
                "rule_id": collision.rule_id,
                "source_id": collision.source_id,
                "target_key_escaped": collision.target_key_escaped,
                "reason_code": collision.reason_code,
                "record_count": len(collision.participants),
                "record_ids": [
                    participant.record_id for participant in collision.participants
                ],
                "record_refs": [
                    participant.record_ref for participant in collision.participants
                ],
            }
        )

    source_invalid = [
        {
            "source_id": source["source_id"],
            "path": source["path"],
            "sha256": source["sha256"],
            "encoding": source["encoding"],
        }
        for source in summary["sources"]
        if source["source_findings"] > 0
        or source["findings_by_severity"].get("high", 0) > 0
    ]

    any_blocking = high > 0
    collision_blocking = sum(
        1
        for finding in high_findings
        if finding.code in {"NORMALIZATION_COLLISION", "DUPLICATE_KEY"}
    )

    steps = [
        {
            "order": 1,
            "phase": "baseline",
            "title": "冻结源文件与规则版本",
            "status": "done",
            "detail": (
                f"已完成 {summary['source_count']} 个本地源的只读清点，"
                f"共 {summary['record_count']} 条记录；输入 SHA-256 与配置 SHA-256 已写入计划。"
            ),
            "acceptance": "迁移窗口内输入文件、配置和本计划哈希不得变化。",
            "evidence": ["manifest.json", "plan.json"],
        },
        {
            "order": 2,
            "phase": "canonicalize",
            "title": "固化目标排序键变换",
            "status": "done",
            "detail": (
                f"按 {summary['key_rule_count']} 条声明式规则生成 "
                f"{summary['keys_evaluated']} 个目标键；"
                f"{summary['changed_keys']} 个键经过归一化或折叠后发生变化。"
            ),
            "acceptance": "目标库排序规则与计划中的 binary UTF-8 键语义一致，不使用系统 locale。",
            "evidence": ["plan.json", "keys.jsonl"],
        },
        {
            "order": 3,
            "phase": "blockers",
            "title": "清除编码、缺失与长度阻断项",
            "status": "blocked" if any_blocking else "ready",
            "detail": (
                f"当前有 {high} 项高等级发现，涉及 {len(blocking_codes)} 类检查。"
                if any_blocking
                else "没有高等级编码、缺失或长度问题。"
            ),
            "acceptance": "高等级发现为 0；源不可解码字节、替代字符与超限键全部有处置记录。",
            "blocking_codes": dict(sorted(blocking_codes.items())),
        },
        {
            "order": 4,
            "phase": "collisions",
            "title": "人工仲裁唯一键碰撞组",
            "status": "blocked" if collision_blocking else "ready",
            "detail": (
                f"发现 {summary['collision_groups']} 个唯一键碰撞组，"
                f"涉及 {summary['collision_records']} 条记录；工具不自动合并、删除或改写业务记录。"
            ),
            "acceptance": "每个碰撞组均有业务负责人裁决；唯一键重跑后碰撞组为 0。",
            "evidence": ["collisions.json"],
            "examples": collision_steps,
        },
        {
            "order": 5,
            "phase": "hygiene",
            "title": "处理不可见字符与异常空白",
            "status": "review" if medium else "ready",
            "detail": (
                "按检查码汇总不可见格式符、双向控制符、控制字符、异常空白和疑似乱码；"
                "任何清理必须回到源系统变更流程，不能只改目标键。"
            ),
            "acceptance": "每条中等级发现均有豁免或源数据修复记录；豁免需写明理由与到期日。",
            "counts": {
                code: count
                for code, count in summary["findings_by_code"].items()
                if code
                in {
                    "INVISIBLE_CHARACTER",
                    "BIDI_CONTROL",
                    "CONTROL_CHARACTER",
                    "ABNORMAL_WHITESPACE",
                    "MOJIBAKE_SUSPECT",
                }
            },
        },
        {
            "order": 6,
            "phase": "shadow",
            "title": "在影子库生成排序键并做旧新对比",
            "status": "pending" if any_blocking else "ready",
            "detail": (
                "本工具不执行任何 UPDATE/INSERT/DELETE。"
                "在独立影子环境按目标键重建索引，对旧排序与新排序做逐键抽样比对，"
                "记录排序迁移造成的顺序变化。"
            ),
            "acceptance": "影子库键总数与预检一致；唯一索引创建成功；抽样对比无未解释差异。",
        },
        {
            "order": 7,
            "phase": "ordering_certificate",
            "title": "核验未来键域排序兼容证书与直译许可",
            "status": _certificate_step_status(result),
            "detail": _certificate_step_detail(result),
            "acceptance": (
                "仅当规则在声明有限域上被穷尽证明保序且唯一、碰撞与长度门禁同时通过时，"
                "才允许把旧范围边界/seek 游标直译为目标 binary UTF-8 键；"
                "有界搜索未穷尽只输出 unknown，未发现反例不得当作已证保序。"
            ),
            "evidence": ["plan.json", "certificates.json", "ledger.sqlite"],
        },
        {
            "order": 8,
            "phase": "cutover",
            "title": "按门禁复跑并放行切换",
            "status": "pending",
            "detail": (
                "使用同一配置复跑并启用 --fail-on high。"
                "只有碰撞组为 0、高等级发现为 0、输入哈希未变化，"
                "且范围/游标切换规则具备已证保序证书或已改走保守路线时才允许切换。"
            ),
            "acceptance": (
                "复跑命令退出码为 0；manifest.json 校验通过；"
                "碰撞组 0；所有必需键非空；直译许可与证书状态一致。"
            ),
            "evidence": ["manifest.json", "report.html"],
        },
    ]

    return {
        "schema_version": 1,
        "kind": "charorder.migration_plan",
        "app": APP_NAME,
        "slug": APP_SLUG,
        "tool_version": __version__,
        "unicode_version": UNICODE_VERSION,
        "run_id": result.run_id,
        "project": config.project.name,
        "target": config.project.target,
        "config_sha256": config.config_sha256,
        "run_verdict": result.verdict,
        "gate": {
            "fail_on": "high",
            "blocking_findings": high,
            "collision_groups": summary["collision_groups"],
            "passes": high == 0 and summary["collision_groups"] == 0,
        },
        "summary": {
            "source_count": summary["source_count"],
            "record_count": summary["record_count"],
            "key_rule_count": summary["key_rule_count"],
            "keys_evaluated": summary["keys_evaluated"],
            "non_null_keys": summary["non_null_keys"],
            "changed_keys": summary["changed_keys"],
            "findings_by_severity": {
                severity: summary["findings_by_severity"].get(severity, 0)
                for severity in SEVERITIES
            },
            "collision_groups": summary["collision_groups"],
            "collision_records": summary["collision_records"],
            "overlength_keys": summary["overlength_keys"],
        },
        "source_fingerprints": [
            {
                "source_id": source["source_id"],
                "kind": source["kind"],
                "path": source["path"],
                "sha256": source["sha256"],
                "size_bytes": source["size_bytes"],
                "encoding": source["encoding"],
                "records": source["records"],
                "status": (
                    "blocked"
                    if source["findings_by_severity"].get("high", 0)
                    else "review"
                    if source["findings_by_severity"].get("medium", 0)
                    else "ready"
                ),
            }
            for source in summary["sources"]
        ],
        "sources_with_issues": source_invalid,
        "ordering_certificates": {
            "target_order": "binary_utf8",
            "unicode_version": UNICODE_VERSION,
            "counts": summary["ordering_certificates"],
            "certificates": [
                certificate.to_dict() for certificate in result.ordering_certificates
            ],
        },
        "snapshot_order_observations": [
            observation.to_dict() for observation in result.snapshot_observations
        ],
        "cutover_permissions": {
            rule["rule_id"]: rule["cutover_permission"] for rule in rules
        },
        "rules": rules,
        "steps": steps,
        "forbidden_actions": [
            "不得由本工具自动合并、删除或改写碰撞记录",
            "不得自动“修复”疑似乱码而覆盖原值",
            "不得把校验失败的目标键直接写入生产唯一索引",
            "不得将源文件或 SQLite 台账当作可回写数据源",
        ],
        "reproduce": {
            "config_file": config.config_path.name,
            "config_sha256": config.config_sha256,
            "input_sha256": summary["input_sha256"],
            "command_template": (
                "python -m charorder run --config <CONFIG> --out <NEW_OUTPUT_DIR> "
                "--fail-on high"
            ),
        },
    }


def _snapshot_block(snapshot: "SnapshotOrderObservation | None") -> dict[str, Any]:
    if snapshot is None:
        return {
            "state": "no_records",
            "state_label": SNAPSHOT_ORDER_LABEL["no_records"],
            "records": 0,
            "inversion_count": 0,
            "confluence_count": 0,
            "examples": [],
        }
    return {
        "state": snapshot.state,
        "state_label": SNAPSHOT_ORDER_LABEL.get(snapshot.state, snapshot.state),
        "records": snapshot.records,
        "inversion_count": snapshot.inversion_count,
        "confluence_count": snapshot.confluence_count,
        "examples": list(snapshot.examples),
    }


def _certificate_block(certificate: "OrderingCertificate | None") -> dict[str, Any] | None:
    if certificate is None:
        return None
    return certificate.to_dict()


def _rule_cutover_permission(
    rule: Any,
    stats: dict[str, Any],
    certificate: "OrderingCertificate | None",
) -> dict[str, Any]:
    """Decide whether old range boundaries/cursors may be translated directly.

    Snapshot gates (collisions, overlength, other high findings) always apply.
    The certificate decides the ordering-specific license; an unproven domain
    never inherits permission merely because the current snapshot looked clean.
    """

    snapshot_gate_blocked = (
        stats["collision_groups"] > 0
        or stats["overlength"] > 0
        or stats["findings_by_severity"].get("high", 0) > 0
    )

    if certificate is None:
        return {
            "direct_translation_allowed": False,
            "license": "not_established",
            "license_label": CERT_LICENSE_LABEL["not_established"],
            "basis": "no_certificate_declared",
            "detail": (
                "未声明可核验的未来原键域；当前快照无倒序不能外推到未来键，"
                "范围/游标切换须维持旧排序服务或做目标侧全域过滤。"
            ),
            "snapshot_gate_blocked": snapshot_gate_blocked,
            "certificate_status": None,
        }

    allowed = (
        certificate.license == "direct_translation"
        and certificate.status == "proven"
        and not snapshot_gate_blocked
    )
    if certificate.status == "proven" and not snapshot_gate_blocked:
        detail = (
            "声明有限域已穷尽证明保序且目标键唯一，碰撞/长度门禁通过，"
            "可将旧范围边界/seek 游标直译为目标 binary UTF-8 键。"
        )
    elif certificate.status == "proven":
        detail = (
            "域内已证保序，但当前快照的碰撞/长度/高等级门禁未通过，"
            "直译暂不生效，须先清除阻断项后复跑。"
        )
    elif certificate.status == "counterexample":
        detail = (
            "声明域内已重放出倒序或合流反例，直译被证书阻断；"
            "即使当前快照未观察到问题，也必须维持旧排序或目标侧全域过滤。"
        )
    elif certificate.status == "invalid_domain":
        detail = (
            "未来键域声明无效或成员全部被门禁排除，无法产生保序结论，直译阻断。"
        )
    else:
        detail = (
            "域规模超出穷尽限制，仅完成有界反例搜索且未穷尽；"
            "未找到反例不等于已证保序，直译不予授权。"
        )

    return {
        "direct_translation_allowed": allowed,
        "license": certificate.license,
        "license_label": CERT_LICENSE_LABEL.get(certificate.license, certificate.license),
        "basis": "ordering_certificate",
        "detail": detail,
        "snapshot_gate_blocked": snapshot_gate_blocked,
        "certificate_status": certificate.status,
        "certificate_status_label": CERT_STATUS_LABEL.get(
            certificate.status, certificate.status
        ),
        "certificate_id": certificate.certificate_id,
    }


def _certificate_step_status(result: "ScanResult") -> str:
    if not result.ordering_certificates:
        return "pending"
    if any(c.status in {"counterexample", "invalid_domain"} for c in result.ordering_certificates):
        return "blocked"
    if any(c.status == "unknown" for c in result.ordering_certificates):
        return "review"
    return "ready"


def _certificate_step_detail(result: "ScanResult") -> str:
    if not result.ordering_certificates:
        return (
            "本次没有规则声明可核验的未来原键域；快照双排序只评价已载入记录，"
            "不能保证未来新增键仍可用旧范围边界或游标直接查询。"
        )
    counts = Counter(c.status for c in result.ordering_certificates)
    return (
        f"共 {len(result.ordering_certificates)} 条规则声明未来键域："
        f"已证保序 {counts.get('proven', 0)} 条、"
        f"反例阻断 {counts.get('counterexample', 0)} 条、"
        f"未穷尽 unknown {counts.get('unknown', 0)} 条、"
        f"无效域 {counts.get('invalid_domain', 0)} 条。"
        "当前快照观察、未来域证书与无证明三类结论分别列示，不合并为单一通过状态。"
    )
