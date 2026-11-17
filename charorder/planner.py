"""Deterministic migration-plan generation."""

from __future__ import annotations

from collections import Counter
from typing import Any, TYPE_CHECKING

from . import APP_NAME, APP_SLUG, UNICODE_VERSION, __version__
from .models import SEVERITIES

if TYPE_CHECKING:  # pragma: no cover
    from .models import ScanResult


def _visual_candidate_steps(result: "ScanResult") -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for candidate in result.visual_candidates[:20]:
        steps.append(
            {
                "candidate_id": candidate.candidate_id,
                "rule_id": candidate.rule_id,
                "skeleton_escaped": candidate.skeleton_escaped,
                "risk_level": candidate.risk_level,
                "status": candidate.status,
                "cross_script": candidate.cross_script,
                "unknown_coverage": candidate.unknown_coverage,
                "conclusion": candidate.conclusion,
                "record_refs": [member["record_ref"] for member in candidate.members],
                "member_keys_escaped": [
                    member["target_key_escaped"] for member in candidate.members
                ],
            }
        )
    return steps


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
    visual_by_rule: dict[str, list[Any]] = {}
    for candidate in result.visual_candidates:
        visual_by_rule.setdefault(candidate.rule_id, []).append(candidate)

    rules: list[dict[str, Any]] = []
    for rule in config.keys:
        stats = rule_stats[rule.id]
        rule_high = stats["findings_by_severity"].get("high", 0)
        rule_medium = stats["findings_by_severity"].get("medium", 0)
        rule_visual = visual_by_rule.get(rule.id, [])
        pending_visual = sum(
            1 for candidate in rule_visual if candidate.status == "review_required"
        )
        unknown_visual = sum(
            1 for candidate in rule_visual if candidate.unknown_coverage
        )
        if stats["records"] == 0:
            status = "no_records"
        elif rule_high:
            status = "blocked"
        elif rule_medium or pending_visual:
            status = "review"
        else:
            status = "ready"
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
                "script_policy": (
                    rule.script_policy.as_dict() if rule.script_policy else None
                ),
                "status": status,
                "records": stats["records"],
                "non_null_keys": stats["non_null_keys"],
                "changed_keys": stats["changed_keys"],
                "collision_groups": stats["collision_groups"],
                "collision_records": stats["collision_records"],
                "overlength": stats["overlength"],
                "visual_candidate_groups": len(rule_visual),
                "visual_candidate_records": sum(
                    len(candidate.members) for candidate in rule_visual
                ),
                "visual_pending_reviews": pending_visual,
                "visual_unknown_coverage": unknown_visual,
                "visual_coverage_unknown_records": stats.get(
                    "visual_coverage_unknown_records", 0
                ),
                "findings_by_severity": stats["findings_by_severity"],
                "blocking_codes": sorted(
                    {
                        finding.code
                        for finding in high_findings
                        if finding.rule_id == rule.id
                    }
                ),
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
    visual_pending = summary.get("visual_pending_reviews", 0)
    visual_unknown = summary.get("visual_unknown_coverage", 0)
    visual_uncovered_findings = summary.get("visual_coverage_unknown_findings", 0)
    visual_unknown_total = visual_unknown + visual_uncovered_findings
    visual_steps = _visual_candidate_steps(result)

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
            "phase": "visual_confusables",
            "title": "人工核验跨键视觉混淆候选",
            "status": "blocked"
            if visual_unknown_total
            else "review"
            if visual_pending
            else "ready",
            "detail": (
                f"在 {summary['visual_candidate_groups']} 组二进制不同的目标键中发现"
                f"相同视觉骨架，涉及 {summary['visual_candidate_records']} 条记录；"
                f"另有 {visual_unknown} 组候选与 {visual_uncovered_findings} 条记录级"
                "检查含映射未覆盖字符或脚本，不能据此宣称无视觉风险。"
                "这些不是数据库唯一碰撞，工具不修改目标键、不改报为碰撞，也不自动合并。"
                if summary["visual_candidate_groups"] or visual_uncovered_findings
                else (
                    "未发现二进制不同却共享视觉骨架的候选键；"
                    "但该结论只在内置映射覆盖范围内成立，未覆盖字符仍按未知处理。"
                )
            ),
            "acceptance": (
                "每个视觉候选组均有具名复核结论（distinct_verified / "
                "merge_required / migration_blocked）并写入配置的 visual_reviews；"
                "映射未覆盖项必须保留为未知，不得给出“无视觉风险”证书；"
                "字节级唯一碰撞仍按 NORMALIZATION_COLLISION / DUPLICATE_KEY 独立处置。"
            ),
            "skeleton_version": summary["visual_confusable_map"]["skeleton_version"],
            "map_version": summary["visual_confusable_map"]["map_version"],
            "map_sha256": summary["visual_confusable_map"]["map_sha256"],
            "counts": {
                "candidate_groups": summary["visual_candidate_groups"],
                "candidate_records": summary["visual_candidate_records"],
                "pending_reviews": visual_pending,
                "unknown_coverage": visual_unknown,
                "coverage_unknown_records": visual_uncovered_findings,
            },
            "evidence": [
                "visual_confusables.json",
                "keys.jsonl",
                "ledger.sqlite",
                "report.html",
            ],
            "examples": visual_steps,
        },
        {
            "order": 6,
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
            "order": 7,
            "phase": "shadow",
            "title": "在影子库生成排序键并做旧新对比",
            "status": "pending" if any_blocking else "ready",
            "detail": (
                "本工具不执行任何 UPDATE/INSERT/DELETE。"
                "在独立影子环境按目标键重建索引，对旧排序与新排序做逐键抽样比对，"
                "记录排序迁移造成的顺序变化。视觉候选未复核前，不得宣称可直接迁移。"
            ),
            "acceptance": "影子库键总数与预检一致；唯一索引创建成功；抽样对比无未解释差异。",
        },
        {
            "order": 8,
            "phase": "cutover",
            "title": "按门禁复跑并放行切换",
            "status": "pending",
            "detail": (
                "使用同一配置复跑并启用 --fail-on high。"
                "只有碰撞组为 0、视觉候选待复核为 0、高等级发现为 0、"
                "输入哈希未变化时才允许切换。"
            ),
            "acceptance": (
                "复跑命令退出码为 0；manifest.json 校验通过；"
                "碰撞组 0；视觉候选待复核 0；所有必需键非空。"
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
            "visual_candidate_groups": summary["visual_candidate_groups"],
            "visual_pending_reviews": visual_pending,
            "visual_unknown_coverage": visual_unknown,
            "visual_coverage_unknown_records": visual_uncovered_findings,
            "passes": (
                high == 0
                and summary["collision_groups"] == 0
                and visual_pending == 0
                and visual_unknown_total == 0
            ),
        },
        "visual_confusables": {
            "skeleton_version": summary["visual_confusable_map"]["skeleton_version"],
            "map_version": summary["visual_confusable_map"]["map_version"],
            "map_sha256": summary["visual_confusable_map"]["map_sha256"],
            "unicode_version": summary["visual_confusable_map"]["unicode_version"],
            "candidate_groups": summary["visual_candidate_groups"],
            "candidate_records": summary["visual_candidate_records"],
            "pending_reviews": visual_pending,
            "unknown_coverage": visual_unknown,
            "coverage_unknown_records": visual_uncovered_findings,
            "separate_from_byte_collisions": True,
            "scope": {
                "rules_with_script_policy": summary["rules_with_script_policy"],
                "rules_without_script_policy": summary["rules_without_script_policy"],
                "note": (
                    "视觉预检只对声明了 script_policy 的键规则生效；"
                    "未声明的规则不计入视觉候选，也不代表其无视觉风险。"
                ),
            },
            "certificate": (
                "none"
                if visual_unknown_total
                else "within_map_coverage_only"
            ),
            "candidates": [
                {
                    "candidate_id": candidate.candidate_id,
                    "rule_id": candidate.rule_id,
                    "source_id": candidate.source_id,
                    "skeleton_escaped": candidate.skeleton_escaped,
                    "skeleton_sha256": candidate.skeleton_sha256,
                    "risk_level": candidate.risk_level,
                    "cross_script": candidate.cross_script,
                    "unknown_coverage": candidate.unknown_coverage,
                    "status": candidate.status,
                    "conclusion": candidate.conclusion,
                    "conclusion_source": (
                        "config.visual_reviews" if candidate.status == "reviewed" else None
                    ),
                    "reviewer": candidate.reviewer,
                    "policy_mode": candidate.policy_mode,
                    "record_refs": [
                        member["record_ref"] for member in candidate.members
                    ],
                    "record_ids": [
                        member["record_id"] for member in candidate.members
                    ],
                    "member_keys_escaped": [
                        member["target_key_escaped"] for member in candidate.members
                    ],
                    "skeleton_version": candidate.skeleton_version,
                    "map_version": candidate.map_version,
                }
                for candidate in result.visual_candidates[:50]
            ],
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
            "visual_candidate_groups": summary["visual_candidate_groups"],
            "visual_candidate_records": summary["visual_candidate_records"],
            "visual_pending_reviews": visual_pending,
            "visual_unknown_coverage": visual_unknown,
            "visual_coverage_unknown_records": visual_uncovered_findings,
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
        "rules": rules,
        "steps": steps,
        "forbidden_actions": [
            "不得由本工具自动合并、删除或改写碰撞记录",
            "不得自动“修复”疑似乱码而覆盖原值",
            "不得把校验失败的目标键直接写入生产唯一索引",
            "不得将源文件或 SQLite 台账当作可回写数据源",
            "不得把视觉混淆候选当作数据库唯一碰撞，或反之",
            "不得在映射未覆盖时给出“无视觉风险”证书",
            "不得在视觉复核未决前宣称两个二进制键可直接迁移",
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
