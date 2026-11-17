"""Deterministic migration-plan generation."""

from __future__ import annotations

from collections import Counter
from typing import Any, TYPE_CHECKING

from . import APP_NAME, APP_SLUG, UNICODE_VERSION, __version__
from .models import SEVERITIES

if TYPE_CHECKING:  # pragma: no cover
    from .models import ScanResult


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
            "phase": "cutover",
            "title": "按门禁复跑并放行切换",
            "status": "pending",
            "detail": (
                "使用同一配置复跑并启用 --fail-on high。"
                "只有碰撞组为 0、高等级发现为 0、输入哈希未变化时才允许切换。"
            ),
            "acceptance": (
                "复跑命令退出码为 0；manifest.json 校验通过；"
                "碰撞组 0；所有必需键非空。"
            ),
            "evidence": ["manifest.json", "report.html"],
        },
    ]

    plan = {
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
    if result.preflight is not None:
        plan["preflight"] = _preflight_plan(result)
        plan["preflight_gate"] = _preflight_gate(result)
    return plan


def _preflight_gate(result: "ScanResult") -> dict[str, Any]:
    preflight = result.preflight
    assert preflight is not None
    if preflight.stale:
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "预检清单已过期，不构成放行依据。",
        }
    if preflight.state in {"identity_invalid", "constraint_invalid"}:
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "关联身份或约束清单无效，不构成放行依据。",
        }
    if preflight.state == "no_feasible":
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "候选中没有满足全部硬约束的整组规则，不得放行。",
        }
    if preflight.budget_exhausted:
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "搜索预算耗尽，最优性 unknown，不得宣称最优或放行。",
        }
    if not preflight.evidence_verified:
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "逐记录键证据复算未通过，不得放行。",
        }
    if preflight.state != "optimal" or any(
        evaluation is None
        for evaluation in preflight.objective_results.values()
    ):
        return {
            "clears": False,
            "state": preflight.state,
            "reason": "两个业务目标未同时取得可证最优解，不得放行。",
        }
    return {
        "clears": True,
        "state": preflight.state,
        "reason": (
            "规则调整预检已穷尽候选，两个目标均有可证最优解，且关联/唯一/长度"
            "硬约束全部成立；仍须按计划在影子库复核后才能切换。"
        ),
    }


def _preflight_plan(result: "ScanResult") -> dict[str, Any]:
    preflight = result.preflight
    assert preflight is not None
    objectives: dict[str, Any] = {}
    recommended: dict[str, Any] = {}
    for objective, evaluation in preflight.objective_results.items():
        if evaluation is None:
            objectives[objective] = None
            continue
        objectives[objective] = {
            "status": evaluation.status,
            "exit_code": evaluation.exit_code,
            "provisional": evaluation.provisional,
            "exhaustive": evaluation.exhaustive,
            "changed_records": evaluation.changed_records,
            "total_bytes": evaluation.total_bytes,
            "selected_transforms": {
                rule_id: spec.as_dict()
                for rule_id, spec in evaluation.selected_transforms.items()
            },
            "combination_rank": evaluation.combination_rank,
            "checks": evaluation.checks,
            "proof": evaluation.proof,
        }
        recommended[objective] = evaluation

    # The "safest" recommendation is the fewest-changed-keys optimum: it is the
    # configuration that alters the fewest existing keys while satisfying all
    # relation constraints.
    primary = recommended.get("min_changed_records")
    return {
        "state": preflight.state,
        "stale": preflight.stale,
        "stale_reasons": preflight.stale_reasons,
        "notes": preflight.notes,
        "run_id": preflight.run_id,
        "config_sha256": preflight.config_sha256,
        "source_digest": preflight.source_digest,
        "rules_sha256": preflight.rules_sha256,
        "constraint_digest": preflight.constraint_digest,
        "evidence_verified": preflight.evidence_verified,
        "candidate_rule_ids": preflight.candidate_rule_ids,
        "candidate_order": preflight.candidate_order,
        "total_combinations": preflight.total_combinations,
        "examined_combinations": preflight.examined_combinations,
        "budget_exhausted": preflight.budget_exhausted,
        "objectives": objectives,
        "witness": preflight.witness,
        "recommended": {
            "objective": "min_changed_records",
            "status": (
                None if primary is None else primary.status
            ),
            "clearance": (
                "not_cleared"
                if primary is None
                or primary.provisional
                or primary.status != "optimal"
                else "advisory_only"
            ),
            "rules": (
                {}
                if primary is None
                else {
                    rule_id: spec.as_dict()
                    for rule_id, spec in primary.selected_transforms.items()
                }
            ),
            "changed_records": None if primary is None else primary.changed_records,
            "total_bytes": None if primary is None else primary.total_bytes,
            "keys": (
                []
                if primary is None
                else [item.as_dict() for item in primary.key_evidence]
            ),
        },
        "relation_summary": preflight.relation_summary,
        "gate": _preflight_gate(result),
        "forbidden_actions": [
            "预检只选择整条规则的 TransformSpec，不合并、删除记录或为单行指定替代键",
            "不得用另一个目标的唯一索引结果替代本目标的整组规则选择",
            "unknown / provisional 结果不得作为迁移放行结论",
        ],
    }