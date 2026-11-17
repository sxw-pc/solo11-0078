"""Deterministic Markdown and self-contained HTML review reports."""

from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any

from . import APP_NAME, APP_SLUG, APP_TAGLINE, UNICODE_VERSION, __version__
from .models import (
    CHECK_LABELS,
    SEVERITIES,
    SEVERITY_LABEL,
    VERDICT_LABEL,
    ScanResult,
)

_STATUS_LABEL = {
    "ready": "可继续",
    "review": "需复核",
    "blocked": "已阻断",
    "pending": "待执行",
    "done": "已完成",
    "no_records": "无记录",
}


def _preflight_state_label(state: str) -> str:
    return {
        "optimal": "可证最优",
        "provisional": "暂定 / 最优性 unknown",
        "unknown": "unknown",
        "no_feasible": "无可行组合",
        "stale": "清单过期",
        "identity_invalid": "身份无效",
        "constraint_invalid": "约束自相矛盾",
        "not_configured": "未启用",
    }.get(state, state)


def _preflight_rows(result: ScanResult) -> list[dict[str, Any]]:
    preflight = result.preflight
    if preflight is None:
        return []
    rows = []
    for objective, evaluation in preflight.objective_results.items():
        if evaluation is None:
            rows.append(
                {
                    "objective": objective,
                    "status": None,
                    "changed_records": None,
                    "total_bytes": None,
                    "provisional": None,
                    "selected": {},
                    "exit_code": None,
                    "checks": {},
                    "proof": {},
                }
            )
            continue
        rows.append(
            {
                "objective": objective,
                "status": evaluation.status,
                "changed_records": evaluation.changed_records,
                "total_bytes": evaluation.total_bytes,
                "provisional": evaluation.provisional,
                "selected": evaluation.selected_transforms,
                "exit_code": evaluation.exit_code,
                "checks": evaluation.checks,
                "proof": evaluation.proof,
            }
        )
    return rows


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|")


def _md_code(value: Any) -> str:
    text = str(value if value is not None else "")
    fence = "``" if "`" in text else "`"
    if "`" in text:
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def _clip(value: Any, limit: int = 4000) -> str:
    text = str(value if value is not None else "")
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…（页面截断，共 {len(text)} 字符；完整内容见 JSON / 台账）"


def _json_text(value: Any, *, indent: int = 2, limit: int = 4000) -> str:
    return _clip(
        json.dumps(value, ensure_ascii=False, indent=indent, sort_keys=True, default=str),
        limit,
    )


def _severity_badge(severity: str) -> str:
    return (
        f'<span class="badge sev-{_e(severity)}">'
        f"{_e(SEVERITY_LABEL.get(severity, severity))}</span>"
    )


def _status_badge(status: str) -> str:
    return (
        f'<span class="status status-{_e(status)}">'
        f"{_e(_STATUS_LABEL.get(status, status))}</span>"
    )


def render_markdown(result: ScanResult) -> str:
    summary = result.summary
    plan = result.plan
    sev = summary["findings_by_severity"]
    lines: list[str] = [
        f"# {APP_NAME} · 迁移预检报告",
        "",
        f"> {result.config.project.name}  ",
        f"> 目标：{result.config.project.target}  ",
        f"> 运行：`{result.run_id}`  ·  结论：**{VERDICT_LABEL.get(result.verdict, result.verdict)}**",
        "",
        "本报告由完全离线的本地预检工具生成。工具不写回源文件，不执行数据库迁移，"
        "不访问网络；所有计数均来自本次输入快照。",
        "",
        "## 运行摘要",
        "",
        f"- 生成时间（UTC）：`{result.generated_at}`",
        f"- 工具版本：`{__version__}` · Unicode 数据：`{UNICODE_VERSION}`",
        f"- 配置 SHA-256：`{result.config.config_sha256}`",
        f"- 源：{summary['source_count']} 个 · 记录：{summary['record_count']} 条 · "
        f"目标键：{summary['keys_evaluated']} 个",
        f"- 高 / 中 / 低风险：**{sev.get('high', 0)} / {sev.get('medium', 0)} / {sev.get('low', 0)}**",
        f"- 归一化唯一键碰撞组：**{summary['collision_groups']}**，"
        f"涉及 **{summary['collision_records']}** 条记录",
        f"- 超限键：**{summary['overlength_keys']}** · 变换后键值变化：**{summary['changed_keys']}**",
        "",
        "## 源文件指纹",
        "",
        "| 源 | 类型 | 路径 | 记录 | 编码 | SHA-256 |",
        "|---|---|---|---:|---|---|",
    ]
    for source in summary["sources"]:
        lines.append(
            f"| {_md(source['source_id'])} | {_md(source['kind'])} | "
            f"{_md_code(source['path'])} | {source['records']} | "
            f"{_md(source['encoding'])} | {_md_code(source['sha256'][:20] + '…')} |"
        )

    lines.extend(
        [
            "",
            "## 目标键规则",
            "",
            "| 规则 | 源 / 列 | 目标 | 变换 | 唯一 | 记录 | 碰撞组 | 超限 | 状态 |",
            "|---|---|---|---|---|---:|---:|---:|---|",
        ]
    )
    plan_rules = {rule["rule_id"]: rule for rule in plan["rules"]}
    for rule in result.config.keys:
        stats = next(item for item in summary["rules"] if item["rule_id"] == rule.id)
        plan_rule = plan_rules[rule.id]
        columns = " + ".join(rule.columns)
        lines.append(
            f"| {_md(rule.id)} | {_md(rule.source_id)} / {_md_code(columns)} | "
            f"{_md_code(rule.destination or '—')} | {_md(rule.transform.describe())} | "
            f"{'是' if rule.unique else '否'} | {stats['records']} | "
            f"{stats['collision_groups']} | {stats['overlength']} | "
            f"{_md(_STATUS_LABEL.get(plan_rule['status'], plan_rule['status']))} |"
        )

    lines.extend(["", "## 唯一键碰撞组", ""])
    if not result.collisions:
        lines.append("未发现唯一键碰撞组。")
    else:
        for group in result.collisions[:100]:
            lines.append(
                f"### `{group.group_id}` · `{group.rule_id}`"
            )
            lines.append("")
            lines.append(
                f"- 目标键：{_md_code(group.target_key_escaped)}  "
                f"\n- 类型：`{group.reason_code}` · 记录数：{len(group.participants)} · "
                f"原始变体：{len(group.raw_variants)}"
            )
            lines.append("")
            lines.append("| 记录引用 | 记录标识 | 原始值 |")
            lines.append("|---|---|---|")
            for participant in group.participants:
                lines.append(
                    f"| {_md(participant.record_ref)} | "
                    f"{_md(participant.record_id or '∅')} | "
                    f"{_md_code(participant.raw_display)} |"
                )
            lines.append("")
        if len(result.collisions) > 100:
            lines.append(
                f"> 页面仅展示前 100 组，其余 {len(result.collisions) - 100} 组见 `collisions.json` 与台账。"
            )

    lines.extend(["", "## 风险清单", ""])
    if not result.findings:
        lines.append("未发现风险项。")
    else:
        lines.extend(
            [
                "| 级别 | 检查 | 源 / 规则 | 记录 | 说明 |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in result.findings[: result.config.max_report_rows]:
            location = " / ".join(
                item
                for item in [
                    finding.source_id or "",
                    finding.rule_id or "",
                    finding.record_ref or "",
                ]
                if item
            )
            lines.append(
                f"| {SEVERITY_LABEL.get(finding.severity, finding.severity)} | "
                f"{_md(finding.code)}<br>{_md(CHECK_LABELS.get(finding.code, ''))} | "
                f"{_md(location)} | {_md(finding.record_id or '—')} | "
                f"{_md(finding.message)} |"
            )
        omitted = len(result.findings) - min(
            len(result.findings), result.config.max_report_rows
        )
        if omitted > 0:
            lines.append(
                f"\n> 页面仅展示前 {result.config.max_report_rows} 项，"
                f"另有 {omitted} 项见 `findings.json` 与台账。"
            )

    lines.extend(["", "## 迁移计划", ""])
    for step in plan["steps"]:
        lines.append(
            f"### {step['order']}. {step['title']}  "
            f"`{_STATUS_LABEL.get(step['status'], step['status'])}`"
        )
        lines.append("")
        lines.append(step["detail"])
        lines.append("")
        lines.append(f"**验收条件：** {step['acceptance']}")
        lines.append("")

    lines.extend(_render_preflight_markdown(result))
    lines.extend(
        [
            "## 复现与边界",
            "",
            f"- 运行 ID 由配置、工具版本、Unicode 数据与所有源文件哈希派生：`{result.run_id}`。",
            "- 计划文件不写墙钟时间；同一配置与输入会生成相同计划内容。",
            "- 本工具只读源文件；运行时无网络请求；仅生成本地报告与 SQLite 审计台账。",
            "- 台账与报告包含原始值，仅适合在受控本地环境处理合成或已授权数据。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_preflight_markdown(result: ScanResult) -> list[str]:
    preflight = result.preflight
    if preflight is None:
        return []
    lines: list[str] = [
        "",
        "## 规则调整预检（关联保全）",
        "",
        f"- 状态：**{_preflight_state_label(preflight.state)}**",
        f"- 配置 SHA-256：`{preflight.config_sha256}`",
        f"- 源摘要：`{preflight.source_digest}`",
        f"- 规则摘要：`{preflight.rules_sha256}`",
        f"- 约束摘要：`{preflight.constraint_digest}`",
        f"- 清单过期：**{'是' if preflight.stale else '否'}**",
        f"- 候选组合：已检查 **{preflight.examined_combinations}** / 共 **{preflight.total_combinations}**；"
        f"预算耗尽：**{'是' if preflight.budget_exhausted else '否'}**",
        f"- 证据复算：**{'通过' if preflight.evidence_verified else '失败'}**",
    ]
    if preflight.stale_reasons:
        lines.append("- 过期原因：")
        lines.extend(f"  - {_md(reason)}" for reason in preflight.stale_reasons)
    for note in preflight.notes:
        lines.append(f"- {_md(note)}")
    lines.append("")
    if not preflight.stale and preflight.state not in {
        "identity_invalid",
        "constraint_invalid",
    }:
        lines.extend(
            [
                "| 目标 | 状态 | 改变键数 | 总字节 | 可证最优 | 导出码 | 选中规则 |",
                "|---|---|---:|---:|---|---:|---|",
            ]
        )
        for row in _preflight_rows(result):
            if row["status"] is None:
                lines.append(
                    f"| {_md(row['objective'])} | 无可行组合 | — | — | — | — | — |"
                )
                continue
            selected = ", ".join(
                f"{rule_id}={spec.case}" for rule_id, spec in row["selected"].items()
            )
            lines.append(
                f"| {_md(row['objective'])} | {_md(row['status'])} | "
                f"{row['changed_records']} | {row['total_bytes']} | "
                f"{'是' if not row['provisional'] else '**unknown**'} | "
                f"{row['exit_code']} | {_md_code(selected or '—')} |"
            )
        lines.append("")
        lines.append("### 逐记录旧新键（主推荐：最少改变键）")
        lines.append("")
        primary = preflight.objective_results.get("min_changed_records")
        if primary is None:
            lines.append("无已验证的主推荐配置。")
        else:
            lines.extend(
                [
                    "| 规则 | 记录 | 旧键 | 新键 | 旧字节 | 新字节 | 变更 | 选中变换 |",
                    "|---|---|---|---|---:|---:|---|---|",
                ]
            )
            for item in primary.key_evidence:
                lines.append(
                    f"| {_md(item.rule_id)} | {_md(item.record_ref)} | "
                    f"{_md_code(item.old_key if item.old_key is not None else '∅')} | "
                    f"{_md_code(item.new_key if item.new_key is not None else '∅')} | "
                    f"{item.old_bytes} | {item.new_bytes} | "
                    f"{'是' if item.changed else '否'} | "
                    f"{_md(item.transform.describe())} |"
                )
            relations = primary.checks.get("relations", {})
            lines.append("")
            lines.append(
                "- 已授权关联全等：**{}**；禁止同键对全部避开：**{}**；"
                "未授权跨表同键拦截：**{}**".format(
                    "是" if relations.get("authorized_links_satisfied") else "否",
                    "是" if relations.get("forbidden_pairs_clear") else "否",
                    "开启"
                    if relations.get("forbid_unauthorized_cross_table")
                    else "关闭",
                )
            )
            lines.append(
                f"- 最优性证明：`{primary.proof.get('optimality', 'unknown')}`；"
                f"已检查组合 {primary.proof.get('examined_combinations')} / "
                f"{primary.proof.get('total_combinations')}；"
                f"平局规则 `{primary.proof.get('tie_break')}`。"
            )
    if preflight.witness:
        lines.extend(["", "### 冲突见证", ""])
        categories = preflight.witness.get("categories", {})
        for code, item in sorted(categories.items()):
            lines.append(
                f"- `{_md(code)}`：{_md(item.get('message', ''))} "
                f"（组合序号 {item.get('combination_rank')}）"
            )
        if preflight.witness.get("note"):
            lines.append(f"- 说明：{_md(preflight.witness['note'])}")
    lines.append("")
    return lines


def _render_preflight_plan_markdown(preflight_plan: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## 规则调整预检",
        "",
        f"- 状态：**{_preflight_state_label(preflight_plan.get('state', ''))}**",
        f"- 配置 SHA-256：`{preflight_plan.get('config_sha256')}`",
        f"- 源摘要：`{preflight_plan.get('source_digest')}`",
        f"- 约束摘要：`{preflight_plan.get('constraint_digest')}`",
        f"- 组合：`{preflight_plan.get('examined_combinations')}` / "
        f"`{preflight_plan.get('total_combinations')}`",
        "",
        "| 目标 | 状态 | 改变键数 | 总字节 | 选中变换 | 最优性 |",
        "|---|---|---:|---:|---|---|",
    ]
    for objective, item in preflight_plan.get("objectives", {}).items():
        if item is None:
            lines.append(f"| {_md(objective)} | 无 | — | — | — | — |")
            continue
        selected = ", ".join(
            f"{rule_id}={spec.get('case')}"
            for rule_id, spec in item.get("selected_transforms", {}).items()
        )
        lines.append(
            f"| {_md(objective)} | {_md(item.get('status'))} | "
            f"{item.get('changed_records')} | {item.get('total_bytes')} | "
            f"{_md_code(selected or '—')} | "
            f"{_md(item.get('proof', {}).get('optimality'))} |"
        )
    recommended = preflight_plan.get("recommended", {})
    gate = preflight_plan.get("gate", {})
    lines.extend(
        [
            "",
            f"- 推荐配置（最少改变键）：`{recommended.get('status')}`；"
            f"放行口径：`{recommended.get('clearance')}`",
            "- 预检只选择整条规则变换；正式规则的 scan 结论仍单独保留。",
        ]
    )
    if gate:
        lines.append(
            f"- 预检门禁：**{'通过' if gate.get('clears') else '未通过'}** — "
            f"{_md(gate.get('reason', ''))}"
        )
    for note in preflight_plan.get("notes", []):
        lines.append(f"- {_md(note)}")
    lines.append("")
    return lines


def _render_preflight_html(result: ScanResult) -> str:
    preflight = result.preflight
    if preflight is None:
        return ""
    state_label = _preflight_state_label(preflight.state)
    summary_rows = "\n".join(
        f"""
        <tr>
          <td class="mono">{_e(row['objective'])}</td>
          <td><span class="status status-{'ready' if row['status'] == 'optimal' else 'review'}">{_e(row['status'] or '—')}</span></td>
          <td class="num">{'' if row['changed_records'] is None else row['changed_records']}</td>
          <td class="num">{'' if row['total_bytes'] is None else row['total_bytes']}</td>
          <td>{_e('是' if row['provisional'] is False else ('unknown' if row['provisional'] else '—'))}</td>
          <td class="mono small">{_e(', '.join(f'{rule_id}={spec.case}' for rule_id, spec in row['selected'].items()) or '—')}</td>
        </tr>"""
        for row in _preflight_rows(result)
    )
    key_rows = []
    primary = preflight.objective_results.get("min_changed_records")
    if primary is not None:
        for item in primary.key_evidence[:500]:
            key_rows.append(
                f"""
        <tr>
          <td class="mono">{_e(item.rule_id)}</td>
          <td class="mono">{_e(item.record_ref)}</td>
          <td class="mono value-cell">{_e(item.old_key if item.old_key is not None else '∅')}</td>
          <td class="mono value-cell">{_e(item.new_key if item.new_key is not None else '∅')}</td>
          <td class="num">{item.old_bytes}</td>
          <td class="num">{item.new_bytes}</td>
          <td>{_e('是' if item.changed else '否')}</td>
        </tr>"""
            )
    if not key_rows:
        key_rows.append(
            '<tr><td colspan="7" class="muted">没有可展示的已验证逐键证据。</td></tr>'
        )
    witness_html = ""
    if preflight.witness:
        items = "".join(
            f"<li><code>{_e(code)}</code>：{_e(item.get('message', ''))}</li>"
            for code, item in sorted(preflight.witness.get("categories", {}).items())
        )
        note = _e(preflight.witness.get("note", ""))
        witness_html = f'<div class="panel"><h3>冲突见证</h3><ul>{items}</ul><p class="note">{note}</p></div>'
    notes_html = "".join(f"<li>{_e(note)}</li>" for note in preflight.notes)
    return f"""
  <section class="section" id="preflight">
    <div class="section-head"><h2>规则调整预检 · 关联保全</h2><p>整组规则选择，非逐行改键</p></div>
    <div class="panel">
      <p class="note">
        状态：<strong>{_e(state_label)}</strong> · 清单过期：
        <strong>{'是' if preflight.stale else '否'}</strong> · 证据复算：
        <strong>{'通过' if preflight.evidence_verified else '失败'}</strong> ·
        组合 {preflight.examined_combinations} / {preflight.total_combinations}
        · 预算耗尽：<strong>{'是' if preflight.budget_exhausted else '否'}</strong>
      </p>
      <div class="run-meta">
        <span>配置 <code>{_e(preflight.config_sha256[:20])}…</code></span>
        <span>源摘要 <code>{_e(preflight.source_digest[:20])}…</code></span>
        <span>约束摘要 <code>{_e(preflight.constraint_digest[:20])}…</code></span>
      </div>
      <ul class="note">{notes_html}</ul>
      <div class="table-scroll" style="margin-top:12px">
        <table>
          <thead><tr><th>目标</th><th>状态</th><th>改变键数</th><th>总字节</th><th>可证最优</th><th>选中规则</th></tr></thead>
          <tbody>{summary_rows}</tbody>
        </table>
      </div>
    </div>
    <div class="panel" style="margin-top:14px">
      <h3>逐记录旧新键（主推荐：最少改变键）</h3>
      <div class="table-scroll">
        <table>
          <thead><tr><th>规则</th><th>记录</th><th>旧键</th><th>新键</th><th>旧字节</th><th>新字节</th><th>变更</th></tr></thead>
          <tbody>{''.join(key_rows)}</tbody>
        </table>
      </div>
      <p class="note">完整证据见 <code>preflight.json</code>、<code>preflight-keys.jsonl</code> 与台账 preflight_* 表。正式规则的 scan 结论仍单独保留。</p>
    </div>
    {witness_html}
  </section>
"""


def render_plan_markdown(result: ScanResult) -> str:
    plan = result.plan
    lines: list[str] = [
        f"# {APP_NAME} · 迁移计划",
        "",
        f"**项目：** {result.config.project.name}  ",
        f"**目标：** {result.config.project.target}  ",
        f"**运行：** `{result.run_id}`  ",
        f"**结论：** {VERDICT_LABEL.get(result.verdict, result.verdict)}",
        "",
        "> 本计划由输入内容派生，不含墙钟时间。工具本身不执行任何数据库写操作，"
        "也不自动改写业务数据。",
        "",
        "## 放行门禁",
        "",
        f"- 门禁等级：`{plan['gate']['fail_on']}`",
        f"- 当前阻断发现：**{plan['gate']['blocking_findings']}**",
        f"- 当前碰撞组：**{plan['gate']['collision_groups']}**",
        f"- 自动门禁结果：**{'通过' if plan['gate']['passes'] else '未通过'}**",
        "",
        "复跑命令模板：",
        "",
        "```bash",
        plan["reproduce"]["command_template"],
        "```",
        "",
        "## 源文件指纹",
        "",
        "| 源 | 类型 | 路径 | 记录 | SHA-256 | 状态 |",
        "|---|---|---|---:|---|---|",
    ]
    for source in plan["source_fingerprints"]:
        lines.append(
            f"| {_md(source['source_id'])} | {_md(source['kind'])} | "
            f"{_md_code(source['path'])} | {source['records']} | "
            f"{_md_code(source['sha256'])} | "
            f"{_md(_STATUS_LABEL.get(source['status'], source['status']))} |"
        )
    lines.extend(
        [
            "",
            "## 规则就绪度",
            "",
            "| 规则 | 源 / 列 | 目标 | 状态 | 记录 | 键变化 | 碰撞组 | 超限 | 阻断检查 |",
            "|---|---|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for rule in plan["rules"]:
        lines.append(
            f"| {_md(rule['rule_id'])} | {_md(rule['source_id'])} / "
            f"{_md_code(' + '.join(rule['columns']))} | "
            f"{_md_code(rule['destination'] or '—')} | "
            f"{_md(_STATUS_LABEL.get(rule['status'], rule['status']))} | "
            f"{rule['records']} | {rule['changed_keys']} | "
            f"{rule['collision_groups']} | {rule['overlength']} | "
            f"{_md(', '.join(rule['blocking_codes']) or '—')} |"
        )
    lines.extend(["", "## 执行步骤", ""])
    for step in plan["steps"]:
        lines.extend(
            [
                f"### {step['order']}. {step['title']}",
                "",
                f"**状态：** {_STATUS_LABEL.get(step['status'], step['status'])}",
                "",
                step["detail"],
                "",
                f"**验收：** {step['acceptance']}",
                "",
            ]
        )
    preflight_plan = plan.get("preflight")
    if preflight_plan:
        lines.extend(_render_preflight_plan_markdown(preflight_plan))
    if plan.get("steps"):
        examples = plan["steps"][3].get("examples", [])
        if examples:
            lines.extend(
                [
                    "## 待裁决碰撞示例（最多 20 组）",
                    "",
                    "| 组 | 规则 | 目标键 | 记录 |",
                    "|---|---|---|---|",
                ]
            )
            for example in examples:
                lines.append(
                    f"| {_md(example['group_id'])} | {_md(example['rule_id'])} | "
                    f"{_md_code(example['target_key_escaped'])} | "
                    f"{_md(', '.join(str(item) for item in example['record_ids'] if item is not None) or '—')} |"
                )
            lines.append("")
    lines.extend(
        [
            "## 禁止动作",
            "",
            *[f"- {item}" for item in plan["forbidden_actions"]],
            "",
        ]
    )
    return "\n".join(lines)


def render_html(result: ScanResult) -> str:
    summary = result.summary
    plan = result.plan
    sev = summary["findings_by_severity"]
    verdict = result.verdict
    plan_rules = {rule["rule_id"]: rule for rule in plan["rules"]}
    rule_stats = {item["rule_id"]: item for item in summary["rules"]}
    max_rows = result.config.max_report_rows
    shown_findings = result.findings[:max_rows]

    source_rows = "\n".join(
        f"""
        <tr>
          <td><span class="mono strong">{_e(source['source_id'])}</span><br><span class="muted">{_e(source['kind'].upper())}</span></td>
          <td><span class="mono path">{_e(source['path'])}</span></td>
          <td class="num">{source['records']:,}</td>
          <td class="num">{source['key_results']:,}</td>
          <td>{_status_badge('blocked' if source['findings_by_severity'].get('high', 0) else 'review' if source['findings_by_severity'].get('medium', 0) else 'ready')}</td>
          <td class="mono hash" title="{_e(source['sha256'])}">{_e(source['sha256'][:16])}…</td>
        </tr>"""
        for source in summary["sources"]
    )

    rule_rows = []
    for rule in result.config.keys:
        stats = rule_stats[rule.id]
        plan_rule = plan_rules[rule.id]
        columns = " + ".join(rule.columns)
        limit_parts = []
        if rule.max_bytes is not None:
            limit_parts.append(f"{rule.max_bytes} B")
        if rule.max_chars is not None:
            limit_parts.append(f"{rule.max_chars} 字符")
        rule_rows.append(
            f"""
        <tr>
          <td>
            <span class="mono strong">{_e(rule.id)}</span>
            <div class="muted">{_e(rule.label)}</div>
          </td>
          <td><span class="mono">{_e(rule.source_id)}</span><br><span class="mono subtle">{_e(columns)}</span></td>
          <td><span class="mono small">{_e(rule.destination or '—')}</span></td>
          <td>{_e(rule.transform.describe())}</td>
          <td class="num">{stats['records']:,}</td>
          <td class="num">{stats['collision_groups']:,}</td>
          <td class="num">{stats['overlength']:,}</td>
          <td><span class="tiny-label">{'唯一' if rule.unique else '非唯一'}</span> / <span class="tiny-label">{'必填' if rule.required else '可空'}</span><br><span class="muted small">{_e(' / '.join(limit_parts) if limit_parts else '未声明长度上限')}</span></td>
          <td>{_status_badge(plan_rule['status'])}</td>
        </tr>"""
        )

    collision_cards = []
    collision_cap = 100
    for group in result.collisions[:collision_cap]:
        member_rows = "\n".join(
            f"""
              <tr>
                <td class="mono">{_e(participant.record_ref)}</td>
                <td class="mono">{_e(participant.record_id or '∅')}</td>
                <td class="mono value-cell">{_e(participant.raw_display)}</td>
              </tr>"""
            for participant in group.participants[:50]
        )
        more = ""
        if len(group.participants) > 50:
            more = (
                f'<p class="note">该组仅展示前 50 条；完整成员见 '
                f"<code>collisions.json</code>。</p>"
            )
        collision_cards.append(
            f"""
        <article class="collision-card">
          <header>
            <div>
              <div class="eyebrow small">{_e(group.reason_code)}</div>
              <h3><span class="mono">{_e(group.group_id)}</span> <span class="muted">·</span> {_e(group.rule_id)}</h3>
            </div>
            <span class="count-chip">{len(group.participants)} 条</span>
          </header>
          <div class="collision-key">
            <span class="tiny-label">目标键</span>
            <code>{_e(group.target_key_escaped)}</code>
          </div>
          <div class="muted small">
            源 {_e(group.source_id)} · 原始变体 {len(group.raw_variants)} 种 · 目标键 SHA-256 {_e((group.participants[0].key_sha256 or '')[:20])}…
          </div>
          <div class="table-scroll compact">
            <table>
              <thead><tr><th>记录引用</th><th>记录标识</th><th>原始值</th></tr></thead>
              <tbody>{member_rows}</tbody>
            </table>
          </div>
          {more}
        </article>"""
        )
    if not collision_cards:
        collision_cards.append(
            '<div class="empty-state"><strong>没有唯一键碰撞组</strong>'
            "<span>归一化后每个唯一候选键都保持单记录映射。</span></div>"
        )
    collision_more = ""
    if len(result.collisions) > collision_cap:
        collision_more = (
            f'<p class="note">页面仅展示前 {collision_cap} 组；'
            f"其余 {len(result.collisions) - collision_cap} 组见 "
            f"<code>collisions.json</code> 与 SQLite 台账。</p>"
        )

    preflight_section = _render_preflight_html(result)

    severity_options = "\n".join(
        f'<option value="{_e(severity)}">{_e(SEVERITY_LABEL[severity])}</option>'
        for severity in SEVERITIES
    )
    code_counts = Counter(finding.code for finding in result.findings)
    code_options = "\n".join(
        f'<option value="{_e(code)}">{_e(CHECK_LABELS.get(code, code))} ({count})</option>'
        for code, count in sorted(
            code_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )
    source_options = "\n".join(
        f'<option value="{_e(source["source_id"])}">{_e(source["source_id"])}</option>'
        for source in summary["sources"]
    )
    rule_options = "\n".join(
        f'<option value="{_e(rule.id)}">{_e(rule.id)}</option>'
        for rule in result.config.keys
    )

    finding_rows = []
    for finding in shown_findings:
        location_bits = []
        if finding.source_id:
            location_bits.append(finding.source_id)
        if finding.rule_id:
            location_bits.append(finding.rule_id)
        if finding.record_ref:
            location_bits.append(finding.record_ref)
        location = " / ".join(location_bits)
        search_text = " ".join(
            [
                finding.code,
                CHECK_LABELS.get(finding.code, ""),
                finding.message,
                finding.source_id or "",
                finding.rule_id or "",
                finding.record_ref or "",
                finding.record_id or "",
                finding.column or "",
            ]
        )
        finding_rows.append(
            f"""
          <tr class="finding-row"
              data-severity="{_e(finding.severity)}"
              data-code="{_e(finding.code)}"
              data-source="{_e(finding.source_id or '')}"
              data-rule="{_e(finding.rule_id or '')}"
              data-search="{_e(search_text.lower())}">
            <td>{_severity_badge(finding.severity)}</td>
            <td>
              <span class="mono strong">{_e(finding.code)}</span>
              <div class="muted small">{_e(CHECK_LABELS.get(finding.code, ''))}</div>
            </td>
            <td>
              <span class="mono small">{_e(location or '—')}</span>
              <div class="muted small">记录：{_e(finding.record_id or '—')}{(' · 列 ' + _e(finding.column)) if finding.column else ''}</div>
            </td>
            <td class="message-cell">{_e(finding.message)}</td>
            <td>
              <details>
                <summary>证据</summary>
                <pre>{_e(_json_text(finding.details))}</pre>
              </details>
            </td>
          </tr>"""
        )
    if not finding_rows:
        finding_rows.append(
            '<tr><td colspan="5"><div class="empty-state"><strong>没有风险项</strong>'
            "<span>本次预检在已声明规则下未发现异常。</span></div></td></tr>"
        )
    omitted_findings = len(result.findings) - len(shown_findings)

    step_cards = "\n".join(
        f"""
        <li class="plan-step">
          <div class="step-index">{step['order']:02d}</div>
          <div class="step-body">
            <div class="step-head">
              <h3>{_e(step['title'])}</h3>
              {_status_badge(step['status'])}
            </div>
            <p>{_e(step['detail'])}</p>
            <p class="acceptance"><strong>验收</strong> {_e(step['acceptance'])}</p>
            {('<p class="tiny-label">检查码：' + _e(', '.join(step.get('blocking_codes', {}).keys())) + '</p>') if step.get('blocking_codes') else ''}
          </div>
        </li>"""
        for step in plan["steps"]
    )

    config = result.config
    high_findings = sev.get("high", 0)
    verdict_detail = {
        "blocked": "存在高等级发现。请先完成源数据或规则处置，再创建目标唯一索引。",
        "review": "没有高等级发现，但仍有需要业务确认的中等级问题。",
        "pass_with_notes": "预检通过，仅有低等级提醒。",
        "pass": "未发现风险，可进入影子库排序验证。",
    }.get(verdict, "")
    severity_tiles = "".join(
        f"""<div class="severity-tile sev-{severity}">
              <span>{_e(SEVERITY_LABEL[severity])}</span>
              <strong>{sev.get(severity, 0):,}</strong>
            </div>"""
        for severity in SEVERITIES
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_e(APP_NAME)} · {_e(config.project.name)} · 迁移预检</title>
<style>
:root {{
  --ink: #18231f;
  --ink-soft: #40534b;
  --paper: #f6f3ec;
  --panel: #fffdf8;
  --line: #d9d3c6;
  --teal: #0e685e;
  --teal-deep: #0b302d;
  --teal-soft: #dcece6;
  --amber: #a76512;
  --amber-soft: #f8ead3;
  --red: #a63a2b;
  --red-soft: #f8dfda;
  --green: #2e6c42;
  --green-soft: #dfeee2;
  --slate: #59665f;
  --shadow: 0 18px 50px rgba(24, 35, 31, .08);
  --radius: 18px;
  --sans: "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  --mono: "Cascadia Code", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  background:
    radial-gradient(circle at 15% 0%, rgba(14, 104, 94, .12), transparent 32rem),
    linear-gradient(115deg, rgba(217, 211, 198, .25) 1px, transparent 1px),
    var(--paper);
  background-size: auto, 28px 28px, auto;
  color: var(--ink);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.65;
}}
a {{ color: var(--teal); }}
code, .mono {{ font-family: var(--mono); }}
.hero {{
  position: relative;
  overflow: hidden;
  padding: 48px clamp(20px, 5vw, 76px) 56px;
  color: #f5f1e7;
  background:
    radial-gradient(circle at 88% 20%, rgba(124, 205, 183, .22), transparent 24rem),
    linear-gradient(135deg, #0a2a27 0%, #103c37 58%, #0b302d 100%);
}}
.hero::after {{
  content: "";
  position: absolute;
  inset: 0;
  opacity: .12;
  pointer-events: none;
  background-image: repeating-linear-gradient(0deg, transparent 0 31px, #f5f1e7 31px 32px);
}}
.hero > * {{ position: relative; z-index: 1; max-width: 1320px; margin-left: auto; margin-right: auto; }}
.eyebrow {{
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: .18em;
  text-transform: uppercase;
  color: #8ec9b9;
}}
.hero h1 {{
  margin: 14px 0 12px;
  font-size: clamp(32px, 5vw, 62px);
  line-height: 1.08;
  letter-spacing: -.035em;
  font-weight: 650;
}}
.hero h1 span {{ color: #9ed5c5; }}
.hero p {{ max-width: 760px; color: #d5e4de; font-size: 16px; }}
.hero-tags {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 26px; }}
.hero-tag {{
  border: 1px solid rgba(222, 242, 235, .28);
  background: rgba(255,255,255,.06);
  border-radius: 999px;
  padding: 6px 12px;
  font-family: var(--mono);
  font-size: 11px;
  color: #e5f0ec;
}}
main {{ max-width: 1320px; margin: 0 auto; padding: 0 clamp(16px, 4vw, 48px) 72px; }}
.section {{ margin-top: 42px; }}
.section-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 18px; margin-bottom: 14px; }}
.section-head h2 {{ margin: 0; font-size: clamp(22px, 2.6vw, 31px); letter-spacing: -.025em; }}
.section-head p {{ margin: 0; color: var(--ink-soft); }}
.verdict {{
  margin-top: -28px;
  position: relative;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: clamp(20px, 3.5vw, 34px);
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) minmax(280px, .7fr);
  gap: 26px;
  align-items: center;
}}
.verdict::before {{
  content: "";
  position: absolute;
  left: 0; top: 20px; bottom: 20px;
  width: 5px; border-radius: 0 5px 5px 0;
  background: var(--red);
}}
.verdict[data-verdict="review"]::before {{ background: var(--amber); }}
.verdict[data-verdict="pass_with_notes"]::before,
.verdict[data-verdict="pass"]::before {{ background: var(--green); }}
.verdict-label {{ color: var(--red); font-weight: 700; margin: 0 0 6px; letter-spacing: .02em; }}
.verdict[data-verdict="review"] .verdict-label {{ color: var(--amber); }}
.verdict[data-verdict="pass_with_notes"] .verdict-label,
.verdict[data-verdict="pass"] .verdict-label {{ color: var(--green); }}
.verdict h2 {{ margin: 0 0 8px; font-size: clamp(24px, 3.2vw, 39px); line-height: 1.15; }}
.verdict p {{ margin: 0; color: var(--ink-soft); max-width: 720px; }}
.severity-tiles {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 9px; }}
.severity-tile {{ border-radius: 12px; padding: 13px 14px; display: flex; flex-direction: column; gap: 2px; }}
.severity-tile span {{ font-size: 12px; color: var(--ink-soft); }}
.severity-tile strong {{ font-family: var(--mono); font-size: 26px; line-height: 1.2; }}
.sev-high.severity-tile {{ background: var(--red-soft); }} .sev-high.severity-tile strong {{ color: var(--red); }}
.sev-medium.severity-tile {{ background: var(--amber-soft); }} .sev-medium.severity-tile strong {{ color: var(--amber); }}
.sev-low.severity-tile {{ background: var(--teal-soft); }} .sev-low.severity-tile strong {{ color: var(--teal); }}
.metrics {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }}
.metric {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px; }}
.metric span {{ display: block; color: var(--ink-soft); font-size: 12px; }}
.metric strong {{ display: block; font-family: var(--mono); font-size: 29px; letter-spacing: -.04em; margin-top: 4px; }}
.metric small {{ color: var(--slate); }}
.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: 0 8px 28px rgba(24,35,31,.045); padding: 22px; }}
.table-scroll {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
th {{ text-align: left; font-size: 11px; letter-spacing: .07em; text-transform: uppercase; color: var(--slate); background: #f1ede4; padding: 10px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }}
td {{ padding: 12px; border-bottom: 1px solid #e8e3d8; vertical-align: top; }}
tr:last-child td {{ border-bottom: 0; }}
tbody tr:hover {{ background: #faf7f0; }}
.num {{ font-family: var(--mono); text-align: right; white-space: nowrap; }}
.mono {{ font-family: var(--mono); }}
.strong {{ font-weight: 650; }}
.small {{ font-size: 12px; }}
.shy, .subtle {{ color: var(--slate); }}
.muted {{ color: var(--slate); }}
.path {{ word-break: break-all; }}
.hash {{ color: var(--slate); font-size: 11px; white-space: nowrap; }}
.badge {{ display: inline-block; border-radius: 999px; padding: 3px 9px; font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap; }}
.sev-high {{ background: var(--red-soft); color: var(--red); }}
.sev-medium {{ background: var(--amber-soft); color: var(--amber); }}
.sev-low {{ background: var(--teal-soft); color: var(--teal); }}
.status {{ display: inline-block; border: 1px solid currentColor; border-radius: 999px; padding: 2px 8px; font-size: 11px; white-space: nowrap; }}
.status-ready, .status-done {{ color: var(--green); }}
.status-review {{ color: var(--amber); }}
.status-blocked {{ color: var(--red); }}
.status-pending, .status-no_records {{ color: var(--slate); }}
.tiny-label {{ font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: var(--slate); }}
.note {{ color: var(--ink-soft); font-size: 12.5px; margin: 12px 0 0; }}
.collisions {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
.collision-card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 20px; min-width: 0; }}
.collision-card header {{ display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }}
.collision-card h3 {{ margin: 3px 0 9px; font-size: 15px; overflow-wrap: anywhere; }}
.collision-key {{ background: #f4f0e7; border: 1px solid #e4ddcf; border-radius: 10px; padding: 10px 12px; margin: 10px 0 8px; overflow-wrap: anywhere; }}
.collision-key code {{ display: block; margin-top: 3px; font-size: 12.5px; }}
.count-chip {{ background: var(--teal-deep); color: #eff8f3; border-radius: 999px; padding: 4px 10px; font-family: var(--mono); font-size: 11px; white-space: nowrap; }}
.table-scroll.compact {{ margin-top: 12px; border: 1px solid var(--line); border-radius: 10px; }}
.compact td, .compact th {{ padding: 8px 10px; }}
.value-cell {{ overflow-wrap: anywhere; max-width: 300px; }}
.empty-state {{ display: flex; flex-direction: column; gap: 5px; align-items: flex-start; padding: 30px; color: var(--ink-soft); border: 1px dashed var(--line); border-radius: 14px; background: #faf7f0; }}
.empty-state strong {{ color: var(--ink); font-size: 16px; }}
.toolbar {{ display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)) minmax(180px, 1.4fr) auto; gap: 10px; align-items: end; margin-bottom: 12px; }}
.toolbar label {{ display: flex; flex-direction: column; gap: 4px; font-size: 11px; letter-spacing: .04em; color: var(--slate); }}
select, input[type="search"] {{ width: 100%; border: 1px solid var(--line); border-radius: 9px; padding: 8px 10px; background: #fffdf8; color: var(--ink); font: inherit; font-size: 13px; }}
.filter-count {{ font-family: var(--mono); font-size: 12px; color: var(--slate); padding-bottom: 8px; white-space: nowrap; }}
.finding-row.hidden {{ display: none; }}
.message-cell {{ min-width: 260px; max-width: 440px; overflow-wrap: anywhere; }}
details summary {{ cursor: pointer; color: var(--teal); font-size: 12px; white-space: nowrap; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11px; line-height: 1.5; background: #f3efe6; border: 1px solid #e4ddcf; border-radius: 8px; padding: 10px; max-width: 430px; max-height: 300px; overflow: auto; }}
.no-match {{ display: none; padding: 24px; color: var(--slate); }}
.plan {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }}
.plan-step {{ display: grid; grid-template-columns: 52px minmax(0, 1fr); gap: 14px; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }}
.step-index {{ font-family: var(--mono); color: var(--teal); font-size: 14px; padding-top: 2px; }}
.step-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
.step-head h3 {{ margin: 0; font-size: 15px; }}
.step-body p {{ margin: 7px 0 0; color: var(--ink-soft); font-size: 13.5px; }}
.acceptance {{ border-left: 2px solid var(--teal-soft); padding-left: 10px; }}
.boundary {{ display: grid; grid-template-columns: 1.1fr .9fr; gap: 14px; }}
.boundary ul {{ margin: 0; padding-left: 19px; color: var(--ink-soft); }}
.boundary li + li {{ margin-top: 7px; }}
.artifact-list {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px; }}
.artifact-list a {{ display: flex; justify-content: space-between; gap: 10px; padding: 9px 11px; border: 1px solid var(--line); border-radius: 9px; text-decoration: none; background: #faf7f0; font-family: var(--mono); font-size: 11.5px; }}
.artifact-list a:hover {{ border-color: var(--teal); }}
.run-meta {{ display: flex; flex-wrap: wrap; gap: 8px 20px; margin-top: 12px; font-size: 12px; color: var(--ink-soft); }}
.run-meta code {{ font-size: 11.5px; }}
footer {{ max-width: 1320px; margin: 0 auto; padding: 0 clamp(16px, 4vw, 48px) 54px; color: var(--slate); font-size: 12px; }}
.footer-rule {{ height: 1px; background: var(--line); margin-bottom: 16px; }}
@media (max-width: 1040px) {{
  .metrics {{ grid-template-columns: repeat(3, 1fr); }}
  .collisions, .boundary {{ grid-template-columns: 1fr; }}
  .toolbar {{ grid-template-columns: repeat(2, 1fr); }}
  .filter-count {{ grid-column: 1 / -1; padding-bottom: 0; }}
}}
@media (max-width: 720px) {{
  .verdict {{ grid-template-columns: 1fr; margin-top: -18px; }}
  .metrics {{ grid-template-columns: repeat(2, 1fr); }}
  .toolbar {{ grid-template-columns: 1fr; }}
  .plan-step {{ grid-template-columns: 1fr; }}
  .step-index {{ padding: 0; }}
  .hero {{ padding-top: 34px; }}
}}
@media print {{
  body {{ background: #fff; }}
  .hero {{ color: #000; background: #fff; border-bottom: 2px solid #000; }}
  .hero p, .eyebrow, .hero-tag {{ color: #333; }}
  .hero::after, .toolbar, .artifact-list {{ display: none; }}
  .verdict, .panel, .metric, .collision-card, .plan-step {{ box-shadow: none; break-inside: avoid; }}
  details {{ display: none; }}
  a {{ color: #000; }}
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --ink: #e9ede9; --ink-soft: #b6c2bb; --paper: #111916; --panel: #18221e;
    --line: #37453e; --teal-soft: #183c35; --amber-soft: #3d2d17;
    --red-soft: #44231e; --green-soft: #1d3924; --slate: #99aaa1;
    --shadow: 0 18px 50px rgba(0,0,0,.25);
  }}
  body {{ background: radial-gradient(circle at 15% 0%, rgba(31, 129, 114, .12), transparent 32rem), var(--paper); }}
  .hero {{ background: linear-gradient(135deg, #071d1a, #0c2e29); }}
  th, .collision-key, .empty-state, pre, .artifact-list a {{ background: #131c18; }}
  tbody tr:hover {{ background: #1b2722; }}
  select, input[type="search"] {{ background: #111916; }}
}}
</style>
</head>
<body>
<header class="hero">
  <div class="eyebrow">CHARORDER / {_e(APP_SLUG)} · 完全离线预检</div>
  <h1>{_e(APP_NAME)}<br><span>文本排序键迁移，先审计再切换。</span></h1>
  <p>{_e(APP_TAGLINE)}。读取本地 CSV、JSONL、SQLite 与 JSON 配置，计算目标排序键，定位碰撞、超长、不可见字符与解码风险。源文件只读，不执行任何迁移语句。</p>
  <div class="hero-tags">
    <span class="hero-tag">OFFLINE / NO NETWORK</span>
    <span class="hero-tag">STDLIB ONLY</span>
    <span class="hero-tag">READ-ONLY REVIEW</span>
    <span class="hero-tag">UNICODE {_e(UNICODE_VERSION)}</span>
  </div>
</header>
<main>
  <section class="verdict" data-verdict="{_e(verdict)}" aria-labelledby="verdict-title">
    <div>
      <p class="verdict-label">{_e(VERDICT_LABEL.get(verdict, verdict))}</p>
      <h2 id="verdict-title">{_e(config.project.name)}</h2>
      <p>{_e(verdict_detail)}</p>
      <div class="run-meta">
        <span>目标 <code>{_e(config.project.target)}</code></span>
        <span>运行 <code>{_e(result.run_id)}</code></span>
        <span>生成 <code>{_e(result.generated_at)}</code></span>
        <span>配置 SHA-256 <code>{_e(config.config_sha256[:20])}…</code></span>
      </div>
    </div>
    <div class="severity-tiles" aria-label="风险计数">
      {severity_tiles}
    </div>
  </section>

  <section class="metrics" aria-label="运行指标">
    <div class="metric"><span>源文件</span><strong>{summary['source_count']}</strong><small>CSV / JSONL / SQLite</small></div>
    <div class="metric"><span>记录</span><strong>{summary['record_count']:,}</strong><small>本次输入快照</small></div>
    <div class="metric"><span>目标键</span><strong>{summary['keys_evaluated']:,}</strong><small>{summary['key_rule_count']} 条规则</small></div>
    <div class="metric"><span>键值变化</span><strong>{summary['changed_keys']:,}</strong><small>归一化 / 折叠后</small></div>
    <div class="metric"><span>碰撞组</span><strong>{summary['collision_groups']:,}</strong><small>{summary['collision_records']} 条记录</small></div>
  </section>

  <section class="section" id="sources">
    <div class="section-head"><h2>源文件与只读指纹</h2><p>哈希已写入计划与台账</p></div>
    <div class="panel table-scroll">
      <table>
        <thead><tr><th>源</th><th>路径</th><th>记录</th><th>键结果</th><th>状态</th><th>SHA-256</th></tr></thead>
        <tbody>{source_rows}</tbody>
      </table>
      <p class="note">源文件在扫描前后均以只读方式处理；SQLite 通过 <code>mode=ro</code> 与 <code>PRAGMA query_only</code> 打开。报告只展示相对配置目录的路径。</p>
    </div>
  </section>

  <section class="section" id="rules">
    <div class="section-head"><h2>目标键规则矩阵</h2><p>二进制 UTF-8 排序键，不依赖系统 locale</p></div>
    <div class="panel table-scroll">
      <table>
        <thead><tr><th>规则</th><th>源 / 列</th><th>目标位置</th><th>变换管线</th><th>记录</th><th>碰撞组</th><th>超限</th><th>约束</th><th>状态</th></tr></thead>
        <tbody>{''.join(rule_rows)}</tbody>
      </table>
      <p class="note">变换顺序固定为：移除 Cf 不可见字符 → 宽度折叠 → Unicode 规范化 → 大小写映射 → 空白折叠 → 首尾清理。含多个列时使用 U+001F 作为复合键分隔符，并检查分隔符歧义。</p>
    </div>
  </section>

  <section class="section" id="collisions">
    <div class="section-head"><h2>唯一键碰撞组</h2><p>业务必须逐组裁决，工具不自动合并</p></div>
    {''.join(collision_cards)}
    {collision_more}
  </section>

  {preflight_section}

  <section class="section" id="findings">
    <div class="section-head"><h2>风险清单</h2><p>全量明细见 findings.json 与 SQLite 台账</p></div>
    <div class="panel">
      <div class="toolbar" id="filter-bar">
        <label>严重级别<select id="filter-severity"><option value="">全部级别</option>{severity_options}</select></label>
        <label>检查类型<select id="filter-code"><option value="">全部检查</option>{code_options}</select></label>
        <label>源文件<select id="filter-source"><option value="">全部源</option>{source_options}</select></label>
        <label>键规则<select id="filter-rule"><option value="">全部规则</option>{rule_options}</select></label>
        <label>关键词<input id="filter-search" type="search" placeholder="检查码、消息、记录、列名…" autocomplete="off"></label>
        <div class="filter-count" id="filter-count">显示 {len(shown_findings):,} / {len(result.findings):,} 项</div>
      </div>
      <div class="table-scroll">
        <table id="findings-table">
          <thead><tr><th>级别</th><th>检查</th><th>位置</th><th>说明</th><th>证据</th></tr></thead>
          <tbody>{''.join(finding_rows)}</tbody>
        </table>
      </div>
      <div class="no-match" id="no-match">当前筛选没有匹配的风险项。</div>
      {f'<p class="note">页面仅展示前 {max_rows:,} 项，另有 {omitted_findings:,} 项见 findings.json 与台账；筛选仅作用于当前页面。</p>' if omitted_findings > 0 else ''}
    </div>
  </section>

  <section class="section" id="plan">
    <div class="section-head"><h2>迁移计划与验收门禁</h2><p>计划由输入内容派生，不含墙钟时间</p></div>
    <ol class="plan">{step_cards}</ol>
  </section>

  <section class="section" id="boundary">
    <div class="section-head"><h2>边界与证据文件</h2><p>只读复核，不执行迁移</p></div>
    <div class="boundary">
      <div class="panel">
        <h3>明确不做</h3>
        <ul>
          <li>不执行 UPDATE / INSERT / DELETE，不创建生产索引。</li>
          <li>不访问网络，不加载 CDN、远程字体或外部脚本。</li>
          <li>不自动修复乱码，不自动合并或删除碰撞记录。</li>
          <li>不使用系统 locale 或模糊匹配模拟排序规则。</li>
          <li>不向源 CSV、JSONL、SQLite 写回任何内容。</li>
        </ul>
        <h3>处置顺序</h3>
        <ul>
          <li>先处理源解码、缺失与超限，再处理唯一键碰撞。</li>
          <li>不可见字符与异常空白应回到源系统治理，不只清理目标键。</li>
          <li>在影子库完成排序对比后，才按本计划的门禁切换。</li>
        </ul>
      </div>
      <div class="panel">
        <h3>本次产物</h3>
        <div class="artifact-list">
          <a href="report.html"><span>交互复核页</span><span>HTML</span></a>
          <a href="report.md"><span>摘要报告</span><span>MD</span></a>
          <a href="plan.json"><span>迁移计划</span><span>JSON</span></a>
          <a href="plan.md"><span>计划摘要</span><span>MD</span></a>
          <a href="findings.json"><span>风险清单</span><span>JSON</span></a>
          <a href="collisions.json"><span>碰撞组</span><span>JSON</span></a>
          <a href="keys.jsonl"><span>逐键结果</span><span>JSONL</span></a>
          <a href="ledger.sqlite"><span>审计台账</span><span>SQLite</span></a>
          <a href="manifest.json"><span>运行清单</span><span>JSON</span></a>
        </div>
        <p class="note">报告包含原始值，仅适合在受控本地环境处理合成或已获授权的数据。</p>
      </div>
    </div>
  </section>
</main>
<footer>
  <div class="footer-rule"></div>
  <div>{_e(APP_NAME)} · {_e(APP_SLUG)} v{_e(__version__)} · {_e(APP_TAGLINE)} · 本页面无外部资源，可离线归档。</div>
</footer>
<script>
(function () {{
  var severity = document.getElementById("filter-severity");
  var code = document.getElementById("filter-code");
  var source = document.getElementById("filter-source");
  var rule = document.getElementById("filter-rule");
  var search = document.getElementById("filter-search");
  var count = document.getElementById("filter-count");
  var noMatch = document.getElementById("no-match");
  var rows = Array.prototype.slice.call(document.querySelectorAll(".finding-row"));
  if (!severity || !code || !source || !rule || !search || !rows.length) {{
    return;
  }}
  function applyFilters() {{
    var term = search.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {{
      var visible =
        (!severity.value || row.dataset.severity === severity.value) &&
        (!code.value || row.dataset.code === code.value) &&
        (!source.value || row.dataset.source === source.value) &&
        (!rule.value || row.dataset.rule === rule.value) &&
        (!term || (row.dataset.search || "").indexOf(term) !== -1);
      row.classList.toggle("hidden", !visible);
      if (visible) {{ shown += 1; }}
    }});
    count.textContent = "显示 " + shown + " / " + rows.length + " 项";
    noMatch.style.display = shown === 0 ? "block" : "none";
  }}
  [severity, code, source, rule].forEach(function (element) {{
    element.addEventListener("change", applyFilters);
  }});
  search.addEventListener("input", applyFilters);
  applyFilters();
}})();
</script>
</body>
</html>
"""
