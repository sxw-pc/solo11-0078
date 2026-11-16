"""Load and structurally validate offline target-index adjudication registers.

Adjudication files are reviewer-authored JSON. They are never written back to a
source. Structural validation happens here; binding against the current input
snapshot, rule digests and expiry happens during the target-index rehearsal.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .models import (
    AdjudicationDocument,
    AdjudicationMember,
    KeyAdjudication,
    ReplacementAssignment,
)
from .transforms import escaped_text, sanitize_text, utf8_bytes

_DOC_FIELDS = {
    "schema_version",
    "kind",
    "index_id",
    "config_sha256",
    "input_sha256",
    "expires_at",
    "decisions",
}
_DECISION_FIELDS = {
    "adjudication_id",
    "target_key",
    "decision",
    "reason",
    "reviewed_by",
    "reviewed_at",
    "members",
    "replacements",
}
_MEMBER_FIELDS = {
    "source_id",
    "rule_id",
    "record_ref",
    "record_id",
    "raw_display",
    "target_key",
    "rule_digest",
}
_REPLACEMENT_FIELDS = {
    "source_id",
    "rule_id",
    "record_ref",
    "record_id",
    "replacement_key",
}


def load_adjudication_file(path: str | Path, base_dir: Path) -> AdjudicationDocument:
    doc_path = Path(path).expanduser()
    if not doc_path.is_absolute():
        doc_path = base_dir / doc_path
    try:
        doc_path = doc_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ConfigError(f"裁决文件不存在：{doc_path}") from exc
    except OSError as exc:
        raise ConfigError(f"无法访问裁决文件：{doc_path}（{exc}）") from exc
    if not doc_path.is_file():
        raise ConfigError(f"裁决路径不是文件：{doc_path}")
    try:
        raw = doc_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"无法读取裁决文件：{doc_path}（{exc}）") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigError("裁决文件必须是 UTF-8 编码的 JSON。") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"裁决文件 JSON 解析失败：第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise ConfigError("裁决文件顶层必须是 JSON 对象。")
    _reject_unknown(data, _DOC_FIELDS, "裁决文件")

    if data.get("schema_version") != 1:
        raise ConfigError("裁决文件 schema_version 必须为 1。")
    if data.get("kind") != "charorder.target_adjudications":
        raise ConfigError(
            "裁决文件 kind 必须是 charorder.target_adjudications。"
        )
    index_id = _require_nonempty_str(data.get("index_id"), "裁决文件.index_id")
    config_sha256 = _require_sha256(data.get("config_sha256"), "裁决文件.config_sha256")

    input_obj = data.get("input_sha256")
    if not isinstance(input_obj, dict) or not input_obj:
        raise ConfigError("裁决文件.input_sha256 必须是非空对象。")
    input_sha256: dict[str, str] = {}
    for source_id, digest in input_obj.items():
        if not isinstance(source_id, str) or not source_id.strip():
            raise ConfigError("裁决文件.input_sha256 的源标识必须是非空字符串。")
        _require_sha256(digest, f"裁决文件.input_sha256.{source_id}")
        input_sha256[source_id.strip()] = digest

    expires_raw = data.get("expires_at")
    expires_at = ""
    if expires_raw is not None:
        expires_at = _require_iso_utc(expires_raw, "裁决文件.expires_at")

    decisions_obj = data.get("decisions")
    if not isinstance(decisions_obj, list) or not decisions_obj:
        raise ConfigError("裁决文件.decisions 必须是非空数组。")

    decisions: list[KeyAdjudication] = []
    seen_decision_ids: set[str] = set()
    seen_group_keys: set[tuple[str, str]] = set()
    for index, item in enumerate(decisions_obj):
        where = f"decisions[{index}]"
        decision = _parse_decision(item, where)
        if decision.adjudication_id in seen_decision_ids:
            raise ConfigError(f"{where}.adjudication_id 重复：{decision.adjudication_id}")
        seen_decision_ids.add(decision.adjudication_id)
        group_key = (index_id, decision.target_key)
        if group_key in seen_group_keys:
            raise ConfigError(
                f"{where} 与另一条裁决指向同一目标键：{decision.target_key!r}"
            )
        seen_group_keys.add(group_key)
        decisions.append(decision)

    return AdjudicationDocument(
        path=doc_path,
        doc_sha256=hashlib.sha256(raw).hexdigest(),
        index_id=index_id,
        config_sha256=config_sha256,
        input_sha256=dict(sorted(input_sha256.items())),
        decisions=tuple(decisions),
        expires_at=expires_at or None,
    )


def _parse_decision(item: Any, where: str) -> KeyAdjudication:
    obj = _require_object(item, where)
    _reject_unknown(obj, _DECISION_FIELDS, where)
    adjudication_id = _require_id(obj.get("adjudication_id"), f"{where}.adjudication_id")
    target_key = obj.get("target_key")
    if not isinstance(target_key, str) or target_key == "":
        raise ConfigError(f"{where}.target_key 必须是非空字符串。")
    target_key = sanitize_text(target_key)
    decision = _require_nonempty_str(obj.get("decision"), f"{where}.decision")
    if decision not in {"merge", "split"}:
        raise ConfigError(f"{where}.decision 必须是 merge 或 split。")

    members_obj = obj.get("members")
    if not isinstance(members_obj, list) or not members_obj:
        raise ConfigError(f"{where}.members 必须是非空数组。")
    members: list[AdjudicationMember] = []
    seen_identities: set[tuple[str, str, str]] = set()
    for member_index, member_item in enumerate(members_obj):
        member_where = f"{where}.members[{member_index}]"
        member = _parse_member(member_item, member_where)
        identity = (member.source_id, member.rule_id, member.record_ref)
        if identity in seen_identities:
            raise ConfigError(f"{member_where} 来源身份在同一裁决内重复。")
        seen_identities.add(identity)
        members.append(member)
    if len(members) < 2:
        raise ConfigError(f"{where}.members 至少需要两个来源身份才能构成裁决。")

    replacements: list[ReplacementAssignment] = []
    if decision == "split":
        replacements_obj = obj.get("replacements")
        if not isinstance(replacements_obj, list) or not replacements_obj:
            raise ConfigError(f"{where}.replacements：split 裁决必须提供替代键数组。")
        seen_replacement_identities: set[tuple[str, str, str]] = set()
        seen_replacement_keys: set[str] = set()
        for repl_index, repl_item in enumerate(replacements_obj):
            repl_where = f"{where}.replacements[{repl_index}]"
            replacement = _parse_replacement(repl_item, repl_where)
            identity = (
                replacement.source_id,
                replacement.rule_id,
                replacement.record_ref,
            )
            if identity not in seen_identities:
                raise ConfigError(
                    f"{repl_where} 的来源身份不属于本裁决 members，裁决必须绑定真实成员。"
                )
            if identity in seen_replacement_identities:
                raise ConfigError(f"{repl_where} 来源身份的替代键重复声明。")
            seen_replacement_identities.add(identity)
            if replacement.replacement_key in seen_replacement_keys:
                raise ConfigError(
                    f"{repl_where} 替代键在同一裁决内重复：{replacement.replacement_key!r}"
                )
            seen_replacement_keys.add(replacement.replacement_key)
            replacements.append(replacement)
        member_identities = {
            (member.source_id, member.rule_id, member.record_ref) for member in members
        }
        missing = member_identities - seen_replacement_identities
        if missing:
            raise ConfigError(
                f"{where}.replacements 未覆盖全部成员，缺少："
                + ", ".join("/".join(part) for part in sorted(missing))
            )
    elif "replacements" in obj and obj["replacements"]:
        raise ConfigError(f"{where}.replacements 仅允许出现在 split 裁决中。")

    return KeyAdjudication(
        adjudication_id=adjudication_id,
        index_id="",
        target_key=target_key,
        decision=decision,
        members=tuple(members),
        reason=_optional_str(obj.get("reason", ""), f"{where}.reason"),
        reviewed_by=_optional_str(obj.get("reviewed_by", ""), f"{where}.reviewed_by"),
        reviewed_at=_optional_str(obj.get("reviewed_at", ""), f"{where}.reviewed_at"),
        replacements=tuple(replacements),
    )


def _parse_member(item: Any, where: str) -> AdjudicationMember:
    obj = _require_object(item, where)
    _reject_unknown(obj, _MEMBER_FIELDS, where)
    source_id = _require_id(obj.get("source_id"), f"{where}.source_id")
    rule_id = _require_id(obj.get("rule_id"), f"{where}.rule_id")
    record_ref = _require_nonempty_str(obj.get("record_ref"), f"{where}.record_ref")
    record_id_raw = obj.get("record_id")
    record_id = None if record_id_raw is None else _optional_str(record_id_raw, f"{where}.record_id")
    raw_display = _require_nonempty_str(obj.get("raw_display"), f"{where}.raw_display")
    target_key = obj.get("target_key")
    if not isinstance(target_key, str) or target_key == "":
        raise ConfigError(f"{where}.target_key 必须是非空字符串。")
    rule_digest = _require_sha256(obj.get("rule_digest"), f"{where}.rule_digest")
    return AdjudicationMember(
        source_id=source_id,
        rule_id=rule_id,
        record_ref=record_ref,
        record_id=record_id or None,
        raw_display=raw_display,
        target_key=sanitize_text(target_key),
        rule_digest=rule_digest,
    )


def _parse_replacement(item: Any, where: str) -> ReplacementAssignment:
    obj = _require_object(item, where)
    _reject_unknown(obj, _REPLACEMENT_FIELDS, where)
    source_id = _require_id(obj.get("source_id"), f"{where}.source_id")
    rule_id = _require_id(obj.get("rule_id"), f"{where}.rule_id")
    record_ref = _require_nonempty_str(obj.get("record_ref"), f"{where}.record_ref")
    record_id_raw = obj.get("record_id")
    record_id = None if record_id_raw is None else _optional_str(record_id_raw, f"{where}.record_id")
    replacement_key = obj.get("replacement_key")
    if not isinstance(replacement_key, str) or replacement_key == "":
        raise ConfigError(f"{where}.replacement_key 必须是非空字符串。")
    safe_key = sanitize_text(replacement_key)
    return ReplacementAssignment(
        source_id=source_id,
        rule_id=rule_id,
        record_ref=record_ref,
        record_id=record_id or None,
        replacement_key=safe_key,
        replacement_escaped=escaped_text(safe_key),
        key_bytes=len(utf8_bytes(safe_key)),
        key_chars=len(safe_key),
    )


def _require_iso_utc(value: Any, where: str) -> str:
    text = _require_nonempty_str(value, where)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"{where} 不是 ISO-8601 时间：{text}") from exc
    if parsed.tzinfo is None:
        raise ConfigError(f"{where} 必须带时区（建议 UTC，例如 2026-12-31T23:59:59Z）。")
    return text


def _reject_unknown(obj: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ConfigError(f"{where} 含未知字段：{', '.join(unknown)}")


def _require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} 必须是对象。")
    return value


def _require_nonempty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where} 必须是非空字符串。")
    return value.strip()


def _optional_str(value: Any, where: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{where} 必须是字符串。")
    return value


def _require_id(value: Any, where: str) -> str:
    text = _require_nonempty_str(value, where)
    if not text[0].isalnum() or any(
        not (ch.isalnum() or ch in "_-") for ch in text
    ) or len(text) > 64:
        raise ConfigError(
            f"{where} 只能使用字母、数字、下划线和连字符，且必须以字母或数字开头：{text}"
        )
    return text


def _require_sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or not re_full_sha256(value):
        raise ConfigError(f"{where} 必须是 64 位十六进制 SHA-256。")
    return value


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())
