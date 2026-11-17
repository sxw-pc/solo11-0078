"""Shared data models for charorder."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("high", "medium", "low")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
SEVERITY_LABEL = {"high": "高", "medium": "中", "low": "低"}

DEFAULT_SEVERITIES: dict[str, str] = {
    "SOURCE_INVALID_BYTES": "high",
    "SOURCE_PARSE_ERROR": "high",
    "SOURCE_ROW_MISMATCH": "high",
    "MISSING_RECORD_ID": "medium",
    "DUPLICATE_RECORD_ID": "high",
    "REQUIRED_VALUE_MISSING": "high",
    "EMPTY_KEY": "medium",
    "INVISIBLE_CHARACTER": "medium",
    "ABNORMAL_WHITESPACE": "medium",
    "CONTROL_CHARACTER": "high",
    "BIDI_CONTROL": "high",
    "REPLACEMENT_CHARACTER": "high",
    "SURROGATE_CHARACTER": "high",
    "MOJIBAKE_SUSPECT": "medium",
    "NON_TEXT_VALUE": "medium",
    "KEY_TOO_LONG_BYTES": "high",
    "KEY_TOO_LONG_CHARS": "high",
    "COMPOSITE_SEPARATOR": "high",
    "NORMALIZATION_COLLISION": "high",
    "DUPLICATE_KEY": "high",
    # Versioned composite-key framing rehearsal (opt-in).
    "LEGACY_COMPOSITE_AMBIGUITY": "high",
    "VERSIONED_KEY_COLLISION": "high",
    "VERSIONED_KEY_EMPTY": "medium",
    "VERSIONED_KEY_TOO_LONG": "high",
    "VERSIONED_ROUNDTRIP_FAILED": "high",
    "VERSIONED_PAYLOAD_CONTROL": "low",
    "VERSION_MARKER_CONFLICT": "high",
    "REHEARSAL_SOURCE_COMPONENT_MISSING": "high",
    "REHEARSAL_RECORD_IDENTITY_DUPLICATE": "high",
    "LEGACY_KEY_UNATTRIBUTABLE": "high",
    "TARGET_INDEX_ENCODING_MIX": "high",
}

CHECK_CODES = tuple(DEFAULT_SEVERITIES.keys())

CHECK_LABELS: dict[str, str] = {
    "SOURCE_INVALID_BYTES": "源文件含非法字节序列",
    "SOURCE_PARSE_ERROR": "源记录解析失败",
    "SOURCE_ROW_MISMATCH": "CSV 行列结构异常",
    "MISSING_RECORD_ID": "记录标识缺失",
    "DUPLICATE_RECORD_ID": "记录标识重复",
    "REQUIRED_VALUE_MISSING": "必需键值缺失",
    "EMPTY_KEY": "空排序键",
    "INVISIBLE_CHARACTER": "不可见格式字符",
    "ABNORMAL_WHITESPACE": "异常空白",
    "CONTROL_CHARACTER": "控制字符",
    "BIDI_CONTROL": "双向文本控制符",
    "REPLACEMENT_CHARACTER": "替换字符 U+FFFD",
    "SURROGATE_CHARACTER": "孤立代理码位",
    "MOJIBAKE_SUSPECT": "疑似乱码",
    "NON_TEXT_VALUE": "非文本值被强制转写",
    "KEY_TOO_LONG_BYTES": "目标键 UTF-8 字节超限",
    "KEY_TOO_LONG_CHARS": "目标键字符数超限",
    "COMPOSITE_SEPARATOR": "复合键含保留分隔符",
    "NORMALIZATION_COLLISION": "归一化后唯一键碰撞",
    "DUPLICATE_KEY": "相同原始值唯一键重复",
    "LEGACY_COMPOSITE_AMBIGUITY": "旧复合键存在结构歧义，无法倒推分量",
    "VERSIONED_KEY_COLLISION": "版本化复合键全量重算后仍碰撞",
    "VERSIONED_KEY_EMPTY": "版本化复合键为空",
    "VERSIONED_KEY_TOO_LONG": "版本化复合键超出长度上限",
    "VERSIONED_ROUNDTRIP_FAILED": "版本化复合键编解码一致性失败",
    "VERSIONED_PAYLOAD_CONTROL": "版本化复合键分量携带保留控制字符",
    "VERSION_MARKER_CONFLICT": "旧键与版本化帧标记冲突",
    "REHEARSAL_SOURCE_COMPONENT_MISSING": "预演记录缺少权威源分量",
    "REHEARSAL_RECORD_IDENTITY_DUPLICATE": "预演记录身份重复",
    "LEGACY_KEY_UNATTRIBUTABLE": "旧目标键无法归属到源记录",
    "TARGET_INDEX_ENCODING_MIX": "目标索引混用无版本区分的旧/新编码",
}

# Declared composite-key encoding strategies.
KEY_ENCODING_LEGACY = "legacy"
KEY_ENCODING_V1 = "v1"
KEY_ENCODINGS = (KEY_ENCODING_LEGACY, KEY_ENCODING_V1)

# Rehearsal contract outcomes.
CONTRACT_LEGACY_BLOCKED = "legacy_blocked"
CONTRACT_VERSIONED_CUTOVER = "versioned_cutover"
CONTRACT_NOT_ELIGIBLE = "not_eligible"

VERDICT_LABEL = {
    "blocked": "阻断：暂不建议迁移",
    "review": "需复核：存在中等级风险",
    "pass_with_notes": "通过：仅剩低等级提醒",
    "pass": "通过：未发现风险",
}


@dataclass(frozen=True)
class ProjectSpec:
    name: str
    target: str
    description: str = ""


@dataclass(frozen=True)
class SourceSpec:
    id: str
    kind: str
    path: Path
    display_path: str
    record_id_field: str
    encoding: str = "utf-8"
    encoding_errors: str = "replace"
    delimiter: str = ","
    quotechar: str = '"'
    table: str | None = None


@dataclass(frozen=True)
class TransformSpec:
    normalization: str = "NFC"
    case: str = "none"
    width_fold: bool = False
    trim: bool = True
    collapse_whitespace: bool = False
    invisible: str = "keep"

    def as_dict(self) -> dict[str, Any]:
        return {
            "normalization": self.normalization,
            "case": self.case,
            "width_fold": self.width_fold,
            "trim": self.trim,
            "collapse_whitespace": self.collapse_whitespace,
            "invisible": self.invisible,
        }

    def describe(self) -> str:
        parts = []
        if self.invisible == "remove":
            parts.append("移除 Cf 不可见字符")
        if self.width_fold:
            parts.append("宽度折叠")
        if self.normalization != "none":
            parts.append(self.normalization)
        if self.case != "none":
            parts.append({"casefold": "casefold", "lower": "小写", "upper": "大写"}[self.case])
        if self.collapse_whitespace:
            parts.append("折叠空白")
        if self.trim:
            parts.append("去首尾空白")
        return " → ".join(parts) if parts else "原样保留"


@dataclass(frozen=True)
class KeyRule:
    id: str
    label: str
    source_id: str
    columns: tuple[str, ...]
    transform: TransformSpec
    destination: str = ""
    description: str = ""
    unique: bool = False
    required: bool = True
    max_bytes: int | None = None
    max_chars: int | None = None
    # Opt-in composite-key strategy. "legacy" keeps the ambiguous U+001F join
    # (and blocks separator-bearing records); "v1" enables the versioned,
    # reversible length-prefixed framing rehearsal.
    key_encoding: str = "legacy"
    # Optional inventory of keys already present in the target index for this
    # rule. Every entry is an opaque legacy/versioned string; the rehearsal
    # must attribute each one to exactly one source record or block cutover,
    # and must reject an index that already mixes encodings.
    legacy_key_inventory: tuple[str, ...] = ()

    @property
    def composite(self) -> bool:
        return len(self.columns) > 1

    @property
    def versioned_framing(self) -> bool:
        return self.key_encoding == KEY_ENCODING_V1


@dataclass(frozen=True)
class AppConfig:
    version: int
    project: ProjectSpec
    sources: tuple[SourceSpec, ...]
    keys: tuple[KeyRule, ...]
    config_path: Path
    config_sha256: str
    severity_overrides: dict[str, str] = field(default_factory=dict)
    max_report_rows: int = 500

    @property
    def source_map(self) -> dict[str, SourceSpec]:
        return {source.id: source for source in self.sources}

    @property
    def key_map(self) -> dict[str, KeyRule]:
        return {key.id: key for key in self.keys}

    def severity_for(self, code: str) -> str:
        if code in self.severity_overrides:
            return self.severity_overrides[code]
        return DEFAULT_SEVERITIES.get(code, "medium")


@dataclass
class SourceRecord:
    source_id: str
    ordinal: int
    record_ref: str
    record_id: str | None
    values: dict[str, Any]
    defects: list[Defect] = field(default_factory=list)


@dataclass(frozen=True)
class Defect:
    code: str
    severity: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    column: str | None = None


@dataclass
class SourceLoad:
    spec: SourceSpec
    records: list[SourceRecord]
    columns: list[str]
    sha256: str
    size_bytes: int
    issues: list[Defect] = field(default_factory=list)
    decode_note: dict[str, Any] | None = None


@dataclass
class Finding:
    finding_id: str
    code: str
    severity: str
    message: str
    source_id: str | None = None
    rule_id: str | None = None
    record_ref: str | None = None
    record_id: str | None = None
    column: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "code": self.code,
            "label": CHECK_LABELS.get(self.code, self.code),
            "severity": self.severity,
            "message": self.message,
            "source_id": self.source_id,
            "rule_id": self.rule_id,
            "record_ref": self.record_ref,
            "record_id": self.record_id,
            "column": self.column,
            "details": self.details,
        }


@dataclass
class KeyResult:
    key_result_id: str
    source_id: str
    rule_id: str
    ordinal: int
    record_ref: str
    record_id: str | None
    raw_values: tuple[str | None, ...]
    raw_display: str
    target_key: str | None
    target_key_escaped: str | None
    key_sha256: str | None
    key_bytes: int
    key_chars: int
    changed: bool
    defects: list[Defect] = field(default_factory=list)
    collision_group_id: str | None = None
    # Populated only for rules opting into versioned framing and only when all
    # source components are available; the legacy target_key above is always
    # retained as the ambiguous legacy summary.
    versioned_key: str | None = None
    versioned_key_escaped: str | None = None
    versioned_key_sha256: str | None = None
    versioned_key_bytes: int = 0
    versioned_key_chars: int = 0
    versioned_roundtrip_ok: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_result_id": self.key_result_id,
            "source_id": self.source_id,
            "rule_id": self.rule_id,
            "record_ref": self.record_ref,
            "record_id": self.record_id,
            "raw_values": list(self.raw_values),
            "raw_display": self.raw_display,
            "target_key": self.target_key,
            "target_key_escaped": self.target_key_escaped,
            "key_sha256": self.key_sha256,
            "key_bytes": self.key_bytes,
            "key_chars": self.key_chars,
            "changed": self.changed,
            "defects": [
                {"code": d.code, "severity": d.severity, "column": d.column}
                for d in self.defects
            ],
            "collision_group_id": self.collision_group_id,
            "versioned_key": self.versioned_key,
            "versioned_key_escaped": self.versioned_key_escaped,
            "versioned_key_sha256": self.versioned_key_sha256,
            "versioned_key_bytes": self.versioned_key_bytes,
            "versioned_key_chars": self.versioned_key_chars,
            "versioned_roundtrip_ok": self.versioned_roundtrip_ok,
        }


@dataclass
class VersionedKeyRow:
    """Per-record rehearsal evidence for one versioned-framing rule."""

    key_result_id: str
    source_id: str
    rule_id: str
    ordinal: int
    record_ref: str
    record_id: str | None
    # The authoritative rollback material: the original source components in
    # declared column order, plus the transform that derived the new key.
    source_components: list[str | None]
    transformed_components: list[str] | None
    legacy_key: str | None
    legacy_key_sha256: str | None
    legacy_key_bytes: int
    versioned_key: str | None
    versioned_key_escaped: str | None
    versioned_key_sha256: str | None
    versioned_key_bytes: int
    versioned_key_chars: int
    roundtrip_ok: bool | None
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_result_id": self.key_result_id,
            "source_id": self.source_id,
            "rule_id": self.rule_id,
            "ordinal": self.ordinal,
            "record_ref": self.record_ref,
            "record_id": self.record_id,
            "source_components": self.source_components,
            "transformed_components": self.transformed_components,
            "legacy_key": self.legacy_key,
            "legacy_key_sha256": self.legacy_key_sha256,
            "legacy_key_bytes": self.legacy_key_bytes,
            "versioned_key": self.versioned_key,
            "versioned_key_escaped": self.versioned_key_escaped,
            "versioned_key_sha256": self.versioned_key_sha256,
            "versioned_key_bytes": self.versioned_key_bytes,
            "versioned_key_chars": self.versioned_key_chars,
            "roundtrip_ok": self.roundtrip_ok,
            "blockers": self.blockers,
            "notes": self.notes,
        }


@dataclass
class CompositeKeyRehearsal:
    """Whole-rule versioned composite-key rehearsal and contract decision."""

    rehearsal_id: str
    rule_id: str
    source_id: str
    encoding: str
    frame_version: str
    frame_prefix_escaped: str
    columns: list[str]
    transform: dict[str, Any]
    unique: bool
    required: bool
    max_bytes: int | None
    max_chars: int | None
    rows: list[VersionedKeyRow]
    # Contract A: stay on legacy encoding. Eligible only when no record under
    # this rule carries a structural separator in a transformed component;
    # separator-bearing rows stay blocked pending source governance.
    legacy_contract: str
    legacy_contract_blockers: list[str]
    blocked_record_refs: list[str]
    # Contract B: cut the whole rule over to versioned framing.
    versioned_contract: str
    versioned_contract_blockers: list[str]
    # Whole-population re-judgement of the new keys.
    versioned_collision_groups: list[dict[str, Any]]
    versioned_empty_record_refs: list[str]
    versioned_overlength_record_refs: list[str]
    payload_control_record_refs: list[str]
    # Target-index integration checks against the declared inventory.
    inventory_size: int
    unattributable_inventory_keys: list[dict[str, Any]]
    index_encoding_mix: bool
    inventory_versioned_collisions: list[dict[str, Any]]
    # The two ambiguous tuples from the requirement must remain distinct
    # identities here; this lists legacy strings shared by >= 2 tuples.
    legacy_ambiguous_strings: list[dict[str, Any]]
    rollback: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rehearsal_id": self.rehearsal_id,
            "rule_id": self.rule_id,
            "source_id": self.source_id,
            "encoding": self.encoding,
            "frame_version": self.frame_version,
            "frame_prefix_escaped": self.frame_prefix_escaped,
            "columns": self.columns,
            "transform": self.transform,
            "unique": self.unique,
            "required": self.required,
            "max_bytes": self.max_bytes,
            "max_chars": self.max_chars,
            "row_count": len(self.rows),
            "rows": [row.to_dict() for row in self.rows],
            "legacy_contract": self.legacy_contract,
            "legacy_contract_blockers": self.legacy_contract_blockers,
            "blocked_record_refs": self.blocked_record_refs,
            "versioned_contract": self.versioned_contract,
            "versioned_contract_blockers": self.versioned_contract_blockers,
            "versioned_collision_groups": self.versioned_collision_groups,
            "versioned_empty_record_refs": self.versioned_empty_record_refs,
            "versioned_overlength_record_refs": self.versioned_overlength_record_refs,
            "payload_control_record_refs": self.payload_control_record_refs,
            "inventory_size": self.inventory_size,
            "unattributable_inventory_keys": self.unattributable_inventory_keys,
            "index_encoding_mix": self.index_encoding_mix,
            "inventory_versioned_collisions": self.inventory_versioned_collisions,
            "legacy_ambiguous_strings": self.legacy_ambiguous_strings,
            "rollback": self.rollback,
        }


@dataclass
class CollisionGroup:
    group_id: str
    rule_id: str
    source_id: str
    target_key: str
    target_key_escaped: str
    reason_code: str
    participants: list[KeyResult]
    raw_variants: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "rule_id": self.rule_id,
            "source_id": self.source_id,
            "target_key": self.target_key,
            "target_key_escaped": self.target_key_escaped,
            "reason_code": self.reason_code,
            "record_count": len(self.participants),
            "distinct_raw_count": len(self.raw_variants),
            "participants": [
                {
                    "key_result_id": k.key_result_id,
                    "record_ref": k.record_ref,
                    "record_id": k.record_id,
                    "raw_values": list(k.raw_values),
                    "raw_display": k.raw_display,
                }
                for k in self.participants
            ],
            "raw_variants": self.raw_variants,
        }


@dataclass
class ScanResult:
    config: AppConfig
    run_id: str
    generated_at: str
    source_loads: list[SourceLoad]
    records: list[SourceRecord]
    key_results: list[KeyResult]
    findings: list[Finding]
    collisions: list[CollisionGroup]
    summary: dict[str, Any]
    verdict: str
    plan: dict[str, Any]
    # Opt-in versioned composite-key rehearsals, one per v1 rule. Empty for
    # fully legacy configurations so legacy scans stay byte-identical.
    rehearsals: list[CompositeKeyRehearsal] = field(default_factory=list)
