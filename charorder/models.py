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
    "TARGET_INDEX_COLLISION": "high",
    "TARGET_ADJUDICATION_MISSING": "high",
    "TARGET_ADJUDICATION_INVALID": "high",
    "TARGET_ADJUDICATION_STALE": "high",
    "TARGET_ADJUDICATION_CONFLICT": "high",
    "TARGET_REPLACEMENT_COLLISION": "high",
    "TARGET_REPLACEMENT_OVERLENGTH": "high",
    "TARGET_PROJECTION_DUPLICATE": "high",
    "TARGET_PROJECTION_OVERLENGTH": "high",
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
    "TARGET_INDEX_COLLISION": "目标唯一索引跨来源碰撞",
    "TARGET_ADJUDICATION_MISSING": "目标索引碰撞组缺少人工裁决",
    "TARGET_ADJUDICATION_INVALID": "目标索引裁决引用失效",
    "TARGET_ADJUDICATION_STALE": "目标索引裁决已过期或绑定不匹配",
    "TARGET_ADJUDICATION_CONFLICT": "同一来源记录被矛盾裁决重复占用",
    "TARGET_REPLACEMENT_COLLISION": "替代键在目标投影中再次碰撞",
    "TARGET_REPLACEMENT_OVERLENGTH": "替代键超出目标字节/字符长度约束",
    "TARGET_PROJECTION_DUPLICATE": "目标投影视图仍存在重复键",
    "TARGET_PROJECTION_OVERLENGTH": "目标投影键超出索引长度约束",
}

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

    @property
    def composite(self) -> bool:
        return len(self.columns) > 1


@dataclass(frozen=True)
class TargetIndexSpec:
    """Declarative grouping of key rules that share one target unique index."""

    id: str
    label: str
    destination: str
    rule_ids: tuple[str, ...]
    max_bytes: int | None = None
    max_chars: int | None = None
    description: str = ""


@dataclass(frozen=True)
class ReplacementAssignment:
    """One verifiable replacement key chosen for a distinct business entity."""

    source_id: str
    rule_id: str
    record_ref: str
    record_id: str | None
    replacement_key: str
    replacement_escaped: str
    key_bytes: int
    key_chars: int


@dataclass(frozen=True)
class AdjudicationMember:
    """Source-record identity bound to the current input and rule digest."""

    source_id: str
    rule_id: str
    record_ref: str
    record_id: str | None
    raw_display: str
    target_key: str
    rule_digest: str


@dataclass(frozen=True)
class KeyAdjudication:
    """A reviewed decision for one cross-source target-key collision group."""

    adjudication_id: str
    index_id: str
    target_key: str
    decision: str  # "merge" | "split"
    members: tuple[AdjudicationMember, ...]
    reason: str = ""
    reviewed_by: str = ""
    reviewed_at: str = ""
    replacements: tuple[ReplacementAssignment, ...] = ()


@dataclass(frozen=True)
class AdjudicationDocument:
    """Offline, read-only adjudication register loaded from a JSON file."""

    path: Path
    doc_sha256: str
    index_id: str
    config_sha256: str
    input_sha256: dict[str, str]
    decisions: tuple[KeyAdjudication, ...]
    expires_at: str | None = None
    version: int = 1


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
    target_indexes: tuple[TargetIndexSpec, ...] = ()
    adjudications: tuple[AdjudicationDocument, ...] = ()

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
class TargetCollisionGroup:
    """A collision inside one declared target unique index projection."""

    group_id: str
    index_id: str
    target_key: str
    target_key_escaped: str
    target_key_bytes: int
    reason_code: str
    participants: list[KeyResult]
    raw_variants: list[str]
    sources: list[str]
    rule_ids: list[str]
    decision: str = "open"  # open | merge | split | invalid
    adjudication_id: str | None = None
    block_reasons: list[str] = field(default_factory=list)
    projected_targets: list["ProjectedTargetRow"] = field(default_factory=list)
    adjudication: KeyAdjudication | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "index_id": self.index_id,
            "target_key": self.target_key,
            "target_key_escaped": self.target_key_escaped,
            "target_key_bytes": self.target_key_bytes,
            "reason_code": self.reason_code,
            "decision": self.decision,
            "adjudication_id": self.adjudication_id,
            "block_reasons": list(self.block_reasons),
            "sources": list(self.sources),
            "rule_ids": list(self.rule_ids),
            "record_count": len(self.participants),
            "distinct_raw_count": len(self.raw_variants),
            "raw_variants": self.raw_variants,
            "participants": [
                {
                    "key_result_id": k.key_result_id,
                    "source_id": k.source_id,
                    "rule_id": k.rule_id,
                    "record_ref": k.record_ref,
                    "record_id": k.record_id,
                    "raw_values": list(k.raw_values),
                    "raw_display": k.raw_display,
                    "target_key": k.target_key,
                    "target_key_bytes": k.key_bytes,
                }
                for k in self.participants
            ],
            "projected_targets": [row.to_dict() for row in self.projected_targets],
        }


@dataclass
class ProjectedTargetRow:
    """One row of the offline target-index projection (the would-be index rows)."""

    index_id: str
    target_key: str
    target_key_escaped: str
    key_bytes: int
    key_chars: int
    provenance: list[dict[str, Any]]
    origin: str  # untouched | merge | replacement
    collision_group_id: str | None = None
    adjudication_id: str | None = None
    over_bytes: bool = False
    over_chars: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_id": self.index_id,
            "target_key": self.target_key,
            "target_key_escaped": self.target_key_escaped,
            "key_bytes": self.key_bytes,
            "key_chars": self.key_chars,
            "origin": self.origin,
            "collision_group_id": self.collision_group_id,
            "adjudication_id": self.adjudication_id,
            "over_bytes": self.over_bytes,
            "over_chars": self.over_chars,
            "provenance": list(self.provenance),
        }


@dataclass
class TargetIndexRehearsal:
    """Offline rehearsal result for one declared target unique index."""

    spec: TargetIndexSpec
    groups: list[TargetCollisionGroup]
    projection: list[ProjectedTargetRow]
    projection_duplicates: list[dict[str, Any]]
    projection_overlength: list[dict[str, Any]]
    adjudication_register: list[dict[str, Any]]
    block_reasons: list[str]
    blocked: bool
    projected_row_count: int
    evaluated_at: str
    stale: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_id": self.spec.id,
            "label": self.spec.label,
            "destination": self.spec.destination,
            "rule_ids": list(self.spec.rule_ids),
            "max_bytes": self.spec.max_bytes,
            "max_chars": self.spec.max_chars,
            "blocked": self.blocked,
            "block_reasons": list(self.block_reasons),
            "stale": self.stale,
            "evaluated_at": self.evaluated_at,
            "collision_group_count": len(self.groups),
            "collision_record_count": sum(len(g.participants) for g in self.groups),
            "projected_row_count": self.projected_row_count,
            "projection_duplicates": list(self.projection_duplicates),
            "projection_overlength": list(self.projection_overlength),
            "groups": [group.to_dict() for group in self.groups],
            "projection": [row.to_dict() for row in self.projection],
            "adjudication_register": list(self.adjudication_register),
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
    target_rehearsals: list[TargetIndexRehearsal] = field(default_factory=list)
