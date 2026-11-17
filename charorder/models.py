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
    # Visual-confusable evidence is deliberately a separate family from the
    # byte-level collision codes above. These codes never replace
    # NORMALIZATION_COLLISION / DUPLICATE_KEY for an exactly equal target_key.
    "SCRIPT_NOT_AUTHORIZED": "high",
    "VISUAL_CONFUSABLE_CANDIDATE": "medium",
    "VISUAL_COVERAGE_UNKNOWN": "medium",
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
    "SCRIPT_NOT_AUTHORIZED": "未授权文字体系",
    "VISUAL_CONFUSABLE_CANDIDATE": "跨键视觉混淆候选",
    "VISUAL_COVERAGE_UNKNOWN": "视觉混淆映射覆盖未知",
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
class ScriptPolicy:
    """Authorization contract for scripts allowed in one target namespace.

    ``strict_script`` permits exactly ``allowed_scripts`` and blocks any other
    script. ``authorized_mixed`` explicitly authorizes a set of scripts for
    mixed-script sources, but still requires manual visual review of
    different-byte keys that share a visual skeleton.
    """

    mode: str  # "strict_script" | "authorized_mixed"
    allowed_scripts: tuple[str, ...]
    namespace: str = ""
    reason: str = ""
    visual_review_required: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "allowed_scripts": list(self.allowed_scripts),
            "namespace": self.namespace,
            "reason": self.reason,
            "visual_review_required": self.visual_review_required,
        }


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
    script_policy: ScriptPolicy | None = None

    @property
    def composite(self) -> bool:
        return len(self.columns) > 1


@dataclass(frozen=True)
class VisualReview:
    """A recorded human conclusion for one visual-confusable candidate."""

    rule_id: str
    skeleton_sha256: str
    conclusion: str  # distinct_verified | merge_required | migration_blocked
    reviewer: str
    note: str = ""
    decided_at: str = ""
    map_version: str = ""
    skeleton_version: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "skeleton_sha256": self.skeleton_sha256,
            "conclusion": self.conclusion,
            "reviewer": self.reviewer,
            "note": self.note,
            "decided_at": self.decided_at,
            "map_version": self.map_version,
            "skeleton_version": self.skeleton_version,
        }


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
    visual_reviews: tuple[VisualReview, ...] = ()

    @property
    def source_map(self) -> dict[str, SourceSpec]:
        return {source.id: source for source in self.sources}

    @property
    def key_map(self) -> dict[str, KeyRule]:
        return {key.id: key for key in self.keys}

    @property
    def visual_review_map(self) -> dict[tuple[str, str], VisualReview]:
        return {
            (review.rule_id, review.skeleton_sha256): review
            for review in self.visual_reviews
        }

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
    # Visual evidence is stored separately from the byte-level key hash.
    visual_profile: dict[str, Any] | None = None
    visual_candidate_ids: list[str] = field(default_factory=list)

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
            "visual_profile": self.visual_profile,
            "visual_candidate_ids": list(self.visual_candidate_ids),
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
class VisualCandidate:
    """A cross-key visual-confusable candidate between different binary keys.

    This is *not* a database uniqueness collision. ``review_status`` records
    whether a human has signed off; until it is ``reviewed`` the migration plan
    must not claim the keys are directly migratable.
    """

    candidate_id: str
    rule_id: str
    source_id: str
    skeleton: str
    skeleton_escaped: str
    skeleton_sha256: str
    skeleton_version: str
    map_version: str
    policy_mode: str
    status: str  # "review_required" | "reviewed"
    risk_level: str  # "high" | "medium" | "unknown"
    members: list[dict[str, Any]]
    cross_script: bool
    unknown_coverage: bool
    requires_review: bool = True
    conclusion: str | None = None
    reviewer: str | None = None
    review_note: str = ""
    decided_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "source_id": self.source_id,
            "skeleton": self.skeleton,
            "skeleton_escaped": self.skeleton_escaped,
            "skeleton_sha256": self.skeleton_sha256,
            "skeleton_version": self.skeleton_version,
            "map_version": self.map_version,
            "policy_mode": self.policy_mode,
            "status": self.status,
            "risk_level": self.risk_level,
            "cross_script": self.cross_script,
            "unknown_coverage": self.unknown_coverage,
            "requires_review": self.requires_review,
            "conclusion": self.conclusion,
            "reviewer": self.reviewer,
            "review_note": self.review_note,
            "decided_at": self.decided_at,
            "record_count": len(self.members),
            "members": list(self.members),
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
    visual_candidates: list[VisualCandidate] = field(default_factory=list)
