"""Shared data models for charorder."""

from __future__ import annotations

import hashlib
import json
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
    # Candidate transforms for rule-adjustment preflight. Empty means this rule
    # is fixed at ``transform`` and cannot be selected by the optimizer.
    candidates: tuple[TransformSpec, ...] = ()
    # Target table / entity namespace. Used to decide whether two records are
    # "different entities in the same target table". Falls back to destination.
    target_table: str = ""

    @property
    def composite(self) -> bool:
        return len(self.columns) > 1

    @property
    def target_unit(self) -> str:
        return self.target_table or self.destination or self.id

    @property
    def selectable(self) -> bool:
        return bool(self.candidates)


@dataclass(frozen=True)
class RecordRef:
    """A record identity bound to one rule and one source."""

    source_id: str
    rule_id: str
    record_ref: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "rule_id": self.rule_id,
            "record_ref": self.record_ref,
        }

    def key(self) -> tuple[str, str, str]:
        return (self.source_id, self.rule_id, self.record_ref)


@dataclass(frozen=True)
class AuthorizedLink:
    """An authorized one-to-one association between two record identities."""

    link_id: str
    left: RecordRef
    right: RecordRef


@dataclass(frozen=True)
class ForbiddenPair:
    """Two cross-table records that must never share a target key."""

    pair_id: str
    left: RecordRef
    right: RecordRef


@dataclass(frozen=True)
class PreflightSpec:
    """Caller-supplied rule-adjustment constraints."""

    max_combinations: int
    authorized_links: tuple[AuthorizedLink, ...]
    forbidden_pairs: tuple[ForbiddenPair, ...]
    forbid_unauthorized_cross_table: bool = True
    expected_sources_sha256: dict[str, str] = field(default_factory=dict)
    expected_source_digest: str = ""
    expected_rules_sha256: str = ""
    constraint_sha256: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_combinations": self.max_combinations,
            "authorized_links": [
                {
                    "link_id": link.link_id,
                    "left": link.left.as_dict(),
                    "right": link.right.as_dict(),
                }
                for link in self.authorized_links
            ],
            "forbidden_pairs": [
                {
                    "pair_id": pair.pair_id,
                    "left": pair.left.as_dict(),
                    "right": pair.right.as_dict(),
                }
                for pair in self.forbidden_pairs
            ],
            "forbid_unauthorized_cross_table": (
                self.forbid_unauthorized_cross_table
            ),
            "expected_sources_sha256": dict(
                sorted(self.expected_sources_sha256.items())
            ),
            "expected_source_digest": self.expected_source_digest,
            "expected_rules_sha256": self.expected_rules_sha256,
            "constraint_sha256": self.constraint_sha256,
        }


def rule_summary(rule: KeyRule) -> dict[str, Any]:
    """Stable, order-preserving description of one rule for digest binding."""

    return {
        "id": rule.id,
        "source_id": rule.source_id,
        "columns": list(rule.columns),
        "destination": rule.destination,
        "target_table": rule.target_unit,
        "unique": rule.unique,
        "required": rule.required,
        "max_bytes": rule.max_bytes,
        "max_chars": rule.max_chars,
        "transform": rule.transform.as_dict(),
        "candidates": [spec.as_dict() for spec in rule.candidates],
    }


def rule_summary_digest(keys: tuple[KeyRule, ...] | list[KeyRule]) -> str:
    payload = [rule_summary(rule) for rule in keys]
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


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
    preflight: PreflightSpec | None = None

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
    preflight: PreflightResult | None = None


@dataclass
class PreflightKeyEvidence:
    """Old and new target key for one record under a candidate configuration."""

    rule_id: str
    source_id: str
    record_ref: str
    record_id: str | None
    old_key: str | None
    old_bytes: int
    new_key: str | None
    new_bytes: int
    changed: bool
    transform: TransformSpec
    defects: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "source_id": self.source_id,
            "record_ref": self.record_ref,
            "record_id": self.record_id,
            "old_key_escaped": (
                None if self.old_key is None else self.old_key
            ),
            "old_bytes": self.old_bytes,
            "new_key_escaped": (
                None if self.new_key is None else self.new_key
            ),
            "new_bytes": self.new_bytes,
            "changed": self.changed,
            "transform": self.transform.as_dict(),
            "defects": list(self.defects),
        }


@dataclass
class PreflightEvaluation:
    """A fully recomputed candidate configuration for one objective."""

    objective: str
    status: str
    selected_transforms: dict[str, TransformSpec]
    exit_code: int
    changed_records: int
    total_bytes: int
    key_evidence: list[PreflightKeyEvidence]
    checks: dict[str, Any]
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    combination_rank: int = 0
    exhaustive: bool = True
    proof: dict[str, Any] = field(default_factory=dict)
    provisional: bool = False
    examined_combinations: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "status": self.status,
            "selected_transforms": {
                rule_id: spec.as_dict()
                for rule_id, spec in self.selected_transforms.items()
            },
            "exit_code": self.exit_code,
            "changed_records": self.changed_records,
            "total_bytes": self.total_bytes,
            "combination_rank": self.combination_rank,
            "exhaustive": self.exhaustive,
            "provisional": self.provisional,
            "examined_combinations": self.examined_combinations,
            "checks": self.checks,
            "diagnostics": self.diagnostics,
            "proof": self.proof,
            "keys": [item.as_dict() for item in self.key_evidence],
        }


@dataclass
class PreflightResult:
    run_id: str
    config_sha256: str
    source_digest: str
    rules_sha256: str
    constraint_digest: str
    stale: bool
    stale_reasons: list[str]
    candidate_rule_ids: list[str]
    total_combinations: int
    examined_combinations: int
    budget_exhausted: bool
    candidate_order: list[dict[str, Any]]
    objective_results: dict[str, PreflightEvaluation | None]
    witness: dict[str, Any] | None
    state: str
    notes: list[str] = field(default_factory=list)
    evidence_verified: bool = True
    relation_summary: dict[str, Any] = field(default_factory=dict)
    config_summary: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "charorder.preflight",
            "run_id": self.run_id,
            "config_sha256": self.config_sha256,
            "source_digest": self.source_digest,
            "rules_sha256": self.rules_sha256,
            "constraint_digest": self.constraint_digest,
            "stale": self.stale,
            "stale_reasons": self.stale_reasons,
            "state": self.state,
            "candidate_rule_ids": self.candidate_rule_ids,
            "total_combinations": self.total_combinations,
            "examined_combinations": self.examined_combinations,
            "budget_exhausted": self.budget_exhausted,
            "candidate_order": self.candidate_order,
            "notes": self.notes,
            "objectives": {
                objective: (None if evaluation is None else evaluation.as_dict())
                for objective, evaluation in self.objective_results.items()
            },
            "witness": self.witness,
            "evidence_verified": self.evidence_verified,
            "relation_summary": self.relation_summary,
            "config_summary": self.config_summary,
        }
