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

# Future-key ordering certificate verdicts and cutover licenses.
CERT_STATUSES = (
    "proven",            # exhaustive proof over the full declared finite domain
    "counterexample",    # a real replayable inversion/confluence pair was found
    "unknown",           # bounded search exhausted its budget without a proof
    "invalid_domain",    # the declared domain itself is not verifiable
)
CERT_LICENSES = (
    "direct_translation",  # old boundaries/cursors may be mapped directly
    "blocked",             # direct translation must not be licensed
    "not_established",     # keep legacy ordering or target-side full-domain filtering
)
SNAPSHOT_ORDER_STATES = (
    "no_inversion_observed",
    "inversion_observed",
    "confluence_observed",
    "no_records",
)
CERT_STATUS_LABEL = {
    "proven": "已证保序（域内穷尽）",
    "counterexample": "已发现倒序/合流反例",
    "unknown": "未穷尽：无证明",
    "invalid_domain": "域声明无效：无法证明",
}
CERT_LICENSE_LABEL = {
    "direct_translation": "允许直译旧范围边界/游标",
    "blocked": "阻断直译",
    "not_established": "待核实：维持旧排序或目标侧全域过滤",
}
SNAPSHOT_ORDER_LABEL = {
    "no_inversion_observed": "当前快照未观察到倒序",
    "inversion_observed": "当前快照已观察到倒序",
    "confluence_observed": "当前快照已观察到合流",
    "no_records": "快照无记录",
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
class DomainComponent:
    """One composite-key component's declared future raw-key domain."""

    column: str
    charset: tuple[str, ...]
    min_length: int
    max_length: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "column": self.column,
            "charset": list(self.charset),
            "min_length": self.min_length,
            "max_length": self.max_length,
        }


@dataclass(frozen=True)
class FutureDomainSpec:
    """Caller-declared, verifiable domain of future raw keys for one rule."""

    components: tuple[DomainComponent, ...]
    legacy_order: str
    exhaustive_member_limit: int
    pair_budget: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "components": [component.as_dict() for component in self.components],
            "legacy_order": self.legacy_order,
            "exhaustive_member_limit": self.exhaustive_member_limit,
            "pair_budget": self.pair_budget,
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
    future_domain: FutureDomainSpec | None = None

    @property
    def composite(self) -> bool:
        return len(self.columns) > 1


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


@dataclass(frozen=True)
class SnapshotOrderObservation:
    """Ordering evidence derived only from the loaded snapshot's keys."""

    rule_id: str
    state: str
    records: int
    inversion_count: int
    confluence_count: int
    examples: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "state": self.state,
            "records": self.records,
            "inversion_count": self.inversion_count,
            "confluence_count": self.confluence_count,
            "examples": list(self.examples),
        }


@dataclass(frozen=True)
class OrderingCertificate:
    """Rule-level certificate for future-key ordering compatibility.

    The certificate never connects to a target database: every target key is
    replayed through the same ``apply_transform`` pipeline used for snapshot
    keys, and ordering is evaluated on whole strings / full composite keys.
    """

    certificate_id: str
    rule_id: str
    source_id: str
    status: str
    license: str
    domain: FutureDomainSpec
    domain_digest: str
    transform_digest: str
    transform: TransformSpec
    unicode_version: str
    target_order: str
    exhaustive: bool
    domain_member_count: int
    eligible_member_count: int
    excluded_count: int
    excluded_reasons: dict[str, int]
    excluded_examples: tuple[dict[str, Any], ...]
    pairs_checked: int
    pair_budget: int
    member_budget: int
    budget_exhausted: bool
    counterexample: dict[str, Any] | None
    invalid_reason: str | None
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "rule_id": self.rule_id,
            "source_id": self.source_id,
            "status": self.status,
            "status_label": CERT_STATUS_LABEL.get(self.status, self.status),
            "license": self.license,
            "license_label": CERT_LICENSE_LABEL.get(self.license, self.license),
            "target_order": self.target_order,
            "legacy_order": self.domain.legacy_order,
            "unicode_version": self.unicode_version,
            "domain_digest": self.domain_digest,
            "transform_digest": self.transform_digest,
            "domain": self.domain.as_dict(),
            "transform": self.transform.as_dict(),
            "exhaustive": self.exhaustive,
            "domain_member_count": self.domain_member_count,
            "eligible_member_count": self.eligible_member_count,
            "excluded_count": self.excluded_count,
            "excluded_reasons": dict(sorted(self.excluded_reasons.items())),
            "excluded_examples": list(self.excluded_examples),
            "pairs_checked": self.pairs_checked,
            "pair_budget": self.pair_budget,
            "member_budget": self.member_budget,
            "budget_exhausted": self.budget_exhausted,
            "counterexample": self.counterexample,
            "invalid_reason": self.invalid_reason,
            "notes": list(self.notes),
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
    ordering_certificates: list[OrderingCertificate] = field(default_factory=list)
    snapshot_observations: list[SnapshotOrderObservation] = field(default_factory=list)
