"""Configuration loading and strict validation."""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .models import (
    DEFAULT_SEVERITIES,
    SEVERITIES,
    AppConfig,
    AuthorizedLink,
    ForbiddenPair,
    KeyRule,
    PreflightSpec,
    ProjectSpec,
    RecordRef,
    SourceSpec,
    TransformSpec,
    rule_summary_digest,
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TOP_LEVEL = {
    "version",
    "project",
    "sources",
    "keys",
    "severity_overrides",
    "reports",
    "preflight",
}
_PROJECT_FIELDS = {"name", "target", "description"}
_SOURCE_FIELDS = {
    "id",
    "type",
    "path",
    "encoding",
    "encoding_errors",
    "record_id_field",
    "delimiter",
    "quotechar",
    "table",
}
_KEY_FIELDS = {
    "id",
    "label",
    "source",
    "columns",
    "transform",
    "candidates",
    "destination",
    "target_table",
    "description",
    "unique",
    "required",
    "max_bytes",
    "max_chars",
}
_TRANSFORM_FIELDS = {
    "normalization",
    "case",
    "width_fold",
    "trim",
    "collapse_whitespace",
    "invisible",
}
_REPORT_FIELDS = {"max_report_rows"}
_PREFLIGHT_FIELDS = {
    "max_combinations",
    "authorized_links",
    "forbidden_pairs",
    "forbid_unauthorized_cross_table",
    "source_sha256",
    "source_digest",
    "rules_sha256",
}
_REF_FIELDS = {"source_id", "rule_id", "record_ref"}


def load_config(path: str | Path) -> AppConfig:
    """Load a JSON configuration file and resolve all referenced paths."""

    config_path = Path(path).expanduser()
    try:
        config_path = config_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ConfigError(f"配置文件不存在：{config_path}") from exc
    except OSError as exc:
        raise ConfigError(f"无法访问配置文件：{config_path}（{exc}）") from exc
    if not config_path.is_file():
        raise ConfigError(f"配置路径不是文件：{config_path}")

    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"无法读取配置文件：{config_path}（{exc}）") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigError("配置文件必须是 UTF-8 编码的 JSON。") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"配置文件 JSON 解析失败：第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ConfigError("配置文件顶层必须是 JSON 对象。")
    _reject_unknown(data, _TOP_LEVEL, "顶层配置")

    version = data.get("version")
    if version != 1:
        raise ConfigError("配置 version 必须为 1。")

    project_obj = _require_object(data.get("project"), "project")
    _reject_unknown(project_obj, _PROJECT_FIELDS, "project")
    name = _require_nonempty_str(project_obj.get("name"), "project.name")
    target = _require_nonempty_str(project_obj.get("target"), "project.target")
    description = _optional_str(project_obj.get("description", ""), "project.description")
    project = ProjectSpec(name=name, target=target, description=description)

    sources_obj = data.get("sources")
    if not isinstance(sources_obj, list) or not sources_obj:
        raise ConfigError("sources 必须是非空数组。")
    sources: list[SourceSpec] = []
    seen_source_ids: set[str] = set()
    for index, item in enumerate(sources_obj):
        source = _parse_source(item, index, config_path.parent)
        if source.id in seen_source_ids:
            raise ConfigError(f"sources[{index}].id 重复：{source.id}")
        seen_source_ids.add(source.id)
        sources.append(source)
    source_by_id = {source.id: source for source in sources}

    keys_obj = data.get("keys")
    if not isinstance(keys_obj, list) or not keys_obj:
        raise ConfigError("keys 必须是非空数组。")
    keys: list[KeyRule] = []
    seen_key_ids: set[str] = set()
    for index, item in enumerate(keys_obj):
        key = _parse_key(item, index)
        if key.id in seen_key_ids:
            raise ConfigError(f"keys[{index}].id 重复：{key.id}")
        seen_key_ids.add(key.id)
        if key.source_id not in source_by_id:
            raise ConfigError(
                f"keys[{index}].source 指向不存在的源：{key.source_id}"
            )
        keys.append(key)

    overrides_obj = data.get("severity_overrides", {})
    if not isinstance(overrides_obj, dict):
        raise ConfigError("severity_overrides 必须是对象。")
    severity_overrides: dict[str, str] = {}
    for code, severity in overrides_obj.items():
        if code not in DEFAULT_SEVERITIES:
            raise ConfigError(
                f"severity_overrides 包含未知检查码：{code}；"
                f"可用检查码：{', '.join(DEFAULT_SEVERITIES)}"
            )
        if severity not in SEVERITIES:
            raise ConfigError(
                f"severity_overrides.{code} 必须是 high / medium / low。"
            )
        severity_overrides[str(code)] = str(severity)

    reports_obj = data.get("reports", {})
    if not isinstance(reports_obj, dict):
        raise ConfigError("reports 必须是对象。")
    _reject_unknown(reports_obj, _REPORT_FIELDS, "reports")
    max_report_rows = reports_obj.get("max_report_rows", 500)
    if (
        isinstance(max_report_rows, bool)
        or not isinstance(max_report_rows, int)
        or not (1 <= max_report_rows <= 100_000)
    ):
        raise ConfigError("reports.max_report_rows 必须是 1..100000 的整数。")

    preflight = _parse_preflight(
        data.get("preflight"), keys, source_by_id
    )
    if preflight is not None:
        if not any(key.selectable for key in keys):
            raise ConfigError(
                "preflight 已声明，但没有任何 keys 提供 candidates；"
                "规则调整预检至少需要一条可选规则。"
            )
        preflight = PreflightSpec(
            max_combinations=preflight.max_combinations,
            authorized_links=preflight.authorized_links,
            forbidden_pairs=preflight.forbidden_pairs,
            forbid_unauthorized_cross_table=(
                preflight.forbid_unauthorized_cross_table
            ),
            expected_sources_sha256=preflight.expected_sources_sha256,
            expected_source_digest=preflight.expected_source_digest,
            expected_rules_sha256=preflight.expected_rules_sha256,
            constraint_sha256=_preflight_digest(keys, preflight),
        )

    return AppConfig(
        version=1,
        project=project,
        sources=tuple(sources),
        keys=tuple(keys),
        config_path=config_path,
        config_sha256=hashlib.sha256(raw).hexdigest(),
        severity_overrides=severity_overrides,
        max_report_rows=max_report_rows,
        preflight=preflight,
    )


def _parse_source(item: Any, index: int, base_dir: Path) -> SourceSpec:
    where = f"sources[{index}]"
    obj = _require_object(item, where)
    _reject_unknown(obj, _SOURCE_FIELDS, where)
    source_id = _require_id(obj.get("id"), f"{where}.id")
    kind = _require_nonempty_str(obj.get("type"), f"{where}.type").lower()
    if kind not in {"csv", "jsonl", "sqlite"}:
        raise ConfigError(f"{where}.type 必须是 csv / jsonl / sqlite。")
    raw_path = _require_nonempty_str(obj.get("path"), f"{where}.path")
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    try:
        path = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ConfigError(f"{where}.path 指向的文件不存在：{path}") from exc
    except OSError as exc:
        raise ConfigError(f"{where}.path 无法访问：{path}（{exc}）") from exc
    if not path.is_file():
        raise ConfigError(f"{where}.path 不是普通文件：{path}")

    record_id_field = _require_nonempty_str(
        obj.get("record_id_field"), f"{where}.record_id_field"
    )
    encoding = _optional_str(obj.get("encoding", "utf-8"), f"{where}.encoding")
    try:
        codecs.lookup(encoding)
    except LookupError as exc:
        raise ConfigError(f"{where}.encoding 不是已知编码：{encoding}") from exc
    encoding_errors = _optional_str(
        obj.get("encoding_errors", "replace"), f"{where}.encoding_errors"
    )
    if encoding_errors not in {"replace", "strict"}:
        raise ConfigError(f"{where}.encoding_errors 只能是 replace 或 strict。")

    delimiter = _optional_str(obj.get("delimiter", ","), f"{where}.delimiter")
    quotechar = _optional_str(obj.get("quotechar", '"'), f"{where}.quotechar")
    if kind == "csv":
        if len(delimiter) != 1:
            raise ConfigError(f"{where}.delimiter 必须是单个字符。")
        if len(quotechar) != 1:
            raise ConfigError(f"{where}.quotechar 必须是单个字符。")
    elif "delimiter" in obj or "quotechar" in obj:
        raise ConfigError(f"{where} 只有 CSV 源支持 delimiter / quotechar。")

    table: str | None = None
    if kind == "sqlite":
        table = _require_nonempty_str(obj.get("table"), f"{where}.table")
    elif "table" in obj:
        raise ConfigError(f"{where}.table 仅适用于 SQLite 源。")

    if kind != "csv" and "encoding" in obj and kind == "sqlite":
        # SQLite text is UTF-8 by contract. An explicit common alias is accepted,
        # but non-UTF-8 codecs would make the audit misleading.
        if encoding.replace("_", "-").lower() not in {"utf-8", "utf8"}:
            raise ConfigError(f"{where}.encoding：SQLite TEXT 必须以 utf-8 读取。")
        encoding = "utf-8"

    try:
        display_path = Path(os.path.relpath(path, base_dir)).as_posix()
    except ValueError:
        display_path = path.as_posix()
    if display_path == ".":
        display_path = path.name

    return SourceSpec(
        id=source_id,
        kind=kind,
        path=path,
        display_path=display_path,
        record_id_field=record_id_field,
        encoding=encoding,
        encoding_errors=encoding_errors,
        delimiter=delimiter,
        quotechar=quotechar,
        table=table,
    )


def _parse_key(item: Any, index: int) -> KeyRule:
    where = f"keys[{index}]"
    obj = _require_object(item, where)
    _reject_unknown(obj, _KEY_FIELDS, where)
    key_id = _require_id(obj.get("id"), f"{where}.id")
    label = _require_nonempty_str(obj.get("label"), f"{where}.label")
    source_id = _require_id(obj.get("source"), f"{where}.source")
    columns_obj = obj.get("columns")
    if not isinstance(columns_obj, list) or not columns_obj:
        raise ConfigError(f"{where}.columns 必须是非空字符串数组。")
    columns: list[str] = []
    for column_index, column in enumerate(columns_obj):
        columns.append(
            _require_nonempty_str(column, f"{where}.columns[{column_index}]")
        )
    if len(set(columns)) != len(columns):
        raise ConfigError(f"{where}.columns 不能包含重复列。")

    transform = _parse_transform(obj.get("transform", {}), f"{where}.transform")
    # ``candidates`` is the complete allowed set; the caller must include the
    # original transform if it is meant to remain selectable. The original
    # transform is still used as the "old key" baseline for change counting.
    candidates = _parse_candidates(obj.get("candidates"), f"{where}.candidates")
    destination = _optional_str(obj.get("destination", ""), f"{where}.destination")
    target_table = _optional_str(
        obj.get("target_table", ""), f"{where}.target_table"
    ).strip()
    description = _optional_str(obj.get("description", ""), f"{where}.description")
    unique = _optional_bool(obj.get("unique", False), f"{where}.unique")
    required = _optional_bool(obj.get("required", True), f"{where}.required")

    max_bytes = _optional_positive_int(obj.get("max_bytes"), f"{where}.max_bytes")
    max_chars = _optional_positive_int(obj.get("max_chars"), f"{where}.max_chars")

    return KeyRule(
        id=key_id,
        label=label,
        source_id=source_id,
        columns=tuple(columns),
        transform=transform,
        destination=destination,
        description=description,
        unique=unique,
        required=required,
        max_bytes=max_bytes,
        max_chars=max_chars,
        candidates=candidates,
        target_table=target_table,
    )


def _parse_transform(item: Any, where: str) -> TransformSpec:
    if item is None:
        item = {}
    obj = _require_object(item, where)
    _reject_unknown(obj, _TRANSFORM_FIELDS, where)

    normalization = _optional_str(obj.get("normalization", "NFC"), f"{where}.normalization")
    if normalization.lower() == "none":
        normalization = "none"
    else:
        normalization = normalization.upper()
    if normalization not in {"none", "NFC", "NFD", "NFKC", "NFKD"}:
        raise ConfigError(f"{where}.normalization 必须是 none/NFC/NFD/NFKC/NFKD。")

    case = _optional_str(obj.get("case", "none"), f"{where}.case").lower()
    if case not in {"none", "lower", "upper", "casefold"}:
        raise ConfigError(f"{where}.case 必须是 none/lower/upper/casefold。")

    width_fold = _optional_bool(obj.get("width_fold", False), f"{where}.width_fold")
    trim = _optional_bool(obj.get("trim", True), f"{where}.trim")
    collapse = _optional_bool(
        obj.get("collapse_whitespace", False), f"{where}.collapse_whitespace"
    )
    invisible = _optional_str(obj.get("invisible", "keep"), f"{where}.invisible").lower()
    if invisible not in {"keep", "remove"}:
        raise ConfigError(f"{where}.invisible 必须是 keep 或 remove。")

    return TransformSpec(
        normalization=normalization,
        case=case,
        width_fold=width_fold,
        trim=trim,
        collapse_whitespace=collapse,
        invisible=invisible,
    )


def _parse_candidates(item: Any, where: str) -> tuple[TransformSpec, ...]:
    if item is None:
        return ()
    if not isinstance(item, list) or not item:
        raise ConfigError(f"{where} 必须是非空 TransformSpec 数组。")
    candidates: list[TransformSpec] = []
    seen: set[tuple[Any, ...]] = set()
    for index, entry in enumerate(item):
        spec = _parse_transform(entry, f"{where}[{index}]")
        signature = _transform_signature(spec)
        if signature in seen:
            raise ConfigError(f"{where} 含重复候选（索引 {index}）。")
        seen.add(signature)
        candidates.append(spec)
    return tuple(candidates)


def _transform_signature(spec: TransformSpec) -> tuple[Any, ...]:
    return (
        spec.normalization,
        spec.case,
        spec.width_fold,
        spec.trim,
        spec.collapse_whitespace,
        spec.invisible,
    )


def _parse_preflight(
    item: Any,
    keys: list[KeyRule],
    source_by_id: dict[str, SourceSpec],
) -> PreflightSpec | None:
    if item is None:
        return None
    obj = _require_object(item, "preflight")
    _reject_unknown(obj, _PREFLIGHT_FIELDS, "preflight")

    max_combinations = obj.get("max_combinations", 100_000)
    if (
        isinstance(max_combinations, bool)
        or not isinstance(max_combinations, int)
        or max_combinations <= 0
    ):
        raise ConfigError("preflight.max_combinations 必须是正整数。")

    forbid_unauthorized = _optional_bool(
        obj.get("forbid_unauthorized_cross_table", True),
        "preflight.forbid_unauthorized_cross_table",
    )

    source_sha_obj = obj.get("source_sha256", {})
    if not isinstance(source_sha_obj, dict):
        raise ConfigError("preflight.source_sha256 必须是对象。")
    expected_sources: dict[str, str] = {}
    for source_id, digest in source_sha_obj.items():
        if source_id not in source_by_id:
            raise ConfigError(
                f"preflight.source_sha256 引用了不存在的源：{source_id}"
            )
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ConfigError(
                f"preflight.source_sha256.{source_id} 必须是 64 位十六进制 SHA-256。"
            )
        expected_sources[str(source_id)] = digest.lower()

    expected_digest = _optional_str(
        obj.get("source_digest", ""), "preflight.source_digest"
    ).strip().lower()
    if expected_digest and (
        len(expected_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_digest)
    ):
        raise ConfigError(
            "preflight.source_digest 必须是 64 位十六进制 SHA-256。"
        )

    expected_rules = _optional_str(
        obj.get("rules_sha256", ""), "preflight.rules_sha256"
    ).strip().lower()
    if expected_rules and (
        len(expected_rules) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_rules)
    ):
        raise ConfigError(
            "preflight.rules_sha256 必须是 64 位十六进制 SHA-256。"
        )

    rule_map = {key.id: key for key in keys}
    links_obj = obj.get("authorized_links", [])
    if not isinstance(links_obj, list):
        raise ConfigError("preflight.authorized_links 必须是数组。")
    links: list[AuthorizedLink] = []
    seen_link_ids: set[str] = set()
    for index, entry in enumerate(links_obj):
        where = f"preflight.authorized_links[{index}]"
        link_obj = _require_object(entry, where)
        _reject_unknown(link_obj, {"link_id", "left", "right"}, where)
        link_id = _require_id(link_obj.get("link_id"), f"{where}.link_id")
        if link_id in seen_link_ids:
            raise ConfigError(f"{where}.link_id 重复：{link_id}")
        seen_link_ids.add(link_id)
        left = _parse_record_ref(link_obj.get("left"), f"{where}.left", rule_map, source_by_id)
        right = _parse_record_ref(
            link_obj.get("right"), f"{where}.right", rule_map, source_by_id
        )
        if left.rule_id == right.rule_id:
            raise ConfigError(
                f"{where} 两侧必须绑定不同规则（不同目标表）：{left.rule_id}"
            )
        if left.key() == right.key():
            raise ConfigError(f"{where} 两侧不能指向同一记录。")
        links.append(AuthorizedLink(link_id=link_id, left=left, right=right))

    pairs_obj = obj.get("forbidden_pairs", [])
    if not isinstance(pairs_obj, list):
        raise ConfigError("preflight.forbidden_pairs 必须是数组。")
    pairs: list[ForbiddenPair] = []
    seen_pair_ids: set[str] = set()
    for index, entry in enumerate(pairs_obj):
        where = f"preflight.forbidden_pairs[{index}]"
        pair_obj = _require_object(entry, where)
        _reject_unknown(pair_obj, {"pair_id", "left", "right"}, where)
        pair_id = _require_id(pair_obj.get("pair_id"), f"{where}.pair_id")
        if pair_id in seen_pair_ids:
            raise ConfigError(f"{where}.pair_id 重复：{pair_id}")
        seen_pair_ids.add(pair_id)
        left = _parse_record_ref(pair_obj.get("left"), f"{where}.left", rule_map, source_by_id)
        right = _parse_record_ref(
            pair_obj.get("right"), f"{where}.right", rule_map, source_by_id
        )
        if left.rule_id == right.rule_id:
            raise ConfigError(
                f"{where} 必须是跨目标表记录对，两侧规则不能相同：{left.rule_id}"
            )
        pairs.append(ForbiddenPair(pair_id=pair_id, left=left, right=right))

    return PreflightSpec(
        max_combinations=max_combinations,
        authorized_links=tuple(links),
        forbidden_pairs=tuple(pairs),
        forbid_unauthorized_cross_table=forbid_unauthorized,
        expected_sources_sha256=expected_sources,
        expected_source_digest=expected_digest,
        expected_rules_sha256=expected_rules,
    )


def _parse_record_ref(
    item: Any,
    where: str,
    rule_map: dict[str, KeyRule],
    source_by_id: dict[str, SourceSpec],
) -> RecordRef:
    obj = _require_object(item, where)
    _reject_unknown(obj, _REF_FIELDS, where)
    source_id = _require_id(obj.get("source_id"), f"{where}.source_id")
    rule_id = _require_id(obj.get("rule_id"), f"{where}.rule_id")
    record_ref = _require_nonempty_str(obj.get("record_ref"), f"{where}.record_ref")
    if source_id not in source_by_id:
        raise ConfigError(f"{where}.source_id 指向不存在的源：{source_id}")
    rule = rule_map.get(rule_id)
    if rule is None:
        raise ConfigError(f"{where}.rule_id 指向不存在的规则：{rule_id}")
    if rule.source_id != source_id:
        raise ConfigError(
            f"{where}.source_id 与规则 {rule_id} 的源不一致："
            f"{source_id} != {rule.source_id}"
        )
    return RecordRef(source_id=source_id, rule_id=rule_id, record_ref=record_ref)


def _preflight_digest(keys: list[KeyRule], preflight: PreflightSpec) -> str:
    payload = {
        "rules_sha256": rule_summary_digest(keys),
        "selectable_rules": [key.id for key in keys if key.selectable],
        "preflight": preflight.as_dict(),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


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


def _optional_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} 必须是布尔值。")
    return value


def _optional_positive_int(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{where} 必须是正整数或 null。")
    return value


def _require_id(value: Any, where: str) -> str:
    text = _require_nonempty_str(value, where)
    if not _ID_RE.fullmatch(text):
        raise ConfigError(
            f"{where} 只能使用字母、数字、下划线和连字符，且必须以字母或数字开头：{text}"
        )
    return text
