"""Configuration loading and strict validation."""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .adjudications import load_adjudication_file
from .errors import ConfigError
from .models import (
    DEFAULT_SEVERITIES,
    SEVERITIES,
    AppConfig,
    KeyRule,
    ProjectSpec,
    SourceSpec,
    TargetIndexSpec,
    TransformSpec,
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TOP_LEVEL = {
    "version",
    "project",
    "sources",
    "keys",
    "severity_overrides",
    "reports",
    "target_indexes",
    "adjudications",
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
    "destination",
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
_TARGET_INDEX_FIELDS = {
    "id",
    "label",
    "destination",
    "rules",
    "max_bytes",
    "max_chars",
    "description",
}
_ADJUDICATION_FIELDS = {"index_id", "path"}


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

    target_indexes = _parse_target_indexes(data.get("target_indexes", []), keys)
    adjudication_docs = _parse_adjudications(
        data.get("adjudications", []), config_path.parent, target_indexes
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
        target_indexes=tuple(target_indexes),
        adjudications=tuple(adjudication_docs),
    )


def _parse_target_indexes(item: Any, keys: list[KeyRule]) -> list[TargetIndexSpec]:
    if item is None:
        item = []
    if not isinstance(item, list):
        raise ConfigError("target_indexes 必须是数组。")
    indexes: list[TargetIndexSpec] = []
    seen_index_ids: set[str] = set()
    key_by_id = {key.id: key for key in keys}
    for index_pos, entry in enumerate(item):
        where = f"target_indexes[{index_pos}]"
        obj = _require_object(entry, where)
        _reject_unknown(obj, _TARGET_INDEX_FIELDS, where)
        index_id = _require_id(obj.get("id"), f"{where}.id")
        if index_id in seen_index_ids:
            raise ConfigError(f"{where}.id 重复：{index_id}")
        seen_index_ids.add(index_id)
        label = _require_nonempty_str(obj.get("label"), f"{where}.label")
        destination = _require_nonempty_str(
            obj.get("destination"), f"{where}.destination"
        )
        rules_obj = obj.get("rules")
        if not isinstance(rules_obj, list) or not rules_obj:
            raise ConfigError(f"{where}.rules 必须是非空字符串数组。")
        rule_ids: list[str] = []
        seen_rule_ids: set[str] = set()
        for rule_pos, rule_ref in enumerate(rules_obj):
            rule_id = _require_id(rule_ref, f"{where}.rules[{rule_pos}]")
            if rule_id not in key_by_id:
                raise ConfigError(
                    f"{where}.rules[{rule_pos}] 指向不存在的键规则：{rule_id}"
                )
            if rule_id in seen_rule_ids:
                raise ConfigError(f"{where}.rules 含重复规则：{rule_id}")
            seen_rule_ids.add(rule_id)
            rule = key_by_id[rule_id]
            if rule.destination and rule.destination != destination:
                raise ConfigError(
                    f"{where}.destination 为 {destination}，"
                    f"但规则 {rule_id} 已声明 destination={rule.destination}；"
                    "同一目标唯一索引内的规则必须指向同一目标 destination。"
                )
            rule_ids.append(rule_id)
        if len({key_by_id[rule_id].source_id for rule_id in rule_ids}) < 2:
            raise ConfigError(
                f"{where}.rules 必须显式纳入至少两个不同来源的键规则，"
                "目标索引演练用于跨来源裁决；单来源碰撞请使用逐规则唯一键检查。"
            )
        max_bytes = _optional_positive_int(obj.get("max_bytes"), f"{where}.max_bytes")
        max_chars = _optional_positive_int(obj.get("max_chars"), f"{where}.max_chars")
        description = _optional_str(obj.get("description", ""), f"{where}.description")
        indexes.append(
            TargetIndexSpec(
                id=index_id,
                label=label,
                destination=destination,
                rule_ids=tuple(rule_ids),
                max_bytes=max_bytes,
                max_chars=max_chars,
                description=description,
            )
        )
    return indexes


def _parse_adjudications(
    item: Any, base_dir: Path, target_indexes: list[TargetIndexSpec]
) -> list:
    if item is None:
        item = []
    if not isinstance(item, list):
        raise ConfigError("adjudications 必须是数组。")
    index_ids = {spec.id for spec in target_indexes}
    docs: list = []
    seen_index_refs: set[str] = set()
    for index_pos, entry in enumerate(item):
        where = f"adjudications[{index_pos}]"
        obj = _require_object(entry, where)
        _reject_unknown(obj, _ADJUDICATION_FIELDS, where)
        index_id = _require_id(obj.get("index_id"), f"{where}.index_id")
        if index_id not in index_ids:
            raise ConfigError(
                f"{where}.index_id 指向未在 target_indexes 声明的索引：{index_id}"
            )
        if index_id in seen_index_refs:
            raise ConfigError(f"{where}.index_id 重复：每个目标索引至多一份裁决台账。")
        seen_index_refs.add(index_id)
        path_text = _require_nonempty_str(obj.get("path"), f"{where}.path")
        doc = load_adjudication_file(path_text, base_dir)
        if doc.index_id != index_id:
            raise ConfigError(
                f"{where}.path 的裁决文件 index_id={doc.index_id}，与配置声明 {index_id} 不一致。"
            )
        docs.append(doc)
    return docs


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
    destination = _optional_str(obj.get("destination", ""), f"{where}.destination")
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
