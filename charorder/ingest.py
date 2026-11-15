"""Read-only source ingestion for CSV, JSONL, and SQLite."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .errors import InputError
from .models import AppConfig, Defect, SourceLoad, SourceRecord, SourceSpec

try:
    csv.field_size_limit(64 * 1024 * 1024)
except (OverflowError, ValueError):  # pragma: no cover - platform dependent
    pass


@dataclass
class DecodeOutcome:
    text: str
    note: dict[str, Any] | None
    defect: Defect | None


def load_sources(config: AppConfig) -> list[SourceLoad]:
    loads: list[SourceLoad] = []
    for spec in config.sources:
        try:
            data = spec.path.read_bytes()
        except OSError as exc:
            raise InputError(f"无法读取源 {spec.id}：{spec.path}（{exc}）") from exc
        digest = hashlib.sha256(data).hexdigest()
        if spec.kind == "csv":
            load = _load_csv(config, spec, data, digest)
        elif spec.kind == "jsonl":
            load = _load_jsonl(config, spec, data, digest)
        elif spec.kind == "sqlite":
            load = _load_sqlite(config, spec, data, digest)
        else:  # guarded by config validation
            raise InputError(f"不支持的源类型：{spec.kind}")
        loads.append(load)
    return loads


def _decode_bytes(config: AppConfig, spec: SourceSpec, data: bytes) -> DecodeOutcome:
    try:
        text = data.decode(spec.encoding, errors="strict")
        return DecodeOutcome(text=text, note=None, defect=None)
    except UnicodeDecodeError as exc:
        if spec.encoding_errors == "strict":
            raise InputError(
                f"源 {spec.id} 无法按 {spec.encoding} 严格解码："
                f"字节偏移 {exc.start}，原因 {exc.reason}。"
                "可将 encoding_errors 改为 replace 以生成风险报告。"
            ) from exc
        text = data.decode(spec.encoding, errors="replace")
        defect = Defect(
            code="SOURCE_INVALID_BYTES",
            severity=config.severity_for("SOURCE_INVALID_BYTES"),
            message=(
                f"源 {spec.id} 含无法按 {spec.encoding} 解码的字节；"
                "已用 U+FFFD 替代后继续预检"
            ),
            details={
                "byte_offset": exc.start,
                "byte_end": exc.end,
                "reason": exc.reason,
                "replacement_chars": text.count("�"),
                "encoding": spec.encoding,
            },
        )
        note = {
            "encoding": spec.encoding,
            "valid": False,
            "byte_offset": exc.start,
            "replacement_chars": text.count("�"),
        }
        return DecodeOutcome(text=text, note=note, defect=defect)
    except LookupError as exc:  # guarded by config, defensive
        raise InputError(f"源 {spec.id} 使用未知编码：{spec.encoding}") from exc


def _load_csv(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text = decoded.text
    if text.startswith("﻿"):
        text = text[1:]
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)

    stream = io.StringIO(text, newline="")
    try:
        reader = csv.DictReader(
            stream, delimiter=spec.delimiter, quotechar=spec.quotechar
        )
        fieldnames = reader.fieldnames
    except csv.Error as exc:
        raise InputError(f"CSV 源 {spec.id} 表头解析失败：{exc}") from exc

    if not fieldnames:
        raise InputError(f"CSV 源 {spec.id} 没有表头。")
    columns = [str(name) for name in fieldnames]
    needed = _needed_columns(config, spec.id)
    missing = sorted(needed - set(columns))
    if missing:
        raise InputError(
            f"CSV 源 {spec.id} 缺少键规则所需列：{', '.join(missing)}；"
            f"实际列为：{', '.join(columns)}"
        )

    records: list[SourceRecord] = []
    try:
        for row in reader:
            extra_values = row.get(None)
            if extra_values:
                issues.append(
                    Defect(
                        code="SOURCE_ROW_MISMATCH",
                        severity=config.severity_for("SOURCE_ROW_MISMATCH"),
                        message=f"CSV 记录列数多于表头，多余值已放入审计详情",
                        details={
                            "row": reader.line_num,
                            "extra_values": [str(value) for value in extra_values],
                        },
                    )
                )
            values, defects = _coerce_mapping(
                config, spec, {name: row.get(name) for name in columns}, reader.line_num
            )
            record = _make_record(
                config,
                spec,
                ordinal=len(records) + 1,
                record_ref=f"row:{reader.line_num}",
                values=values,
                defects=defects,
            )
            records.append(record)
    except csv.Error as exc:
        issues.append(
            Defect(
                code="SOURCE_PARSE_ERROR",
                severity=config.severity_for("SOURCE_PARSE_ERROR"),
                message=f"CSV 解析中断：{exc}",
                details={"near_row": len(records) + 1},
            )
        )

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=decoded.note,
    )


def _load_jsonl(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text = decoded.text
    if text.startswith("﻿"):
        text = text[1:]
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)
    records: list[SourceRecord] = []
    columns: list[str] = []
    seen_columns: set[str] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(
                Defect(
                    code="SOURCE_PARSE_ERROR",
                    severity=config.severity_for("SOURCE_PARSE_ERROR"),
                    message=f"JSONL 第 {line_number} 行解析失败：{exc.msg}",
                    details={
                        "line": line_number,
                        "column": exc.colno,
                        "reason": exc.msg,
                    },
                )
            )
            continue
        if not isinstance(obj, dict):
            issues.append(
                Defect(
                    code="SOURCE_PARSE_ERROR",
                    severity=config.severity_for("SOURCE_PARSE_ERROR"),
                    message=f"JSONL 第 {line_number} 行不是 JSON 对象",
                    details={"line": line_number, "actual_type": type(obj).__name__},
                )
            )
            continue
        for key in obj:
            if key not in seen_columns:
                seen_columns.add(key)
                columns.append(key)
        values, defects = _coerce_mapping(
            config, spec, obj, line_number, allow_missing=True
        )
        records.append(
            _make_record(
                config,
                spec,
                ordinal=len(records) + 1,
                record_ref=f"line:{line_number}",
                values=values,
                defects=defects,
            )
        )

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=decoded.note,
    )


def _load_sqlite(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    assert spec.table is not None
    uri = spec.path.as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise InputError(f"无法以只读方式打开 SQLite 源 {spec.id}：{exc}") from exc
    try:
        connection.row_factory = sqlite3.Row
        connection.text_factory = bytes
        connection.execute("PRAGMA query_only = ON")
        table_row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name = ?",
            (spec.table,),
        ).fetchone()
        if table_row is None:
            raise InputError(f"SQLite 源 {spec.id} 不存在表或视图：{spec.table}")
        table_name = _metadata_text(table_row[0])
        pragma_rows = connection.execute(
            f"PRAGMA table_info({_quote_identifier(table_name)})"
        ).fetchall()
        if not pragma_rows:
            raise InputError(f"SQLite 源 {spec.id} 无法读取表结构：{spec.table}")
        columns = [_metadata_text(row["name"]) for row in pragma_rows]
        needed = _needed_columns(config, spec.id)
        missing = sorted(needed - set(columns))
        if missing:
            raise InputError(
                f"SQLite 源 {spec.id} 缺少键规则所需列：{', '.join(missing)}；"
                f"实际列为：{', '.join(columns)}"
            )
        select_columns = [column for column in columns if column in needed]
        # Always include record_id first where possible for readable audit data.
        if spec.record_id_field in select_columns:
            select_columns.remove(spec.record_id_field)
            select_columns.insert(0, spec.record_id_field)
        else:  # needed set should have made this unreachable
            raise InputError(f"SQLite 源 {spec.id} 缺少记录标识列：{spec.record_id_field}")
        select_sql = ", ".join(_quote_identifier(column) for column in select_columns)
        query = f"SELECT {select_sql} FROM {_quote_identifier(table_name)}"
        issues: list[Defect] = []
        records: list[SourceRecord] = []
        try:
            cursor = connection.execute(query)
            for row in cursor:
                raw_values = {
                    column: row[column]
                    for column in select_columns
                }
                values, defects = _coerce_mapping(
                    config, spec, raw_values, len(records) + 1
                )
                records.append(
                    _make_record(
                        config,
                        spec,
                        ordinal=len(records) + 1,
                        record_ref=f"row:{len(records) + 1}",
                        values=values,
                        defects=defects,
                    )
                )
        except sqlite3.Error as exc:
            raise InputError(
                f"SQLite 源 {spec.id} 查询失败（{spec.table}）：{exc}"
            ) from exc
    finally:
        connection.close()

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note={
            "encoding": "utf-8",
            "valid": True,
            "sqlite_read_only": True,
        },
    )


def _needed_columns(config: AppConfig, source_id: str) -> set[str]:
    spec = config.source_map[source_id]
    needed = {spec.record_id_field}
    for key in config.keys:
        if key.source_id == source_id:
            needed.update(key.columns)
    return needed


def _coerce_mapping(
    config: AppConfig,
    spec: SourceSpec,
    raw: dict[str, Any],
    row_number: int,
    *,
    allow_missing: bool = False,
) -> tuple[dict[str, Any], list[Defect]]:
    values: dict[str, Any] = {}
    defects: list[Defect] = []
    for column, value in raw.items():
        converted, defect = _coerce_value(config, spec, column, value, row_number)
        values[column] = converted
        if defect:
            defects.append(defect)
    if not allow_missing:
        for column in _needed_columns(config, spec.id):
            if column not in values:
                values[column] = None
    return values, defects


def _coerce_value(
    config: AppConfig,
    spec: SourceSpec,
    column: str,
    value: Any,
    row_number: int,
) -> tuple[str | None, Defect | None]:
    if value is None:
        return None, None
    if isinstance(value, str):
        return value, None
    if isinstance(value, bytes):
        try:
            return value.decode(spec.encoding, errors="strict"), None
        except UnicodeDecodeError:
            text = value.decode(spec.encoding, errors="replace")
            return (
                text,
                Defect(
                    code="REPLACEMENT_CHARACTER",
                    severity=config.severity_for("REPLACEMENT_CHARACTER"),
                    message=f"列 {column} 的字节值无法严格解码，已替换为 U+FFFD",
                    details={"row": row_number, "column": column},
                    column=column,
                ),
            )
        except LookupError:
            text = value.decode("utf-8", errors="replace")
            return text, None
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, (int, float)):
        rendered = str(value)
    elif isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        rendered = str(value)
    return (
        rendered,
        Defect(
            code="NON_TEXT_VALUE",
            severity=config.severity_for("NON_TEXT_VALUE"),
            message=f"列 {column} 的原值不是文本，预检时将按字符串 {type(value).__name__} 转写",
            details={
                "row": row_number,
                "column": column,
                "source_type": type(value).__name__,
            },
            column=column,
        ),
    )


def _make_record(
    config: AppConfig,
    spec: SourceSpec,
    *,
    ordinal: int,
    record_ref: str,
    values: dict[str, Any],
    defects: list[Defect],
) -> SourceRecord:
    record_id = values.get(spec.record_id_field)
    record_id_text = str(record_id).strip() if record_id is not None else ""
    if not record_id_text:
        defects.append(
            Defect(
                code="MISSING_RECORD_ID",
                severity=config.severity_for("MISSING_RECORD_ID"),
                message=f"记录标识列 {spec.record_id_field} 为空；仍按 {record_ref} 审计",
                details={"record_ref": record_ref, "field": spec.record_id_field},
                column=spec.record_id_field,
            )
        )
        record_id_value: str | None = None
    else:
        record_id_value = record_id_text
    return SourceRecord(
        source_id=spec.id,
        ordinal=ordinal,
        record_ref=record_ref,
        record_id=record_id_value,
        values=values,
        defects=defects,
    )


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _metadata_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
