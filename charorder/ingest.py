"""Read-only source ingestion for CSV, JSONL, and SQLite."""

from __future__ import annotations

import codecs
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

# Cap on byte-span evidence kept in findings/notes; totals are always kept.
_MAX_SPAN_EVIDENCE = 50


@dataclass(frozen=True)
class DecodeTaint:
    """Provenance for decoder-inserted U+FFFD replacement characters.

    ``char_indices`` are positions in the decoded text that the decoder
    inserted because of undecodable bytes — never legitimate U+FFFD code
    points that were already encoded in the source. ``byte_spans`` are the
    absolute ``(start, end, reason)`` byte ranges of the original file that
    failed to decode. ``reliable`` is False when the positions could not be
    reproduced exactly; callers must then widen taint to the whole source
    instead of guessing locations.
    """

    replacement_chars: int
    char_indices: frozenset[int]
    byte_spans: tuple[tuple[int, int, str], ...]
    reliable: bool


@dataclass
class DecodeOutcome:
    text: str
    note: dict[str, Any] | None
    defect: Defect | None
    taint: DecodeTaint | None = None


_TRACK_HANDLER = "charorder-replacement-tracker"
_TRACK_STATE: dict[str, Any] = {"spans": None}


def _tracking_error_handler(exc: UnicodeError) -> tuple[str, int]:
    """Mimic the built-in ``replace`` decode handler while recording spans."""

    spans = _TRACK_STATE["spans"]
    if isinstance(exc, UnicodeDecodeError):
        if spans is not None:
            spans.append((exc.start, exc.end, exc.reason))
        return ("�", exc.end)
    raise exc  # pragma: no cover - defensive, decode-only usage


codecs.register_error(_TRACK_HANDLER, _tracking_error_handler)


def _tracking_encoding(encoding: str) -> str:
    """Codec used to reproduce replacement positions with absolute offsets.

    ``utf-8-sig`` reports error-handler offsets relative to the BOM-stripped
    buffer, so tracking is done with plain ``utf-8`` (the BOM then decodes to
    a leading U+FEFF, which is reconciled against the real decode afterwards).
    """

    if encoding.replace("_", "-").lower() in {"utf-8-sig", "utf8-sig"}:
        return "utf-8"
    return encoding


def _collect_error_spans(
    data: bytes, encoding: str
) -> list[tuple[int, int, str]] | None:
    spans: list[tuple[int, int, str]] = []
    _TRACK_STATE["spans"] = spans
    try:
        data.decode(encoding, errors=_TRACK_HANDLER)
    except (UnicodeError, ValueError, LookupError):
        return None
    finally:
        _TRACK_STATE["spans"] = None
    return spans


def _rebuild_with_positions(
    data: bytes, encoding: str, spans: list[tuple[int, int, str]]
) -> tuple[str, frozenset[int]] | None:
    """Rebuild the replaced text, recording each inserted U+FFFD position."""

    parts: list[str] = []
    indices: list[int] = []
    pos = 0
    char_pos = 0
    try:
        for start, end, _reason in spans:
            if start < pos or end <= start:
                return None  # overlapping/degenerate spans: cannot trust
            good = data[pos:start].decode(encoding, errors="strict")
            parts.append(good)
            char_pos += len(good)
            parts.append("�")
            indices.append(char_pos)
            char_pos += 1
            pos = end
        parts.append(data[pos:].decode(encoding, errors="strict"))
    except (UnicodeError, ValueError, LookupError):
        return None
    return "".join(parts), frozenset(indices)


def _measure_taint(data: bytes, encoding: str, text: str) -> DecodeTaint | None:
    """Locate decoder-inserted replacements, or declare tracking unreliable.

    The rebuilt text must equal the real ``errors="replace"`` decode exactly;
    otherwise no positions are trusted and the caller widens taint
    conservatively. Returns None only when no replacement happened at all.
    """

    tracking = _tracking_encoding(encoding)
    spans = _collect_error_spans(data, tracking)
    if not spans:
        return None
    byte_spans = tuple(spans)
    rebuilt = _rebuild_with_positions(data, tracking, spans)
    if rebuilt is not None:
        rebuilt_text, indices = rebuilt
        if rebuilt_text == text:
            return DecodeTaint(
                replacement_chars=len(indices),
                char_indices=indices,
                byte_spans=byte_spans,
                reliable=True,
            )
        if rebuilt_text == "﻿" + text:
            # The spec codec consumed a BOM that the tracking codec kept.
            return DecodeTaint(
                replacement_chars=len(indices),
                char_indices=frozenset(index - 1 for index in indices),
                byte_spans=byte_spans,
                reliable=True,
            )
    return DecodeTaint(
        replacement_chars=text.count("�"),
        char_indices=frozenset(),
        byte_spans=byte_spans,
        reliable=False,
    )


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
        return DecodeOutcome(text=text, note=None, defect=None, taint=None)
    except UnicodeDecodeError as exc:
        if spec.encoding_errors == "strict":
            raise InputError(
                f"源 {spec.id} 无法按 {spec.encoding} 严格解码："
                f"字节偏移 {exc.start}，原因 {exc.reason}。"
                "可将 encoding_errors 改为 replace 以生成风险报告。"
            ) from exc
        text = data.decode(spec.encoding, errors="replace")
        taint = _measure_taint(data, spec.encoding, text)
        if taint is None:  # pragma: no cover - defensive: strict decode failed
            taint = DecodeTaint(
                replacement_chars=text.count("�"),
                char_indices=frozenset(),
                byte_spans=((exc.start, exc.end, exc.reason),),
                reliable=False,
            )
        first_span = taint.byte_spans[0] if taint.byte_spans else (
            exc.start,
            exc.end,
            exc.reason,
        )
        defect = Defect(
            code="SOURCE_INVALID_BYTES",
            severity=config.severity_for("SOURCE_INVALID_BYTES"),
            message=(
                f"源 {spec.id} 含无法按 {spec.encoding} 解码的字节；"
                "已用 U+FFFD 替代后继续预检，受污染键一律标为不确定"
            ),
            details={
                "byte_offset": first_span[0],
                "byte_end": first_span[1],
                "reason": first_span[2],
                "replacement_chars": taint.replacement_chars,
                "encoding": spec.encoding,
                "byte_spans": [
                    {"start": start, "end": end, "reason": reason}
                    for start, end, reason in taint.byte_spans[:_MAX_SPAN_EVIDENCE]
                ],
                "byte_spans_total": len(taint.byte_spans),
                "tracking_reliable": taint.reliable,
            },
        )
        note = {
            "encoding": spec.encoding,
            "valid": False,
            "byte_offset": first_span[0],
            "replacement_chars": taint.replacement_chars,
            "tracking_reliable": taint.reliable,
        }
        return DecodeOutcome(text=text, note=note, defect=defect, taint=taint)
    except LookupError as exc:  # guarded by config, defensive
        raise InputError(f"源 {spec.id} 使用未知编码：{spec.encoding}") from exc


def _strip_bom(text: str, taint: DecodeTaint | None) -> tuple[str, DecodeTaint | None]:
    if not text.startswith("﻿"):
        return text, taint
    text = text[1:]
    if taint is not None and taint.reliable:
        # A BOM is never a decoder-inserted replacement, so index 0 is clean.
        taint = DecodeTaint(
            replacement_chars=taint.replacement_chars,
            char_indices=frozenset(index - 1 for index in taint.char_indices),
            byte_spans=taint.byte_spans,
            reliable=taint.reliable,
        )
    return text, taint


def _load_csv(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text, taint = _strip_bom(decoded.text, decoded.taint)
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)

    stream = io.StringIO(text, newline="")
    try:
        reader = csv.reader(
            stream, delimiter=spec.delimiter, quotechar=spec.quotechar
        )
        header = next(reader, None)
    except csv.Error as exc:
        raise InputError(f"CSV 源 {spec.id} 表头解析失败：{exc}") from exc

    if not header:
        raise InputError(f"CSV 源 {spec.id} 没有表头。")
    columns = [str(name) for name in header]
    header_end = stream.tell()
    needed = _needed_columns(config, spec.id)
    missing = sorted(needed - set(columns))
    if missing:
        raise InputError(
            f"CSV 源 {spec.id} 缺少键规则所需列：{', '.join(missing)}；"
            f"实际列为：{', '.join(columns)}"
        )

    records: list[SourceRecord] = []
    # (record, span_start, span_end, parsed field values) for taint mapping.
    row_spans: list[tuple[SourceRecord, int, int, list[str]]] = []
    try:
        row_start = stream.tell()
        for row in reader:
            row_end = stream.tell()
            line_num = reader.line_num
            if not row:  # blank physical line, skipped like DictReader
                row_start = row_end
                continue
            if len(row) > len(columns):
                issues.append(
                    Defect(
                        code="SOURCE_ROW_MISMATCH",
                        severity=config.severity_for("SOURCE_ROW_MISMATCH"),
                        message=f"CSV 记录列数多于表头，多余值已放入审计详情",
                        details={
                            "row": line_num,
                            "extra_values": [
                                str(value) for value in row[len(columns):]
                            ],
                        },
                    )
                )
            values, defects, value_taint = _coerce_mapping(
                config, spec, dict(zip(columns, row)), line_num
            )
            record = _make_record(
                config,
                spec,
                ordinal=len(records) + 1,
                record_ref=f"row:{line_num}",
                values=values,
                defects=defects,
            )
            if value_taint:
                record.tainted_columns |= value_taint
                record.taint_scope = "field"
            records.append(record)
            row_spans.append((record, row_start, row_end, row))
            row_start = row_end
    except csv.Error as exc:
        issues.append(
            Defect(
                code="SOURCE_PARSE_ERROR",
                severity=config.severity_for("SOURCE_PARSE_ERROR"),
                message=f"CSV 解析中断：{exc}",
                details={"near_row": len(records) + 1},
            )
        )

    taint_note = _apply_csv_taint(spec, text, taint, columns, header_end, row_spans)

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=_merge_taint_note(decoded.note, taint_note),
    )


def _apply_csv_taint(
    spec: SourceSpec,
    text: str,
    taint: DecodeTaint | None,
    columns: list[str],
    header_end: int,
    row_spans: list[tuple[SourceRecord, int, int, list[str]]],
) -> dict[str, Any] | None:
    """Attribute decoder replacements to CSV fields, or widen honestly."""

    if taint is None:
        return None
    base = _taint_note_base(spec, taint)
    if spec.taint_tracking == "conservative":
        _taint_all_records(row_spans, "source")
        base.update(
            scope="source",
            reason="配置 taint_tracking=conservative：发生替换的整个源的键判定均视为不确定",
            affected_records=len(row_spans),
        )
        return base
    if not taint.reliable:
        _taint_all_records(row_spans, "source")
        base.update(
            scope="source",
            reason=(
                f"编码 {spec.encoding} 的替换位置无法逐字节复现"
                "（分段解码与整体解码不一致），污染扩大到整个源；不猜测精准位置"
            ),
            affected_records=len(row_spans),
        )
        return base
    indices = taint.char_indices
    if any(index < header_end for index in indices):
        _taint_all_records(row_spans, "source")
        base.update(
            scope="source",
            reason="CSV 表头含替换字符，列名归属不可靠，污染扩大到整个源",
            affected_records=len(row_spans),
        )
        return base

    affected_columns: set[str] = set()
    affected_records = 0
    widened_records = 0
    for record, start, end, row in row_spans:
        local = [index for index in indices if start <= index < end]
        if not local:
            continue
        affected_records += 1
        fields = _csv_record_fields(
            text, start, end, spec.delimiter, spec.quotechar
        )
        if fields is None or [value for _, _, value in fields] != row:
            # Field boundaries could not be reproduced against the csv parser;
            # widen this record instead of guessing a column.
            record.taint_unknown = True
            record.taint_scope = "record"
            widened_records += 1
            continue
        record_columns: set[str] = set()
        unknown = False
        for index in local:
            owner = _field_owner(fields, index)
            if owner is None or owner >= len(columns):
                # Replacement inside an unnamed extra field: no declared
                # column can be blamed, so the whole record is suspect.
                unknown = True
                break
            record_columns.add(columns[owner])
        if unknown:
            record.taint_unknown = True
            record.taint_scope = "record"
            widened_records += 1
            continue
        record.tainted_columns |= record_columns
        if record.taint_scope == "none":
            record.taint_scope = "field"
        affected_columns.update(record_columns)

    base["affected_records"] = affected_records
    if widened_records:
        base.update(
            scope="record",
            reason=(
                f"{widened_records} 条记录的 CSV 字段边界无法与解析器复核一致，"
                "这些记录的污染扩大到整行；不猜测精准列位置"
            ),
        )
    else:
        base["scope"] = "field"
    if affected_columns:
        base["affected_columns"] = sorted(affected_columns)
    return base


def _taint_all_records(
    row_spans: list[tuple["SourceRecord", int, int, list[str]]] | list["SourceRecord"],
    scope: str,
) -> None:
    for item in row_spans:
        record = item[0] if isinstance(item, tuple) else item
        record.taint_unknown = True
        record.taint_scope = scope


def _field_owner(
    fields: list[tuple[int, int, str]], index: int
) -> int | None:
    for position, (start, end, _value) in enumerate(fields):
        if start <= index < end:
            return position
    return None


def _csv_record_fields(
    text: str, start: int, end: int, delimiter: str, quotechar: str
) -> list[tuple[int, int, str]] | None:
    """Locate field spans inside one CSV record's raw decoded text.

    Mirrors the stdlib csv state machine for the supported dialect knobs
    (delimiter, quotechar, doublequote, no escapechar). The caller verifies
    the extracted values against csv.reader output; any structural surprise
    returns None so taint can be widened to the whole record instead of
    guessing. Byte offsets are never treated as character columns.
    """

    if end > start and text[end - 1] == "\n":
        end -= 1
        if end > start and text[end - 1] == "\r":
            end -= 1
    elif end > start and text[end - 1] == "\r":
        end -= 1

    fields: list[tuple[int, int, str]] = []
    i = start
    while True:
        field_start = i
        parts: list[str] = []
        state = "start"
        while i < end:
            ch = text[i]
            if ch in "\r\n" and state != "quoted":
                return None  # terminator inside a record span: unexpected
            if state == "start":
                if ch == quotechar:
                    state = "quoted"
                    i += 1
                elif ch == delimiter:
                    break
                else:
                    parts.append(ch)
                    state = "unquoted"
                    i += 1
            elif state == "unquoted":
                if ch == delimiter:
                    break
                parts.append(ch)
                i += 1
            elif state == "quoted":
                if ch == quotechar:
                    state = "quote_in_quoted"
                    i += 1
                else:
                    parts.append(ch)
                    i += 1
            else:  # quote_in_quoted
                if ch == quotechar:
                    parts.append(quotechar)
                    state = "quoted"
                    i += 1
                elif ch == delimiter:
                    break
                else:
                    parts.append(ch)
                    state = "unquoted"
                    i += 1
        fields.append((field_start, i, "".join(parts)))
        if i < end and text[i] == delimiter:
            i += 1
            if i >= end:
                fields.append((i, i, ""))  # trailing delimiter → empty field
                break
        else:
            break
    return fields


def _load_jsonl(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text, taint = _strip_bom(decoded.text, decoded.taint)
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)
    records: list[SourceRecord] = []
    columns: list[str] = []
    seen_columns: set[str] = set()

    lines = text.splitlines()
    # Character spans of each physical line, aligned with ``lines`` so a
    # decoder-inserted position maps to exactly one line (never a column).
    line_spans: list[tuple[int, int]] = []
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line_spans.append((offset, offset + len(raw_line)))
        offset += len(raw_line)

    tainted_lines: set[int] = set()
    if taint is not None and taint.reliable:
        for index in taint.char_indices:
            for line_number, (start, end) in enumerate(line_spans, start=1):
                if start <= index < end:
                    tainted_lines.add(line_number)
                    break

    record_lines: list[tuple[SourceRecord, int]] = []
    for line_number, line in enumerate(lines, start=1):
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
        values, defects, value_taint = _coerce_mapping(
            config, spec, obj, line_number, allow_missing=True
        )
        record = _make_record(
            config,
            spec,
            ordinal=len(records) + 1,
            record_ref=f"line:{line_number}",
            values=values,
            defects=defects,
        )
        if value_taint:
            record.tainted_columns |= value_taint
            record.taint_scope = "field"
        records.append(record)
        record_lines.append((record, line_number))

    taint_note = _apply_jsonl_taint(
        spec, taint, tainted_lines, record_lines
    )

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=_merge_taint_note(decoded.note, taint_note),
    )


def _apply_jsonl_taint(
    spec: SourceSpec,
    taint: DecodeTaint | None,
    tainted_lines: set[int],
    record_lines: list[tuple[SourceRecord, int]],
) -> dict[str, Any] | None:
    """Widen JSONL decode taint to whole records (never guessed columns)."""

    if taint is None:
        return None
    base = _taint_note_base(spec, taint)
    if spec.taint_tracking == "conservative":
        for record, _line in record_lines:
            record.taint_unknown = True
            record.taint_scope = "source"
        base.update(
            scope="source",
            reason="配置 taint_tracking=conservative：发生替换的整个源的键判定均视为不确定",
            affected_records=len(record_lines),
        )
        return base
    if not taint.reliable:
        for record, _line in record_lines:
            record.taint_unknown = True
            record.taint_scope = "source"
        base.update(
            scope="source",
            reason=(
                f"编码 {spec.encoding} 的替换位置无法逐字节复现"
                "（分段解码与整体解码不一致），污染扩大到整个源；不猜测精准位置"
            ),
            affected_records=len(record_lines),
        )
        return base
    affected = 0
    for record, line_number in record_lines:
        if line_number in tainted_lines:
            record.taint_unknown = True
            record.taint_scope = "record"
            affected += 1
    base.update(
        scope="record",
        reason=(
            "JSON 字符串转义（\\uXXXX、\\\"）使解码后字符位置无法可靠映射回字段，"
            "污染扩大到整行记录；不猜测字段位置"
        ),
        affected_records=affected,
    )
    return base


def _taint_note_base(spec: SourceSpec, taint: DecodeTaint) -> dict[str, Any]:
    return {
        "tracking": spec.taint_tracking,
        "reliable": taint.reliable,
        "replacement_chars": taint.replacement_chars,
        "byte_spans": [
            {"start": start, "end": end, "reason": reason}
            for start, end, reason in taint.byte_spans[:_MAX_SPAN_EVIDENCE]
        ],
        "byte_spans_total": len(taint.byte_spans),
    }


def _merge_taint_note(
    note: dict[str, Any] | None, taint_note: dict[str, Any] | None
) -> dict[str, Any] | None:
    if taint_note is None:
        return note
    merged = dict(note) if note else {}
    merged["taint"] = taint_note
    return merged


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
                values, defects, value_taint = _coerce_mapping(
                    config, spec, raw_values, len(records) + 1
                )
                record = _make_record(
                    config,
                    spec,
                    ordinal=len(records) + 1,
                    record_ref=f"row:{len(records) + 1}",
                    values=values,
                    defects=defects,
                )
                if value_taint:
                    record.tainted_columns |= value_taint
                    record.taint_scope = "field"
                records.append(record)
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
) -> tuple[dict[str, Any], list[Defect], frozenset[str]]:
    values: dict[str, Any] = {}
    defects: list[Defect] = []
    tainted_columns: set[str] = set()
    for column, value in raw.items():
        converted, defect, tainted = _coerce_value(config, spec, column, value, row_number)
        values[column] = converted
        if defect:
            defects.append(defect)
        if tainted:
            tainted_columns.add(column)
    if not allow_missing:
        for column in _needed_columns(config, spec.id):
            if column not in values:
                values[column] = None
    return values, defects, frozenset(tainted_columns)


def _coerce_value(
    config: AppConfig,
    spec: SourceSpec,
    column: str,
    value: Any,
    row_number: int,
) -> tuple[str | None, Defect | None, bool]:
    if value is None:
        return None, None, False
    if isinstance(value, str):
        return value, None, False
    if isinstance(value, bytes):
        try:
            return value.decode(spec.encoding, errors="strict"), None, False
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
                True,
            )
        except LookupError:
            text = value.decode("utf-8", errors="replace")
            return text, None, False
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
        False,
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
