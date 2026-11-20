"""Read-only source ingestion for CSV, JSONL, and SQLite.

The decoder is allowed to repair illegal bytes with U+FFFD so a preflight run
can still produce a risk report.  A repaired byte is *not* source evidence,
though: it must never silently become a trustworthy target key.  This module
therefore records where every replacement was inserted and propagates that
provenance down to the affected records, fields and (later) key rules.

Two attribution strategies are supported, both safe:

* ``field`` (default) - localize replacement characters to the exact field
  for encodings and formats where the mapping is provable (UTF-8 CSV/JSONL).
  Any failure to prove the location widens the scope to the whole record or
  the whole source and records the reason; the code never guesses a position.
* ``whole_source`` - treat every key built from a source with repairs as
  uncertain.  This is the conservative route and is always available.

The raw bytes are hashed before any decoding, so fingerprints keep binding to
the original file.
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import io
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import InputError
from .models import AppConfig, Defect, SourceLoad, SourceRecord, SourceSpec

try:
    csv.field_size_limit(64 * 1024 * 1024)
except (OverflowError, ValueError):  # pragma: no cover - platform dependent
    pass

REPLACEMENT_CHARACTER = "�"

# Codecs for which a byte offset can be proven to map back to a character
# offset (stateless, ASCII-transparent UTF-8 family).
_PRECISE_CODECS = {"utf-8", "utf-8-sig"}

# Line boundaries recognised by ``str.splitlines``.  Longest sequences first.
_LINE_BREAKS = (
    "\r\n",
    "\n",
    "\r",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    " ",
    " ",
)


@dataclass(frozen=True)
class DecodeErrorSpan:
    """One illegal byte sequence repaired by the decoder.

    ``char_start``/``char_end`` are offsets into the decoded text *after* BOM
    removal.  They are -1 when the mapping could not be proven.
    """

    byte_start: int
    byte_end: int
    char_start: int
    char_end: int
    replacement: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "replacement": self.replacement,
            "reason": self.reason,
        }


@dataclass
class DecodeOutcome:
    text: str
    note: dict[str, Any] | None
    defect: Defect | None
    inserted_chars: int = 0
    literal_chars: int = 0
    spans: list[DecodeErrorSpan] = field(default_factory=list)
    precise: bool = False
    precise_reason: str = ""
    bom_chars: int = 0


@dataclass
class _CsvRow:
    fields: list[tuple[int, int]]
    start: int
    end: int


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


# ---------------------------------------------------------------------------
# Decoding with provenance
# ---------------------------------------------------------------------------


def _strip_bom(text: str) -> tuple[str, int]:
    if text.startswith("﻿"):
        return text[1:], 1
    return text, 0


def _decode_bytes(config: AppConfig, spec: SourceSpec, data: bytes) -> DecodeOutcome:
    try:
        text = data.decode(spec.encoding, errors="strict")
        text, bom = _strip_bom(text)
        return DecodeOutcome(
            text=text,
            note={
                "encoding": spec.encoding,
                "valid": True,
                "literal_replacement_chars": text.count(REPLACEMENT_CHARACTER),
                "inserted_replacement_chars": 0,
                "invalid_sequence_count": 0,
                "bom_chars": bom,
            },
            defect=None,
            literal_chars=text.count(REPLACEMENT_CHARACTER),
            bom_chars=bom,
        )
    except UnicodeDecodeError as exc:
        if spec.encoding_errors == "strict":
            raise InputError(
                f"源 {spec.id} 无法按 {spec.encoding} 严格解码："
                f"字节偏移 {exc.start}，原因 {exc.reason}。"
                "可将 encoding_errors 改为 replace 以生成风险报告。"
            ) from exc
        return _decode_with_attribution(config, spec, data, exc)
    except LookupError as exc:  # guarded by config, defensive
        raise InputError(f"源 {spec.id} 使用未知编码：{spec.encoding}") from exc


def _decode_with_attribution(
    config: AppConfig, spec: SourceSpec, data: bytes, first_error: UnicodeDecodeError
) -> DecodeOutcome:
    codec_name = codecs.lookup(spec.encoding).name
    base_codec = "utf-8" if codec_name in _PRECISE_CODECS else None

    raw_spans: list[dict[str, Any]] = []
    # ``codecs.register_error`` has no unregister API.  Reuse one process-wide
    # private handler name and rebind it per call; this keeps the global error
    # registry bounded and the tool remains single-threaded per run.
    handler_name = "charorder-decode-attribution"
    state: dict[str, Any] = {"spans": raw_spans}

    def _capture(exc: UnicodeDecodeError) -> tuple[str, int]:
        replacement, new_pos = codecs.lookup_error("replace")(exc)
        state["spans"].append(
            {
                "byte_start": exc.start,
                "byte_end": exc.end,
                "new_pos": new_pos,
                "replacement": replacement,
                "reason": exc.reason,
            }
        )
        return replacement, new_pos

    codecs.register_error(handler_name, _capture)
    if base_codec is not None:
        decoded_raw = data.decode(base_codec, errors=handler_name)
    else:
        decoded_raw = data.decode(spec.encoding, errors="replace")
        # Enumerate byte offsets for the audit trail; character positions stay
        # unknown because the mapping is not provable for this codec.
        try:
            data.decode(spec.encoding, errors=handler_name)
        except Exception:  # pragma: no cover - defensive
            pass
        raw_spans = state["spans"]

    text, bom = _strip_bom(decoded_raw)
    precise = base_codec is not None
    precise_reason = "" if precise else f"编码 {spec.encoding} 无法证明字节偏移到字段的映射"

    spans: list[DecodeErrorSpan] = []
    if precise:
        char_in_raw = 0
        byte_cursor = 0
        pieces: list[bytes | str] = []
        for raw in raw_spans:
            try:
                prefix = data[byte_cursor : raw["byte_start"]].decode(
                    base_codec, errors="strict"
                )
            except UnicodeDecodeError:
                precise = False
                precise_reason = "无法重建非法字节之前的字符位置"
                break
            char_in_raw += len(prefix)
            pieces.append(prefix)
            char_start = char_in_raw - bom
            replacement = raw["replacement"]
            pieces.append(replacement)
            spans.append(
                DecodeErrorSpan(
                    byte_start=raw["byte_start"],
                    byte_end=raw["byte_end"],
                    char_start=max(0, char_start),
                    char_end=max(0, char_start + len(replacement)),
                    replacement=replacement,
                    reason=raw["reason"],
                )
            )
            char_in_raw += len(replacement)
            byte_cursor = raw["new_pos"]
        if precise:
            try:
                tail = data[byte_cursor:].decode(base_codec, errors="strict")
            except UnicodeDecodeError:
                precise = False
                precise_reason = "无法重建非法字节之后的字符位置"
            else:
                pieces.append(tail)
                rebuilt = "".join(pieces)
                if rebuilt != decoded_raw:
                    # Positions cannot be trusted if the reconstruction does
                    # not reproduce the decoder output exactly.
                    precise = False
                    precise_reason = "字符位置重建结果与解码输出不一致"

    inserted = len(raw_spans)
    literal = max(0, decoded_raw.count(REPLACEMENT_CHARACTER) - inserted)
    if precise and len(spans) != inserted:
        precise = False
        precise_reason = "非法字节序列数量与字符映射数量不一致"
    if not precise:
        spans = [
            DecodeErrorSpan(
                byte_start=raw["byte_start"],
                byte_end=raw["byte_end"],
                char_start=-1,
                char_end=-1,
                replacement=raw["replacement"],
                reason=raw["reason"],
            )
            for raw in raw_spans
        ]

    mapping = "char_exact" if precise else "whole_source"
    sequence_details = [span.to_dict() for span in spans[:100]]
    defect = Defect(
        code="SOURCE_INVALID_BYTES",
        severity=config.severity_for("SOURCE_INVALID_BYTES"),
        message=(
            f"源 {spec.id} 含 {inserted} 个无法按 {spec.encoding} 解码的字节序列；"
            f"已用 U+FFFD 替代后继续预检，"
            + (
                "受影响字段已标记为不确定"
                if precise
                else "无法精确定位，整源键证据按不确定处理"
            )
        ),
        details={
            "byte_offset": first_error.start,
            "byte_end": first_error.end,
            "reason": first_error.reason,
            "replacement_chars": inserted,
            "literal_replacement_chars": literal,
            "invalid_sequence_count": inserted,
            "invalid_sequences": sequence_details,
            "truncated_sequences": max(0, inserted - len(sequence_details)),
            "encoding": spec.encoding,
            "mapping": mapping,
            "mapping_note": precise_reason
            or "字节偏移已映射为字符位置，用于字段级污染追踪",
        },
    )
    note = {
        "encoding": spec.encoding,
        "valid": False,
        "byte_offset": first_error.start,
        "byte_end": first_error.end,
        "replacement_chars": inserted,
        "literal_replacement_chars": literal,
        "inserted_replacement_chars": inserted,
        "invalid_sequence_count": inserted,
        "invalid_sequences": sequence_details,
        "mapping": mapping,
        "mapping_note": precise_reason,
        "bom_chars": bom,
    }
    return DecodeOutcome(
        text=text,
        note=note,
        defect=defect,
        inserted_chars=inserted,
        literal_chars=literal,
        spans=spans,
        precise=precise,
        precise_reason=precise_reason,
        bom_chars=bom,
    )


# ---------------------------------------------------------------------------
# Simple CSV field-span parser (mirrors csv.reader for span purposes only)
# ---------------------------------------------------------------------------


def _csv_row_spans(
    text: str, delimiter: str, quotechar: str
) -> list[_CsvRow] | None:
    """Return raw character spans for every CSV row/field.

    The parser intentionally mirrors the stdlib reader's lenient behaviour so
    spans line up with parsed rows.  The caller validates alignment against
    ``csv.reader`` and falls back to whole-source attribution on any mismatch.
    """

    if delimiter in "\r\n" or quotechar in "\r\n" or delimiter == quotechar:
        return None

    rows: list[_CsvRow] = []
    length = len(text)
    index = 0
    while index < length:
        row_start = index
        # Blank physical line: the stdlib reader yields an empty row.
        if text[index] in "\r\n":
            if text[index] == "\r" and index + 1 < length and text[index + 1] == "\n":
                index += 2
            else:
                index += 1
            rows.append(_CsvRow(fields=[], start=row_start, end=index))
            continue

        fields: list[tuple[int, int]] = []
        while True:
            field_start = index
            if index < length and text[index] == quotechar:
                index += 1
                while index < length:
                    char = text[index]
                    if char == quotechar:
                        if index + 1 < length and text[index + 1] == quotechar:
                            index += 2
                            continue
                        index += 1
                        break
                    index += 1
                # The stdlib reader appends trailing unquoted characters.
                while index < length and text[index] not in (delimiter, "\r", "\n"):
                    index += 1
            else:
                while index < length and text[index] not in (delimiter, "\r", "\n"):
                    index += 1
            fields.append((field_start, index))
            if index < length and text[index] == delimiter:
                index += 1
                continue
            break

        if index < length:
            if text[index] == "\r":
                index += 1
                if index < length and text[index] == "\n":
                    index += 1
            elif text[index] == "\n":
                index += 1
        rows.append(_CsvRow(fields=fields, start=row_start, end=index))
    return rows


def _row_for_offset(rows: list[_CsvRow], char_offset: int) -> int | None:
    for index, row in enumerate(rows):
        if row.start <= char_offset < row.end:
            return index
        if row.start > char_offset:
            return None
    return None


def _field_for_offset(row: _CsvRow, char_offset: int) -> int | None:
    for index, (start, end) in enumerate(row.fields):
        if start <= char_offset < end:
            return index
    return None


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------


def _iter_lines_with_offsets(text: str) -> Iterable[tuple[int, int, str]]:
    """Yield ``(line_number, start_offset, content)`` matching ``splitlines``."""

    offset = 0
    number = 0
    for chunk in text.splitlines(keepends=True):
        number += 1
        content = chunk
        for break_sequence in _LINE_BREAKS:
            if content.endswith(break_sequence):
                content = content[: -len(break_sequence)]
                break
        yield number, offset, content
        offset += len(chunk)


@dataclass
class _JsonSpans:
    key_spans: list[tuple[int, int]]
    value_spans: dict[str, tuple[int, int, Any]]


def _json_object_spans(line: str) -> _JsonSpans | None:
    """Map top-level JSON object member names to their raw value spans.

    Returns ``None`` when the scanner cannot prove the structure; callers then
    widen contamination to the whole record rather than guessing.
    """

    decoder = json.JSONDecoder()
    length = len(line)
    index = 0

    def skip_space(position: int) -> int:
        while position < length and line[position] in " \t\r\n":
            position += 1
        return position

    index = skip_space(index)
    if index >= length or line[index] != "{":
        return None
    index += 1
    key_spans: list[tuple[int, int]] = []
    value_spans: dict[str, tuple[int, int, Any]] = {}
    while True:
        index = skip_space(index)
        if index >= length:
            return None
        if line[index] == "}":
            index += 1
            break
        try:
            key, key_end = decoder.raw_decode(line, index)
        except ValueError:
            return None
        if not isinstance(key, str):
            return None
        key_spans.append((index, key_end))
        index = skip_space(key_end)
        if index >= length or line[index] != ":":
            return None
        index = skip_space(index + 1)
        try:
            value, value_end = decoder.raw_decode(line, index)
        except ValueError:
            return None
        # json.loads keeps the last occurrence of a duplicate key.
        value_spans[key] = (index, value_end, value)
        index = skip_space(value_end)
        if index >= length:
            return None
        if line[index] == ",":
            index += 1
            continue
        if line[index] == "}":
            index += 1
            break
        return None
    if skip_space(index) != length:
        return None
    return _JsonSpans(key_spans=key_spans, value_spans=value_spans)


# ---------------------------------------------------------------------------
# Conservative / precise contamination application
# ---------------------------------------------------------------------------


def _mark_column(
    record: SourceRecord,
    column: str,
    *,
    inserted: int = 0,
    literal: int = 0,
) -> None:
    if inserted:
        record.contaminated_columns.add(column)
    if inserted or literal or column in record.contamination_origins:
        origin = record.contamination_origins.setdefault(
            column, {"inserted": 0, "literal": 0}
        )
        origin["inserted"] += inserted
        origin["literal"] += literal


def _widen_whole_source(
    load: SourceLoad, records: Iterable[SourceRecord], reason: str
) -> None:
    load.contamination_scope = "whole_source"
    load.contamination_reasons.append(reason)
    columns = set(load.columns)
    load.contaminated_columns = set(columns)
    for record in records:
        record.contaminated_columns = set(columns)
        record.contamination_reasons.append(reason)
        # Unknown inserted/literal split: mark as present via ``None`` (unknown)
        # so reports never claim a clean count.
        for column in columns:
            record.contamination_origins.setdefault(
                column, {"inserted": None, "literal": None}  # type: ignore[dict-item]
            )


def _widen_record(
    record: SourceRecord, columns: Iterable[str], reason: str
) -> None:
    record.contamination_reasons.append(reason)
    for column in columns:
        record.contaminated_columns.add(column)
        record.contamination_origins.setdefault(
            column, {"inserted": None, "literal": None}  # type: ignore[dict-item]
        )


def _finalize_contamination(
    load: SourceLoad,
    *,
    precise: bool,
    reasons: list[str],
    scope_hint: str,
) -> None:
    """Populate source-level aggregates from per-record provenance."""

    if not any(record.contaminated_columns for record in load.records):
        load.contaminated_columns = set()
        load.contamination_scope = "none"
        # Keep explanatory reasons (e.g. a damaged line that failed to parse
        # and produced no record/key evidence at all).
        load.contamination_reasons = list(dict.fromkeys(reasons))
        load.record_contamination = [set() for _ in load.records]
        return
    load.contaminated_columns = set().union(
        *(record.contaminated_columns for record in load.records)
    )
    load.record_contamination = [
        set(record.contaminated_columns) for record in load.records
    ]
    record_reasons = [
        reason for record in load.records for reason in record.contamination_reasons
    ]
    load.contamination_reasons = list(
        dict.fromkeys([*reasons, *record_reasons])
    )
    if (
        load.contamination_scope == "whole_source"
        or "whole_source" in scope_hint
        or not precise
    ):
        load.contamination_scope = "whole_source"
    elif record_reasons:
        load.contamination_scope = "record"
    else:
        load.contamination_scope = "field"
    if load.contamination_scope == "whole_source":
        # A whole-source scope must actually cover every column of every record.
        if load.contaminated_columns != set(load.columns) or any(
            record.contaminated_columns != set(load.columns)
            for record in load.records
        ):
            _widen_whole_source(
                load, load.records, "污染范围升级为整源，所有字段按不确定处理"
            )
            load.record_contamination = [
                set(record.contaminated_columns) for record in load.records
            ]


def _csv_contamination(
    load: SourceLoad,
    decoded: DecodeOutcome,
    text: str,
    span_rows: list[_CsvRow],
    csv_rows: list[tuple[list[str], int]],
    data_positions: list[int],
    records: list[SourceRecord],
    header: list[str],
) -> None:
    if decoded.inserted_chars == 0:
        return
    if not decoded.precise:
        _widen_whole_source(
            load,
            records,
            decoded.precise_reason or "CSV 字段位置无法由解码偏移证明",
        )
        return
    if len(span_rows) != len(csv_rows):
        _widen_whole_source(load, records, "CSV 行跨度与标准解析器不一致")
        return
    for index, (parsed, _line_number) in enumerate(csv_rows):
        if len(span_rows[index].fields) != len(parsed):
            _widen_whole_source(load, records, "CSV 字段跨度与标准解析器不一致")
            return
    if len(data_positions) != len(records):
        _widen_whole_source(load, records, "CSV 记录与行跨度无法一一对应")
        return
    record_for_row = {
        row_index: record for row_index, record in zip(data_positions, records)
    }
    inserted_per_field: dict[tuple[int, int], int] = {}

    for span in decoded.spans:
        if span.char_start < 0:
            _widen_whole_source(load, records, "解码偏移缺少字符位置")
            return
        row_index = _row_for_offset(span_rows, span.char_start)
        if row_index is None:
            _widen_whole_source(load, records, "非法字节落在任何记录之外")
            return
        if row_index == 0:
            _widen_whole_source(load, records, "CSV 表头含解码替换字符，列身份不可靠")
            return
        record = record_for_row.get(row_index)
        if record is None:
            # A span inside a skipped/blank row cannot affect key columns.
            continue
        field_index = _field_for_offset(span_rows[row_index], span.char_start)
        if field_index is None:
            _widen_record(record, header, "非法字节落在 CSV 字段边界，记录整体不确定")
            continue
        if field_index >= len(header):
            # Extra (restkey) values never feed declared key columns.
            continue
        _mark_column(record, header[field_index], inserted=1)
        key = (row_index, field_index)
        inserted_per_field[key] = inserted_per_field.get(key, 0) + 1

    # Legal U+FFFD already present in the source: raw count minus repairs.
    for row_index, record in record_for_row.items():
        row = span_rows[row_index]
        for field_index, (start, end) in enumerate(row.fields):
            if field_index >= len(header):
                continue
            raw_literal = text[start:end].count(REPLACEMENT_CHARACTER)
            repaired = inserted_per_field.get((row_index, field_index), 0)
            literal = max(0, raw_literal - repaired)
            if literal:
                _mark_column(record, header[field_index], literal=literal)


def _jsonl_contamination(
    load: SourceLoad,
    decoded: DecodeOutcome,
    lines: list[tuple[int, int, str]],
    parsed_objects: dict[int, dict[str, Any]],
    records: list[SourceRecord],
) -> None:
    if decoded.inserted_chars == 0:
        return
    if not decoded.precise:
        _widen_whole_source(
            load, records, decoded.precise_reason or "JSONL 位置无法由解码偏移证明"
        )
        return

    record_by_line = {_record_line(record): record for record in records}
    for span in decoded.spans:
        if span.char_start < 0:
            _widen_whole_source(load, records, "解码偏移缺少字符位置")
            return
        target = None
        for number, start, content in lines:
            if start <= span.char_start < start + len(content):
                target = (number, start, content)
                break
        if target is None:
            _widen_whole_source(load, records, "非法字节落在 JSONL 行边界之外")
            return
        number, start, content = target
        if not content.strip():
            continue
        obj = parsed_objects.get(number)
        if obj is None:
            # The affected line did not yield a record (parse error is high).
            load.contamination_reasons.append(
                f"第 {number} 行的非法字节伴随解析失败，未产生键证据"
            )
            continue
        record = record_by_line.get(number)
        if record is None:  # defensive
            _widen_whole_source(load, records, "JSONL 行无法对应记录")
            return
        spans = _json_object_spans(content)
        if spans is None:
            _widen_record(
                record,
                obj.keys(),
                f"第 {number} 行 JSON 结构无法证明，整行字段按不确定处理",
            )
            continue
        local = span.char_start - start
        if any(key_start <= local < key_end for key_start, key_end in spans.key_spans):
            _widen_whole_source(
                load, records, f"第 {number} 行的 JSON 键名含解码替换字符，列身份不可靠"
            )
            return
        matched = None
        for key, (value_start, value_end, value) in spans.value_spans.items():
            if value_start <= local < value_end:
                matched = (key, value)
                break
        if matched is None:
            _widen_record(
                record,
                obj.keys(),
                f"第 {number} 行的非法字节落在 JSON 结构位置，整行字段按不确定处理",
            )
            continue
        key, value = matched
        if not isinstance(value, str):
            _widen_record(
                record,
                obj.keys(),
                f"第 {number} 行第 {key} 列非文本值含非法字节，整行字段按不确定处理",
            )
            continue
        _mark_column(record, key, inserted=1)

    # Distinguish legal U+FFFD already present in the original text.  Values
    # that were widened to "unknown" keep their literal count unknown too.
    for record in records:
        for column, origin in record.contamination_origins.items():
            inserted = origin.get("inserted")
            if inserted is None:
                continue
            recorded = origin.get("literal") or 0
            value = record.values.get(column)
            if isinstance(value, str) and value.count(REPLACEMENT_CHARACTER) > inserted:
                origin["literal"] = (
                    value.count(REPLACEMENT_CHARACTER) - inserted + recorded
                )


def _record_line(record: SourceRecord) -> int:
    prefix, _, value = record.record_ref.partition(":")
    try:
        return int(value) if prefix == "line" else -1
    except ValueError:
        return -1


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------


def _load_csv(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text = decoded.text
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)

    stream = io.StringIO(text, newline="")
    reader = csv.reader(stream, delimiter=spec.delimiter, quotechar=spec.quotechar)
    csv_rows: list[tuple[list[str], int]] = []
    parse_error: csv.Error | None = None
    try:
        for row in reader:
            csv_rows.append((row, reader.line_num))
    except csv.Error as exc:
        parse_error = exc

    header = csv_rows[0][0] if csv_rows else None
    if not header:
        raise InputError(f"CSV 源 {spec.id} 没有表头。")
    columns = [str(name) for name in header]
    needed = _needed_columns(config, spec.id)
    missing = sorted(needed - set(columns))
    if missing:
        raise InputError(
            f"CSV 源 {spec.id} 缺少键规则所需列：{', '.join(missing)}；"
            f"实际列为：{', '.join(columns)}"
        )

    # Keep every parsed row (including the header and blank rows) so that the
    # span parser can be validated 1:1 before any offset is trusted.
    data_positions = [
        index
        for index, (row, _line) in enumerate(csv_rows)
        if index > 0 and row != []
    ]
    data_rows = [csv_rows[index] for index in data_positions]

    records: list[SourceRecord] = []
    for row, line_num in data_rows:
        extra_values = row[len(columns) :] if len(row) > len(columns) else None
        if extra_values:
            issues.append(
                Defect(
                    code="SOURCE_ROW_MISMATCH",
                    severity=config.severity_for("SOURCE_ROW_MISMATCH"),
                    message="CSV 记录列数多于表头，多余值已放入审计详情",
                    details={
                        "row": line_num,
                        "extra_values": [str(value) for value in extra_values],
                    },
                )
            )
        raw = dict(zip(columns, row))
        values, defects, origins = _coerce_mapping(
            config, spec, raw, line_num
        )
        record = _make_record(
            config,
            spec,
            ordinal=len(records) + 1,
            record_ref=f"row:{line_num}",
            values=values,
            defects=defects,
            contamination_origins=origins,
        )
        records.append(record)

    if parse_error is not None:
        issues.append(
            Defect(
                code="SOURCE_PARSE_ERROR",
                severity=config.severity_for("SOURCE_PARSE_ERROR"),
                message=f"CSV 解析中断：{parse_error}",
                details={"near_row": len(records) + 1},
            )
        )

    load = SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=decoded.note,
        invalid_byte_offsets=[span.to_dict() for span in decoded.spans],
    )

    # Whole-source policy is applied before precise attribution.
    if spec.invalid_byte_policy == "whole_source" and decoded.inserted_chars:
        _widen_whole_source(load, records, "配置 invalid_byte_policy=whole_source")
    elif decoded.inserted_chars:
        span_rows = _csv_row_spans(text, spec.delimiter, spec.quotechar)
        if span_rows is None:
            _widen_whole_source(
                load, records, "CSV 分隔符/引号配置无法重建字段跨度"
            )
        else:
            _csv_contamination(
                load,
                decoded,
                text,
                span_rows,
                csv_rows,
                data_positions,
                records,
                columns,
            )
    _finalize_contamination(
        load,
        precise=decoded.precise or decoded.inserted_chars == 0,
        reasons=load.contamination_reasons,
        scope_hint=(
            "record"
            if any(record.contamination_reasons for record in records)
            else "field"
        ),
    )
    return load


# ---------------------------------------------------------------------------
# JSONL loading
# ---------------------------------------------------------------------------


def _load_jsonl(
    config: AppConfig, spec: SourceSpec, data: bytes, digest: str
) -> SourceLoad:
    decoded = _decode_bytes(config, spec, data)
    text = decoded.text
    issues: list[Defect] = []
    if decoded.defect:
        issues.append(decoded.defect)
    records: list[SourceRecord] = []
    columns: list[str] = []
    seen_columns: set[str] = set()
    lines = list(_iter_lines_with_offsets(text))
    parsed_objects: dict[int, dict[str, Any]] = {}

    for line_number, _start, line in lines:
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
        parsed_objects[line_number] = obj
        values, defects, origins = _coerce_mapping(
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
                contamination_origins=origins,
            )
        )

    load = SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=digest,
        size_bytes=len(data),
        issues=issues,
        decode_note=decoded.note,
        invalid_byte_offsets=[span.to_dict() for span in decoded.spans],
    )

    if spec.invalid_byte_policy == "whole_source" and decoded.inserted_chars:
        _widen_whole_source(load, records, "配置 invalid_byte_policy=whole_source")
    else:
        _jsonl_contamination(load, decoded, lines, parsed_objects, records)
    _finalize_contamination(
        load,
        precise=decoded.precise or decoded.inserted_chars == 0,
        reasons=load.contamination_reasons,
        scope_hint=(
            "record"
            if any(record.contamination_reasons for record in records)
            else "field"
        ),
    )
    return load


# ---------------------------------------------------------------------------
# SQLite loading (per-value byte decoding also carries provenance)
# ---------------------------------------------------------------------------


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
                values, defects, origins = _coerce_mapping(
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
                        contamination_origins=origins,
                    )
                )
        except sqlite3.Error as exc:
            raise InputError(
                f"SQLite 源 {spec.id} 查询失败（{spec.table}）：{exc}"
            ) from exc
    finally:
        connection.close()

    load = SourceLoad(
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
            "literal_replacement_chars": sum(
                (origin.get("literal") or 0)
                for record in records
                for origin in record.contamination_origins.values()
            ),
            "inserted_replacement_chars": sum(
                (origin.get("inserted") or 0)
                for record in records
                for origin in record.contamination_origins.values()
            ),
        },
        invalid_byte_offsets=[],
    )
    if any(record.contaminated_columns for record in records):
        if spec.invalid_byte_policy == "whole_source":
            _widen_whole_source(load, records, "配置 invalid_byte_policy=whole_source")
        else:
            load.contamination_reasons = ["SQLite 字节值无法严格解码，已定位到字段"]
            load.contaminated_columns = set().union(
                *(record.contaminated_columns for record in records)
            )
            load.contamination_scope = "field"
        load.record_contamination = [
            set(record.contaminated_columns) for record in records
        ]
    return load


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
) -> tuple[dict[str, Any], list[Defect], dict[str, dict[str, int | None]]]:
    values: dict[str, Any] = {}
    defects: list[Defect] = []
    origins: dict[str, dict[str, int | None]] = {}
    for column, value in raw.items():
        converted, defect, origin = _coerce_value(
            config, spec, column, value, row_number
        )
        values[column] = converted
        if defect:
            defects.append(defect)
        if origin:
            origins[column] = origin
    if not allow_missing:
        for column in _needed_columns(config, spec.id):
            if column not in values:
                values[column] = None
    return values, defects, origins


def _coerce_value(
    config: AppConfig,
    spec: SourceSpec,
    column: str,
    value: Any,
    row_number: int,
) -> tuple[str | None, Defect | None, dict[str, int | None] | None]:
    if value is None:
        return None, None, None
    if isinstance(value, str):
        return value, None, None
    if isinstance(value, bytes):
        try:
            return value.decode(spec.encoding, errors="strict"), None, None
        except UnicodeDecodeError:
            text = value.decode(spec.encoding, errors="replace")
            inserted = text.count(REPLACEMENT_CHARACTER)
            return (
                text,
                Defect(
                    code="REPLACEMENT_CHARACTER",
                    severity=config.severity_for("REPLACEMENT_CHARACTER"),
                    message=f"列 {column} 的字节值无法严格解码，已替换为 U+FFFD",
                    details={"row": row_number, "column": column},
                    column=column,
                ),
                {"inserted": inserted, "literal": 0},
            )
        except LookupError:
            text = value.decode("utf-8", errors="replace")
            return text, None, None
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
        None,
    )


def _make_record(
    config: AppConfig,
    spec: SourceSpec,
    *,
    ordinal: int,
    record_ref: str,
    values: dict[str, Any],
    defects: list[Defect],
    contamination_origins: dict[str, dict[str, int | None]] | None = None,
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
    origins = contamination_origins or {}
    contaminated = {
        column
        for column, origin in origins.items()
        if (origin.get("inserted") or 0) > 0
    }
    return SourceRecord(
        source_id=spec.id,
        ordinal=ordinal,
        record_ref=record_ref,
        record_id=record_id_value,
        values=values,
        defects=defects,
        contaminated_columns=contaminated,
        contamination_origins=origins,
    )


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _metadata_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
