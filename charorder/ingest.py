"""Read-only source ingestion for CSV, JSONL, and SQLite.

SQLite sources are never hashed while still live. For every SQLite source we
first create a *private consistent snapshot* with the online backup API
(committed WAL pages included, uncommitted transactions excluded) and then
perform every read — table structure, required columns and row values —
inside that one frozen snapshot. Source identity is derived solely from that
same snapshot, in one of two declared modes:

* ``logical_content``  : a stable canonical encoding of the actually selected
  columns, record identities and row values; checkpoints / page
  rearrangements / unselected tables do not change the identity.
* ``physical_snapshot``: the SHA-256 of the private snapshot file bytes;
  physical layout changes may produce a new identity (new run_id).
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .errors import InputError
from .models import (
    AppConfig,
    Defect,
    SourceLoad,
    SourceRecord,
    SourceSpec,
    SQLITE_IDENTITY_MODES,
)

try:
    csv.field_size_limit(64 * 1024 * 1024)
except (OverflowError, ValueError):  # pragma: no cover - platform dependent
    pass


# Version tag for the canonical logical encoding of SQLite key inputs.
# Bump only if the framing below changes in an incompatible way.
LOGICAL_ENCODING_SCHEMA = "charorder/sqlite-logical/v1"

# SQLite storage classes (as returned by typeof()) mapped to stable type tags.
_TYPE_NULL = "null"
_TYPE_INTEGER = "integer"
_TYPE_REAL = "real"
_TYPE_TEXT = "text"
_TYPE_BLOB = "blob"
_TYPE_TAGS = {
    _TYPE_NULL,
    _TYPE_INTEGER,
    _TYPE_REAL,
    _TYPE_TEXT,
    _TYPE_BLOB,
}


@dataclass
class DecodeOutcome:
    text: str
    note: dict[str, Any] | None
    defect: Defect | None


@dataclass
class SqliteSnapshot:
    """A private, consistent, read-only copy of a SQLite source.

    ``connection`` reads only this frozen file; the live source database is
    never queried for content after the snapshot is taken.
    """

    source_path: Path
    directory: Path
    snapshot_path: Path
    connection: sqlite3.Connection
    source_had_wal: bool
    source_wal_size: int
    snapshot_page_count: int


def load_sources(config: AppConfig) -> list[SourceLoad]:
    loads: list[SourceLoad] = []
    for spec in config.sources:
        if spec.kind == "sqlite":
            # Do not read the live main-database bytes: committed rows may live
            # in the WAL and a concurrent writer can change the file at any
            # moment. Snapshot first, derive identity from the frozen copy.
            load = _load_sqlite(config, spec)
        else:
            try:
                data = spec.path.read_bytes()
            except OSError as exc:
                raise InputError(
                    f"无法读取源 {spec.id}：{spec.path}（{exc}）"
                ) from exc
            digest = hashlib.sha256(data).hexdigest()
            if spec.kind == "csv":
                load = _load_csv(config, spec, data, digest)
            elif spec.kind == "jsonl":
                load = _load_jsonl(config, spec, data, digest)
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
        identity_mode="file_bytes",
        identity={
            "mode": "file_bytes",
            "digest": digest,
            "size_bytes": len(data),
            "description": "整份源文件字节的 SHA-256（CSV/JSONL 行为保持不变）。",
        },
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
        identity_mode="file_bytes",
        identity={
            "mode": "file_bytes",
            "digest": digest,
            "size_bytes": len(data),
            "description": "整份源文件字节的 SHA-256（CSV/JSONL 行为保持不变）。",
        },
    )


# --------------------------------------------------------------------------- #
# SQLite snapshotting
# --------------------------------------------------------------------------- #


def _copy_database_snapshot(
    source: sqlite3.Connection,
    target: sqlite3.Connection,
    *,
    pages: int = 0,
    progress: Any = None,
    sleep: float = 0.0,
) -> None:
    """Copy one transactionally consistent image into the private target.

    Kept as a named module function so the copy policy (page size, progress
    callback) is explicit; callers always read from ``target`` afterwards.
    """

    kwargs: dict[str, Any] = {}
    if pages:
        kwargs["pages"] = pages
    if progress is not None:
        kwargs["progress"] = progress
    if sleep:
        kwargs["sleep"] = sleep
    source.backup(target, **kwargs)


@contextlib.contextmanager
def sqlite_snapshot(spec: SourceSpec) -> Iterator[SqliteSnapshot]:
    """Create and open a private consistent snapshot of a SQLite source.

    The online backup API copies one transactionally consistent database
    image (including pages committed in the WAL) into a temporary file. The
    live source is opened read-only and never modified; all subsequent reads
    go through the snapshot connection. Temporary files are always removed.
    """

    assert spec.table is not None
    source_path = spec.path
    wal_path = source_path.with_name(source_path.name + "-wal")
    source_had_wal = wal_path.exists()
    source_wal_size = wal_path.stat().st_size if source_had_wal else 0

    temp_dir = Path(tempfile.mkdtemp(prefix="charorder-snap-"))
    snapshot_path = temp_dir / "snapshot.sqlite"
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    snapshot: sqlite3.Connection | None = None
    try:
        try:
            source = sqlite3.connect(
                source_path.as_uri() + "?mode=ro", uri=True
            )
            target = sqlite3.connect(str(snapshot_path))
            # Rollback journal only: the private copy must not carry a WAL.
            target.execute("PRAGMA journal_mode = DELETE")
            # One consistent image. If a writer commits while the backup is in
            # flight, SQLite restarts atomically — the snapshot is either the
            # pre-commit or the post-commit version, never a mix of both.
            _copy_database_snapshot(source, target)
        except sqlite3.Error as exc:
            raise InputError(
                f"无法为 SQLite 源 {spec.id} 创建只读一致快照：{exc}"
            ) from exc
        finally:
            if target is not None:
                target.close()
            if source is not None:
                source.close()

        sidecar_wal = snapshot_path.with_name(snapshot_path.name + "-wal")
        if sidecar_wal.exists():  # defensive: DELETE mode must not leave a WAL
            raise InputError(
                f"SQLite 源 {spec.id} 的私有快照意外生成 WAL 附属文件：{sidecar_wal}"
            )

        try:
            snapshot = sqlite3.connect(
                snapshot_path.as_uri() + "?mode=ro", uri=True
            )
            snapshot.row_factory = sqlite3.Row
            snapshot.text_factory = bytes
            snapshot.execute("PRAGMA query_only = ON")
            # Pin one read transaction for the whole ingestion: schema,
            # columns and rows all come from this single frozen image.
            snapshot.execute("BEGIN")
            page_count = int(
                snapshot.execute("PRAGMA page_count").fetchone()[0]
            )
        except sqlite3.Error as exc:
            raise InputError(
                f"无法以只读方式打开 SQLite 源 {spec.id} 的快照：{exc}"
            ) from exc

        yield SqliteSnapshot(
            source_path=source_path,
            directory=temp_dir,
            snapshot_path=snapshot_path,
            connection=snapshot,
            source_had_wal=source_had_wal,
            source_wal_size=source_wal_size,
            snapshot_page_count=page_count,
        )
    finally:
        if snapshot is not None:
            with contextlib.suppress(sqlite3.Error):
                snapshot.rollback()
            snapshot.close()
        # Remove every file the private snapshot may have produced.
        with contextlib.suppress(OSError):
            for entry in temp_dir.iterdir():
                entry.unlink()
        with contextlib.suppress(OSError):
            temp_dir.rmdir()


def _hash_snapshot_file(snapshot: SqliteSnapshot) -> tuple[str, int]:
    """Hash the exact private snapshot bytes that were queried."""

    data = snapshot.snapshot_path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _load_sqlite(config: AppConfig, spec: SourceSpec) -> SourceLoad:
    assert spec.table is not None
    if spec.identity_mode not in SQLITE_IDENTITY_MODES:  # guarded by config
        raise InputError(f"SQLite 源 {spec.id} 的身份口径未知：{spec.identity_mode}")

    with sqlite_snapshot(spec) as snapshot:
        return _read_sqlite_snapshot(config, spec, snapshot)


def _read_sqlite_snapshot(
    config: AppConfig, spec: SourceSpec, snapshot: SqliteSnapshot
) -> SourceLoad:
    connection = snapshot.connection
    table_row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name = ?",
        (spec.table,),
    ).fetchone()
    if table_row is None:
        raise InputError(f"SQLite 源 {spec.id} 不存在表或视图：{spec.table}")
    table_name = _metadata_text(table_row[0])
    # PRAGMA table_list (SQLite >= 3.37.0) exposes the object type and the
    # WITHOUT ROWID flag; only ordinary rowid tables expose an implicit rowid.
    object_kind = "view"
    without_rowid = False
    try:
        table_list = connection.execute("PRAGMA table_list").fetchall()
    except sqlite3.Error:  # pragma: no cover - very old SQLite builds
        table_list = []
    table_list_hit = False
    for entry in table_list:
        if _metadata_text(entry["name"]) == table_name:
            table_list_hit = True
            object_kind = _metadata_text(entry["type"])
            # PRAGMA table_list exposes the WITHOUT ROWID flag as "wr".
            without_rowid = bool(entry["wr"])
            break
    if not table_list_hit:
        # Fallback: sqlite_master distinguishes tables from views; assume a
        # base table is rowid-bearing (the default), then probe directly for
        # WITHOUT ROWID tables which have no implicit rowid.
        master_kind = connection.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", (spec.table,)
        ).fetchone()
        object_kind = _metadata_text(master_kind[0]) if master_kind else "view"
        if object_kind == "table":
            try:
                connection.execute(
                    f"SELECT rowid FROM {_quote_identifier(table_name)} LIMIT 1"
                )
            except sqlite3.Error:
                without_rowid = True
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
        raise InputError(
            f"SQLite 源 {spec.id} 缺少记录标识列：{spec.record_id_field}"
        )

    # typeof() preserves the SQLite storage class so NULL / empty string /
    # numeric / text / blob values can never collapse into one another.
    select_sql = ", ".join(
        f"{_quote_identifier(column)} AS {_quote_identifier(column)}, "
        f"typeof({_quote_identifier(column)}) AS {_quote_identifier(column + '__type')}"
        for column in select_columns
    )
    # Explicit physical ordering where the object has a rowid; logical
    # identity never relies on it anyway (rows are canonicalized again), but
    # this makes ingestion deterministic for the common case. WITHOUT ROWID
    # tables and views are read in SQLite's natural order.
    query = f"SELECT {select_sql} FROM {_quote_identifier(table_name)}"
    if object_kind == "table" and not without_rowid:
        query += " ORDER BY rowid"

    issues: list[Defect] = []
    records: list[SourceRecord] = []
    typed_rows: list[dict[str, tuple[str, Any]]] = []
    try:
        cursor = connection.execute(query)
        for row in cursor:
            typed: dict[str, tuple[str, Any]] = {}
            raw_values: dict[str, Any] = {}
            for column in select_columns:
                storage_type = _metadata_text(row[column + "__type"])
                if storage_type not in _TYPE_TAGS:  # pragma: no cover - defensive
                    raise InputError(
                        f"SQLite 源 {spec.id} 列 {column} 出现未知存储类型：{storage_type}"
                    )
                stored = row[column]
                typed[column] = (storage_type, stored)
                raw_values[column] = stored
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
            typed_rows.append(typed)
    except sqlite3.Error as exc:
        raise InputError(
            f"SQLite 源 {spec.id} 查询失败（{spec.table}）：{exc}"
        ) from exc

    logical_encoding = encode_sqlite_logical(
        table_name=table_name,
        select_columns=select_columns,
        typed_rows=typed_rows,
    )
    logical_digest = hashlib.sha256(logical_encoding).hexdigest()
    physical_digest, physical_size = _hash_snapshot_file(snapshot)

    if spec.identity_mode == "logical_content":
        identity_digest = logical_digest
        identity_size = len(logical_encoding)
    else:
        identity_digest = physical_digest
        identity_size = physical_size

    identity = {
        "mode": spec.identity_mode,
        "table": table_name,
        "selected_columns": list(select_columns),
        "row_count": len(typed_rows),
        "logical_content": {
            "schema": LOGICAL_ENCODING_SCHEMA,
            "sha256": logical_digest,
            "size_bytes": len(logical_encoding),
            "description": (
                "对实际选中列、记录标识与行值（含 SQLite 存储类型）的稳定二进制编码；"
                "NULL、空串、类型与重复行互不混淆，且不依赖无 ORDER BY 的返回顺序。"
            ),
        },
        "physical_snapshot": {
            "sha256": physical_digest,
            "size_bytes": physical_size,
            "snapshot_page_count": snapshot.snapshot_page_count,
            "description": (
                "包含 WAL 已提交内容的私有一致性快照文件字节 SHA-256；"
                "页面重排、文件布局或未选中表变化可能改变该身份。"
            ),
        },
        "snapshot": {
            "source_path": str(snapshot.source_path),
            "source_wal_present": snapshot.source_had_wal,
            "source_wal_size_bytes": snapshot.source_wal_size,
            "read_only": True,
            "query_only": True,
            "pinned_transaction": True,
            "temporary_files_removed": True,
        },
        "digest": identity_digest,
        "size_bytes": identity_size,
    }

    return SourceLoad(
        spec=spec,
        records=records,
        columns=columns,
        sha256=identity_digest,
        size_bytes=identity_size,
        issues=issues,
        decode_note={
            "encoding": "utf-8",
            "valid": True,
            "sqlite_read_only": True,
            "sqlite_snapshot": True,
            "identity_mode": spec.identity_mode,
            "source_wal_present": snapshot.source_had_wal,
            "snapshot_page_count": snapshot.snapshot_page_count,
        },
        identity_mode=spec.identity_mode,
        identity=identity,
    )


# --------------------------------------------------------------------------- #
# Canonical logical encoding
# --------------------------------------------------------------------------- #


def _length_prefixed(payload: bytes) -> bytes:
    return len(payload).to_bytes(8, byteorder="big", signed=False) + payload


def _encode_typed_value(storage_type: str, value: Any) -> bytes:
    """Frame one SQLite value so type and content are unambiguous.

    Layout per value: ``tag_len(1) + tag + payload_len(8) + payload`` where
    every length is exact, which makes separators/injection impossible.
    """

    tag = storage_type.encode("ascii")
    if storage_type == _TYPE_NULL:
        payload = b""
    elif storage_type == _TYPE_INTEGER:
        payload = str(int(value)).encode("ascii")
    elif storage_type == _TYPE_REAL:
        # repr(float) round-trips exactly on the same Python/SQLite runtime.
        payload = repr(float(value)).encode("ascii")
    elif storage_type == _TYPE_TEXT:
        # text_factory=bytes delivers the raw UTF-8 database bytes.
        payload = bytes(value)
    elif storage_type == _TYPE_BLOB:
        payload = bytes(value)
    else:  # pragma: no cover - guarded by callers
        raise InputError(f"无法编码未知 SQLite 存储类型：{storage_type}")
    return (
        len(tag).to_bytes(1, byteorder="big", signed=False)
        + tag
        + _length_prefixed(payload)
    )


def encode_sqlite_logical(
    *,
    table_name: str,
    select_columns: list[str],
    typed_rows: list[dict[str, tuple[str, Any]]],
) -> bytes:
    """Build the deterministic byte encoding used by ``logical_content``.

    The encoding covers the queried table/view name, the actually selected
    columns in fixed order, and every selected row as typed values keyed by
    record content. Rows are sorted as complete byte frames, so SQLite's
    unspecified return order cannot change the digest. Duplicate rows remain
    duplicate frames (they are not deduplicated). NULL, empty strings,
    integers/reals/text/blobs each carry their own type tag.
    """

    parts: list[bytes] = [_length_prefixed(LOGICAL_ENCODING_SCHEMA.encode("ascii"))]
    parts.append(_length_prefixed(table_name.encode("utf-8")))
    parts.append(len(select_columns).to_bytes(8, byteorder="big", signed=False))
    for column in select_columns:
        parts.append(_length_prefixed(column.encode("utf-8")))

    row_frames: list[bytes] = []
    for typed in typed_rows:
        frame_parts = [len(select_columns).to_bytes(8, byteorder="big", signed=False)]
        for column in select_columns:
            storage_type, value = typed[column]
            frame_parts.append(_length_prefixed(column.encode("utf-8")))
            frame_parts.append(
                _length_prefixed(_encode_typed_value(storage_type, value))
            )
        row_frames.append(b"".join(frame_parts))
    # Order-independent: identical multisets of rows hash identically even if
    # the database returns them in a different order.
    row_frames.sort()

    out = b"".join(parts)
    out += len(row_frames).to_bytes(8, byteorder="big", signed=False)
    out += b"".join(_length_prefixed(frame) for frame in row_frames)
    return out


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
