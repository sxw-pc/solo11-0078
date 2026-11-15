"""Unicode normalization, key construction, and text-anomaly inspection."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .models import TransformSpec

UNIT_SEPARATOR = "\x1f"

_MOJIBAKE_RE = re.compile(r"(?:Ã[\u0080-¿]|Â[\u0080-¿]|â€[\u0080-™]|ï»¿)")
_BIDI_CONTROLS = {
    "؜",
    "‎",
    "‏",
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
}
_SURROGATE_RANGE = range(0xD800, 0xE000)


@dataclass(frozen=True)
class TextIssue:
    code: str
    message: str
    details: dict[str, Any]
    column: str | None = None


def char_label(ch: str) -> str:
    codepoint = f"U+{ord(ch):04X}"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        name = "UNNAMED"
    return f"{codepoint} {name}"


def _is_surrogate(ch: str) -> bool:
    return ord(ch) in _SURROGATE_RANGE


def fold_width(text: str) -> str:
    """Fold East Asian full-width/half-width forms without a general NFKC pass.

    Only characters whose East_Asian_Width is F or H are passed through NFKC.
    Contiguous runs are normalized together so half-width kana plus a voiced
    sound mark compose correctly. Ordinary CJK wide ideographs are untouched,
    and compatibility characters such as circled digits or ligatures are not
    silently folded.
    """

    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append(unicodedata.normalize("NFKC", "".join(run)))
            run.clear()

    for ch in text:
        if unicodedata.east_asian_width(ch) in {"F", "H"}:
            run.append(ch)
        else:
            flush()
            out.append(ch)
    flush()
    return "".join(out)


def _remove_invisible(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def apply_transform(value: str, spec: TransformSpec) -> str:
    """Apply the declared key pipeline in a fixed, documented order."""

    text = value
    if spec.invisible == "remove":
        text = _remove_invisible(text)
    if spec.width_fold:
        text = fold_width(text)
    if spec.normalization != "none":
        text = unicodedata.normalize(spec.normalization, text)
    if spec.case == "casefold":
        text = text.casefold()
    elif spec.case == "lower":
        text = text.lower()
    elif spec.case == "upper":
        text = text.upper()
    if spec.collapse_whitespace:
        text = re.sub(r"\s+", " ", text, flags=re.UNICODE)
    if spec.trim:
        text = text.strip()
    return text


def make_target_key(components: list[str], spec: TransformSpec) -> str:
    transformed = [apply_transform(component, spec) for component in components]
    return UNIT_SEPARATOR.join(transformed)


def has_unit_separator(value: str) -> bool:
    return UNIT_SEPARATOR in value


def analyze_text(value: str, column: str | None = None) -> list[TextIssue]:
    """Inspect a raw text value without altering it."""

    issues: list[TextIssue] = []

    invisible: dict[str, int] = {}
    controls: dict[str, int] = {}
    bidi: dict[str, int] = {}
    surrogates: dict[str, int] = {}
    for ch in value:
        category = unicodedata.category(ch)
        if ch in _BIDI_CONTROLS:
            bidi[ch] = bidi.get(ch, 0) + 1
        elif _is_surrogate(ch):
            surrogates[ch] = surrogates.get(ch, 0) + 1
        elif category == "Cf":
            invisible[ch] = invisible.get(ch, 0) + 1
        elif category == "Cc" and not ch.isspace():
            controls[ch] = controls.get(ch, 0) + 1

    if invisible:
        chars = _char_summary(invisible)
        issues.append(
            TextIssue(
                code="INVISIBLE_CHARACTER",
                message=f"发现 {sum(invisible.values())} 个不可见格式字符（{len(invisible)} 种）",
                details={"count": sum(invisible.values()), "characters": chars},
                column=column,
            )
        )
    if bidi:
        chars = _char_summary(bidi)
        issues.append(
            TextIssue(
                code="BIDI_CONTROL",
                message=f"发现 {sum(bidi.values())} 个双向文本控制符",
                details={"count": sum(bidi.values()), "characters": chars},
                column=column,
            )
        )
    if controls:
        chars = _char_summary(controls)
        issues.append(
            TextIssue(
                code="CONTROL_CHARACTER",
                message=f"发现 {sum(controls.values())} 个非空白控制字符",
                details={"count": sum(controls.values()), "characters": chars},
                column=column,
            )
        )
    if surrogates:
        chars = _char_summary(surrogates)
        issues.append(
            TextIssue(
                code="SURROGATE_CHARACTER",
                message="文本中存在孤立 UTF-16 代理码位，目标库通常无法编码",
                details={"count": sum(surrogates.values()), "characters": chars},
                column=column,
            )
        )

    replacement_count = value.count("�")
    if replacement_count:
        issues.append(
            TextIssue(
                code="REPLACEMENT_CHARACTER",
                message=f"发现 {replacement_count} 个 U+FFFD 替换字符，可能来自解码失败",
                details={"count": replacement_count},
                column=column,
            )
        )

    mojibake = _MOJIBAKE_RE.search(value)
    if mojibake:
        issues.append(
            TextIssue(
                code="MOJIBAKE_SUSPECT",
                message="发现 UTF-8/拉丁编码错配的典型乱码片段，未自动修复",
                details={"sample": escaped_text(value[max(0, mojibake.start() - 8) : mojibake.end() + 8])},
                column=column,
            )
        )

    whitespace_issues: list[str] = []
    unusual_ws: dict[str, int] = {}
    for ch in value:
        if ch.isspace() and ch != " ":
            unusual_ws[ch] = unusual_ws.get(ch, 0) + 1
    if unusual_ws:
        whitespace_issues.append(f"{sum(unusual_ws.values())} 个非普通空格空白")
    if value and value != value.strip():
        whitespace_issues.append("首尾空白")
    if re.search(r"\s{2,}", value, flags=re.UNICODE):
        whitespace_issues.append("连续空白")
    if value and not value.strip():
        whitespace_issues.append("全空白")
    if whitespace_issues:
        details: dict[str, Any] = {"issues": whitespace_issues}
        if unusual_ws:
            details["characters"] = _char_summary(unusual_ws)
        issues.append(
            TextIssue(
                code="ABNORMAL_WHITESPACE",
                message="异常空白：" + "、".join(whitespace_issues),
                details=details,
                column=column,
            )
        )

    return issues


def _char_summary(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"char": escaped_text(ch), "codepoint": f"U+{ord(ch):04X}", "name": _name(ch), "count": count}
        for ch, count in sorted(counts.items(), key=lambda item: ord(item[0]))
    ]


def _name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED"


def escaped_text(text: str) -> str:
    """Return a single-quoted, unambiguous display form for audit pages."""

    parts = ["'"]
    for ch in text:
        code = ord(ch)
        category = unicodedata.category(ch)
        if ch == "\\":
            parts.append("\\\\")
        elif ch == "'":
            parts.append("\\'")
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\r":
            parts.append("\\r")
        elif ch == "\t":
            parts.append("\\t")
        elif category in {"Cf", "Cc", "Cs", "Zl", "Zp"} or not ch.isprintable():
            if code <= 0xFFFF:
                parts.append(f"\\u{code:04x}")
            else:
                parts.append(f"\\U{code:08x}")
        else:
            parts.append(ch)
    parts.append("'")
    return "".join(parts)


def format_raw_values(values: tuple[str | None, ...]) -> str:
    if len(values) == 1:
        return "∅" if values[0] is None else escaped_text(values[0])
    rendered = ["∅" if value is None else escaped_text(value) for value in values]
    return "[" + ", ".join(rendered) + "]"


def utf8_bytes(text: str) -> bytes:
    """Encode for byte-limit calculations, replacing lone surrogates."""

    return sanitize_text(text).encode("utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(utf8_bytes(text)).hexdigest()


def sanitize_text(text: str) -> str:
    """Make a string safe for SQLite and UTF-8 JSON output."""

    if not any(0xD800 <= ord(ch) < 0xE000 for ch in text):
        return text
    return "".join(
        "�" if 0xD800 <= ord(ch) < 0xE000 else ch for ch in text
    )
