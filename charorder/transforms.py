"""Unicode normalization, key construction, and text-anomaly inspection."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .models import TransformSpec

UNIT_SEPARATOR = "\x1f"

# --- Versioned composite-key framing (opt-in) ---------------------------------
# The legacy encoding joins transformed components with U+001F, which is
# ambiguous whenever a component itself contains U+001F. Version 1 instead
# emits a self-delimiting length-prefixed frame per component:
#
#     FRAME_MARKER "v1:" <decimal codepoint count> ":" <component>
#
# repeated for every component, including empty ones. Because each frame
# declares exactly how many code points its payload spans, no byte sequence
# inside a payload (U+001F, the frame marker, backslashes, escape-like text,
# multi-byte Unicode, ...) can ever be interpreted as framing. Encoding and
# decoding are total, deterministic inverses; the frame carries an explicit
# version marker so a target index can tell the two encodings apart and never
# mixes them.
FRAME_MARKER = "\x01"
FRAME_VERSION = "v1"
FRAME_PREFIX = FRAME_MARKER + FRAME_VERSION + ":"
# Frame payloads may transport any code point; control characters inside a
# payload are still audited but do not break the framing.
FRAME_STRUCTURAL_CONTROLS = frozenset({FRAME_MARKER})


class VersionedKeyError(ValueError):
    """Raised when a versioned key frame cannot be decoded."""


def encode_versioned_key(components: list[str]) -> str:
    """Encode an arbitrary component sequence into a reversible v1 frame.

    Every input is accepted, including empty strings and components that
    contain U+001F, the frame marker, or backslash/escape-like text. No
    substitution or escaping of payload bytes is performed, so payload text
    that merely looks like an escape sequence cannot collide with framing.
    """

    frames = [FRAME_PREFIX]
    for component in components:
        if not isinstance(component, str):
            raise TypeError("版本化复合键的分量必须是字符串。")
        frames.append(str(len(component)))
        frames.append(":")
        frames.append(component)
    return "".join(frames)


def decode_versioned_key(framed_key: str) -> list[str]:
    """Decode a v1 frame back to the exact original component sequence.

    Raises VersionedKeyError on any structural violation (missing marker,
    non-numeric length, truncated payload, trailing bytes). A well-formed
    frame always decodes successfully, including frames carrying empty
    components or control characters.
    """

    if not isinstance(framed_key, str):
        raise VersionedKeyError("版本化复合键必须是字符串。")
    marker_len = len(FRAME_MARKER)
    if not framed_key.startswith(FRAME_PREFIX):
        raise VersionedKeyError("缺少版本化复合键的版本标记。")
    position = len(FRAME_PREFIX)
    components: list[str] = []
    total = len(framed_key)
    while position < total:
        separator = framed_key.find(":", position)
        if separator == -1:
            raise VersionedKeyError("分帧缺少长度分隔符。")
        length_text = framed_key[position:separator]
        if not length_text.isdigit() or (
            len(length_text) > 1 and length_text.startswith("0")
        ):
            raise VersionedKeyError("分帧长度字段不是规范十进制非负整数。")
        length = int(length_text)
        payload_start = separator + 1
        payload_end = payload_start + length
        if payload_end > total:
            raise VersionedKeyError("分帧声明的分量长度超出键范围。")
        components.append(framed_key[payload_start:payload_end])
        position = payload_end
    return components


def is_versioned_key(text: str | None) -> bool:
    """Return True only when *text* parses completely as a v1 frame.

    Merely starting with the marker is not enough: the whole string must
    satisfy the frame grammar, so payload content resembling a marker cannot
    be mistaken for a versioned key.
    """

    if not text or not text.startswith(FRAME_PREFIX):
        return False
    try:
        decode_versioned_key(text)
    except VersionedKeyError:
        return False
    return True


def versioned_roundtrip_ok(components: list[str]) -> bool:
    """Evidence helper: encode then decode must reproduce the tuple exactly."""

    return decode_versioned_key(encode_versioned_key(components)) == list(components)


def payload_control_codepoints(components: list[str]) -> list[str]:
    """List reserved/control code points carried inside frame payloads.

    The frame marker is structural and excluded; everything else in the Cc/Cf
    categories (U+001F included) is reported for data-governance purposes
    without affecting reversibility.
    """

    seen: set[str] = set()
    for component in components:
        for ch in component:
            if ch in FRAME_STRUCTURAL_CONTROLS:
                continue
            if unicodedata.category(ch) in {"Cc", "Cf"}:
                seen.add(ch)
    return sorted(seen, key=ord)


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
