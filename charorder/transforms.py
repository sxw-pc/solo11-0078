"""Unicode normalization, key construction, and text-anomaly inspection."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .models import TransformSpec

# ---------------------------------------------------------------------------
# Language-specific casing (Turkish ``tr`` / Azerbaijani ``az``)
#
# These mappings implement the *context-aware* rules of Unicode SpecialCasing.txt
# and are pinned to the Unicode database version bundled with the running
# interpreter (see charorder.UNICODE_VERSION / unicodedata.unidata_version). They
# are full-string mappings, not character substitutions: the dotted capital
# ``I`` + U+0307 sequence is a two-codepoint context, and U+0307 is removed
# after any soft-dotted character (SpecialCasing: "After_Soft_Dotted"). A naive
# ``text.replace("I", "ı")`` cannot express either rule, so it must not be used
# to claim Turkic support.
#
# Reference (SpecialCasing.txt, Unicode 14.0):
#   tr/az lower: U+0049 -> U+0131 ; U+0130 -> U+0069 ; U+0049+0307 -> U+0069
#   tr/az upper: U+0069 -> U+0130 ; U+0131 -> U+0049
# ---------------------------------------------------------------------------

TURKIC_LANGUAGES = frozenset({"tr", "az"})

# Exact Soft_Dotted enumeration from PropList.txt for the pinned Unicode
# version (56 code points in Unicode 14.0). Soft-dotted characters lose an
# immediately following combining dot above on lowercasing. The literal is
# kept verbatim (rather than derived at runtime) so the mapping is fixed to
# one auditable Unicode data version, matching charorder.UNICODE_VERSION.
_SOFT_DOTTED = frozenset(
    "ijıȷɟɨᵢᶖᶤᶨḭḯṧṩịἀἁἂἃἄἅἆἇᾰᾱῐῑῠῡⁱⅈⅉⱼ𝐢𝐣𝑖𝑗𝒊𝒋𝓮𝔢𝔣𝕖𝕗𝖊𝖋𝗂𝗃𝗶𝗷𝘪𝘫𝙞𝙟𝚒𝚓"
)
_DOT_ABOVE = "̇"  # U+0307 COMBINING DOT ABOVE
_CAPITAL_I = "I"  # U+0049 LATIN CAPITAL LETTER I
_DOTTED_CAPITAL_I = "İ"  # U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE
_DOTLESS_LOWER_I = "ı"  # U+0131 LATIN SMALL LETTER DOTLESS I
_SMALL_I = "i"  # U+0069 LATIN SMALL LETTER I

# Codepoints whose key equivalence depends on which casing semantics apply.
# U+0307 is listed because its behaviour changes after soft-dotted letters and
# when it occurs as the decomposed form of U+0130.
TURKIC_CASE_SENSITIVE_CODEPOINTS = frozenset(
    {_CAPITAL_I, _DOTTED_CAPITAL_I, _DOTLESS_LOWER_I, _SMALL_I, _DOT_ABOVE}
)


def contains_turkic_sensitive_codepoints(text: str) -> bool:
    """Return True if *text* contains any I-family codepoint governed by tr/az.

    The check works on raw input: it does not depend on normalization order,
    so both the precomposed ``İ`` and the decomposed ``I``+U+0307 forms are
    detected.
    """

    return any(ch in TURKIC_CASE_SENSITIVE_CODEPOINTS for ch in text)


def turkic_lower(text: str) -> str:
    """Full-string-context lowercase for Turkish/Azerbaijani.

    Implements the tr/az conditional mappings of SpecialCasing.txt:

    * ``I`` -> ``ı`` (U+0131), except ``I`` + U+0307 -> ``i`` (Before_Dot);
    * ``İ`` (U+0130) -> ``i``;
    * U+0307 following a soft-dotted character is removed (After_Soft_Dotted);
    * every other codepoint follows the default Unicode lowercase mapping.
    """

    out: list[str] = []
    for index, ch in enumerate(text):
        if ch == _DOT_ABOVE:
            if index > 0:
                predecessor = text[index - 1]
                if predecessor == _CAPITAL_I:
                    # I+0307 is the NFD form of İ: the Before_Dot branch
                    # already emitted plain i, so this dot is consumed.
                    continue
                # After_Soft_Dotted (SpecialCasing.txt): test the lowercase
                # form of the *original* predecessor, since the Soft_Dotted
                # property list is defined on lowercase letters while input
                # may be uppercase.
                lowered_predecessor = predecessor.lower()
                if (
                    len(lowered_predecessor) == 1
                    and lowered_predecessor in _SOFT_DOTTED
                ):
                    continue
            out.append(ch)
        elif ch == _CAPITAL_I:
            if index + 1 < len(text) and text[index + 1] == _DOT_ABOVE:
                # I+0307 lowercases to i; the following dot is consumed by
                # the U+0307 branch above.
                out.append(_SMALL_I)
            else:
                out.append(_DOTLESS_LOWER_I)
        elif ch == _DOTTED_CAPITAL_I:
            out.append(_SMALL_I)
        else:
            out.append(ch.lower())
    return "".join(out)


def turkic_upper(text: str) -> str:
    """Full-string-context uppercase for Turkish/Azerbaijani.

    Implements the unconditional tr/az mappings from SpecialCasing.txt:

    * ``i`` -> ``İ`` (U+0130);
    * ``ı`` (U+0131) -> ``I``;
    * every other codepoint follows the default Unicode uppercase mapping.
    """

    out: list[str] = []
    for ch in text:
        if ch == _SMALL_I:
            out.append(_DOTTED_CAPITAL_I)
        elif ch == _DOTLESS_LOWER_I:
            out.append(_CAPITAL_I)
        else:
            out.append(ch.upper())
    return "".join(out)


def turkic_casefold(text: str) -> str:
    """Casefold for Turkish/Azerbaijani.

    The tr/az contract lowercases with the full-context mapping first, then
    applies the default casefold to the remainder (e.g. German ß -> ss). The
    I-family is already resolved by ``turkic_lower`` so the locale-neutral
    casefold can never reintroduce the wrong ``i``/``ı`` collapse.
    """

    return turkic_lower(text).casefold()


@dataclass(frozen=True)
class TraceStage:
    """One fixed-order pipeline stage and the codepoints it produced."""

    stage: str
    applied: bool
    output_codepoints: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "applied": self.applied,
            "output_codepoints": list(self.output_codepoints),
        }


@dataclass(frozen=True)
class TransformTrace:
    """Codepoint-level audit trail of one component through the pipeline."""

    component_index: int
    raw_codepoints: tuple[str, ...]
    stages: tuple[TraceStage, ...]
    final_codepoints: tuple[str, ...]
    language: str | None
    case_contract: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_index": self.component_index,
            "language": self.language,
            "case_contract": self.case_contract,
            "raw_codepoints": list(self.raw_codepoints),
            "final_codepoints": list(self.final_codepoints),
            "stages": [stage.to_dict() for stage in self.stages],
        }


def codepoint_labels(text: str) -> tuple[str, ...]:
    return tuple(f"U+{ord(ch):04X}" for ch in text)


def apply_transform_traced(
    value: str,
    spec: TransformSpec,
    *,
    language: str | None = None,
) -> tuple[str, TransformTrace]:
    """Apply the declared key pipeline and return a codepoint trace.

    The stage order is fixed and documented:

    1. remove Cf invisible characters (when declared);
    2. East Asian width folding (when declared);
    3. Unicode normalization (NFC/NFD/NFKC/NFKD, when declared);
    4. case mapping -- locale-neutral by default, or the full-context tr/az
       mapping when *language* is a supported Turkic language and the rule
       opted into a language policy;
    5. whitespace collapsing (when declared);
    6. end trimming (when declared).
    """

    text = value
    stages: list[TraceStage] = []

    def record(stage: str, applied: bool, current: str) -> None:
        stages.append(
            TraceStage(
                stage=stage,
                applied=applied,
                output_codepoints=codepoint_labels(current),
            )
        )

    applied_invisible = spec.invisible == "remove"
    if applied_invisible:
        text = _remove_invisible(text)
    record("invisible_remove", applied_invisible, text)

    if spec.width_fold:
        text = fold_width(text)
    record("width_fold", spec.width_fold, text)

    if spec.normalization != "none":
        text = unicodedata.normalize(spec.normalization, text)
    record(f"normalize_{spec.normalization}", spec.normalization != "none", text)

    case_contract = "neutral"
    if spec.case != "none":
        if language in TURKIC_LANGUAGES:
            case_contract = f"turkic_{language}"
            if spec.case == "casefold":
                text = turkic_casefold(text)
            elif spec.case == "lower":
                text = turkic_lower(text)
            else:  # upper
                text = turkic_upper(text)
        else:
            case_contract = "neutral"
            if spec.case == "casefold":
                text = text.casefold()
            elif spec.case == "lower":
                text = text.lower()
            elif spec.case == "upper":
                text = text.upper()
    record(f"case_{spec.case}", spec.case != "none", text)

    if spec.collapse_whitespace:
        text = re.sub(r"\s+", " ", text, flags=re.UNICODE)
    record("collapse_whitespace", spec.collapse_whitespace, text)

    if spec.trim:
        text = text.strip()
    record("trim", spec.trim, text)

    trace = TransformTrace(
        component_index=0,
        raw_codepoints=codepoint_labels(value),
        stages=tuple(stages),
        final_codepoints=codepoint_labels(text),
        language=language,
        case_contract=case_contract,
    )
    return text, trace

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


def apply_transform(
    value: str, spec: TransformSpec, *, language: str | None = None
) -> str:
    """Apply the declared key pipeline in a fixed, documented order.

    With no *language* (or an unsupported one) the behaviour is the original
    locale-neutral pipeline. Pass a ``tr``/``az`` tag to use the full-string
    Turkic casing contract when the rule's transform opted into one.
    """

    transformed, _trace = apply_transform_traced(value, spec, language=language)
    return transformed


def make_target_key(
    components: list[str],
    spec: TransformSpec,
    *,
    language: str | None = None,
) -> str:
    transformed = [
        apply_transform(component, spec, language=language)
        for component in components
    ]
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
