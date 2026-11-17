"""Unicode normalization, key construction, and text-anomaly inspection.

The visual-confusable preflight at the bottom of this module is intentionally
read-only: it never changes a target key. It produces evidence (scripts,
codepoints, mapping chains and a visual skeleton) that is separate from the
byte-level collision checks in :mod:`charorder.engine`.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .models import ScriptPolicy, TransformSpec

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


# ---------------------------------------------------------------------------
# Offline visual-confusable preflight
# ---------------------------------------------------------------------------
#
# Design constraints:
#   * The bundled map is a fixed, versioned snapshot. Nothing here touches the
#     network, the system locale, fonts, or an ICU database.
#   * A "visual risk" is a *different* evidence family from a byte-level
#     collision. The engine keeps NORMALIZATION_COLLISION / DUPLICATE_KEY for
#     keys that are exactly equal as UTF-8; this module only compares keys that
#     differ at the byte level.
#   * When a codepoint or a whole script cannot be classified by the bundled
#     data we say so explicitly and never return a "no visual risk" result.

CONFUSABLE_MAP_PATH = Path(__file__).resolve().parent / "data" / "confusables.json"

_MAX_SKELETON_DEPTH = 8
# Hard safety cap on repeated-expansion output. Reaching it is recorded as
# unknown coverage and the skeleton is *not* truncated, so two long keys can
# never be grouped merely because they share a prefix.
_MAX_SKELETON_EXPANSION = 4096


@dataclass(frozen=True)
class ConfusableMap:
    """The immutable, in-memory form of the bundled confusable map."""

    map_version: str
    skeleton_version: str
    unicode_version: str
    map_sha256: str
    # (match_codepoints) -> (skeleton_codepoints, scripts, note)
    entries: dict[tuple[int, ...], tuple[tuple[int, ...], tuple[str, ...], str]]
    script_ranges: dict[str, tuple[tuple[int, int], ...]]
    # longest match sequence in codepoints, used to bound scanning work
    max_match_length: int
    provenance: dict[str, Any]

    def scripts_for(self, ch: str) -> tuple[str, ...]:
        code = ord(ch)
        found = tuple(
            name
            for name, ranges in self.script_ranges.items()
            if any(start <= code <= end for start, end in ranges)
        )
        return found

    def version_info(self) -> dict[str, Any]:
        return {
            "kind": "charorder.confusable_map",
            "map_version": self.map_version,
            "skeleton_version": self.skeleton_version,
            "unicode_version": self.unicode_version,
            "map_sha256": self.map_sha256,
            "entry_count": len(self.entries),
            "script_count": len(self.script_ranges),
            "provenance": self.provenance,
        }


@lru_cache(maxsize=1)
def load_confusable_map() -> ConfusableMap:
    """Load the bundled map once. Raises ConfigError if the snapshot is broken."""

    try:
        raw = CONFUSABLE_MAP_PATH.read_bytes()
    except OSError as exc:  # pragma: no cover - packaging failure
        raise ConfigError(f"无法读取内置混淆映射数据：{CONFUSABLE_MAP_PATH}（{exc}）") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover
        raise ConfigError(f"内置混淆映射数据不是有效 UTF-8 JSON：{exc}") from exc

    if doc.get("kind") != "charorder.confusable_map" or doc.get("schema_version") != 1:
        raise ConfigError("内置混淆映射数据的类型或 schema_version 不正确。")

    entries: dict[
        tuple[int, ...], tuple[tuple[int, ...], tuple[str, ...], str]
    ] = {}
    max_match_length = 1
    for item in doc.get("entries", []):
        match = tuple(int(value, 16) for value in item["match"])
        skeleton = tuple(int(value, 16) for value in item["skeleton"])
        scripts = tuple(str(value) for value in item.get("scripts", []))
        entries[match] = (skeleton, scripts, str(item.get("note", "")))
        max_match_length = max(max_match_length, len(match))

    script_ranges: dict[str, tuple[tuple[int, int], ...]] = {}
    for item in doc.get("scripts", []):
        script_ranges[str(item["name"])] = tuple(
            (int(start, 16), int(end, 16)) for start, end in item["ranges"]
        )

    return ConfusableMap(
        map_version=str(doc["map_version"]),
        skeleton_version=str(doc["skeleton_version"]),
        unicode_version=str(doc["unicode_version"]),
        map_sha256=hashlib.sha256(raw).hexdigest(),
        entries=entries,
        script_ranges=script_ranges,
        max_match_length=max_match_length,
        provenance=dict(doc.get("provenance", {})),
    )


@dataclass(frozen=True)
class SkeletonResult:
    """Skeleton plus the exact mapping chain that produced it."""

    skeleton: str
    codepoints: tuple[int, ...]
    scripts: tuple[str, ...]
    unknown_codepoints: tuple[int, ...]
    unknown_scripts: tuple[str, ...]
    # One row per mapped unit: original codepoints -> replacement codepoints.
    chain: tuple[dict[str, Any], ...]
    # How many recursion steps were needed to reach a stable skeleton.
    depth: int
    coverage: str  # "covered" | "partial" | "unknown"

    def as_dict(self) -> dict[str, Any]:
        return {
            "skeleton": escaped_text(self.skeleton),
            "skeleton_codepoints": [f"U+{code:04X}" for code in self.codepoints],
            "scripts": list(self.scripts),
            "unknown_codepoints": [f"U+{code:04X}" for code in self.unknown_codepoints],
            "unknown_scripts": list(self.unknown_scripts),
            "chain": list(self.chain),
            "depth": self.depth,
            "coverage": self.coverage,
        }


def _codepoint_label(code: int) -> str:
    return f"U+{code:04X}"


def _char_script_summary(ch: str, confusables: ConfusableMap) -> list[dict[str, Any]]:
    scripts = confusables.scripts_for(ch)
    return [
        {
            "char": escaped_text(ch),
            "codepoint": _codepoint_label(ord(ch)),
            "name": _name(ch),
            "scripts": list(scripts),
            "mapped": (ord(ch),) in confusables.entries
            or any(
                key[0] == ord(ch) and len(key) == 1 for key in confusables.entries
            ),
        }
    ]


def _map_unit(
    text: str, index: int, confusables: ConfusableMap
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[str, ...], str] | None:
    """Find the longest bundled mapping starting at ``index``."""

    for length in range(
        min(confusables.max_match_length, len(text) - index), 0, -1
    ):
        key = tuple(ord(ch) for ch in text[index : index + length])
        found = confusables.entries.get(key)
        if found is not None:
            skeleton, scripts, note = found
            return key, skeleton, scripts, note
    return None


def _decompose_fallback(code: int) -> tuple[int, ...]:
    """Best-effort decomposition for codepoints absent from the map.

    This uses only the Python Unicode database (no network). It is recorded in
    the mapping chain so reviewers can see exactly how a skeleton was formed.
    """

    text = unicodedata.normalize("NFD", chr(code))
    return tuple(ord(ch) for ch in text)


def visual_skeleton(
    text: str, confusables: ConfusableMap | None = None
) -> SkeletonResult:
    """Produce a visual skeleton and a reviewable mapping chain.

    Mapping is applied repeatedly (bounded) until it stabilises. Multi-codepoint
    entries are matched greedily, longest first. Any codepoint that the map
    cannot classify is carried through and recorded as unknown coverage.

    ``scripts`` and unknown-coverage evidence describe the *input* key, not the
    derived skeleton, so a Cyrillic key that maps onto a Latin skeleton is still
    reported as Cyrillic evidence.
    """

    confusables = confusables or load_confusable_map()

    # Evidence about the original key: scripts, and which codepoints the
    # bundled map cannot classify.
    original_scripts: list[str] = []
    unknown_codepoints: list[int] = []
    unknown_scripts: list[str] = []
    index = 0
    while index < len(text):
        found = _map_unit(text, index, confusables)
        if found is not None:
            key = found[0]
            index += len(key)
            continue
        ch = text[index]
        for name in confusables.scripts_for(ch):
            if name not in {"Common", "Inherited"} and name not in original_scripts:
                original_scripts.append(name)
        if not confusables.scripts_for(ch):
            if ord(ch) not in unknown_codepoints:
                unknown_codepoints.append(ord(ch))
            name = _name(ch)
            if name != "UNNAMED" and "UNKNOWN" not in name:
                unknown_scripts.append(name)
        elif ord(ch) not in unknown_codepoints:
            # Known script but no visual mapping: we can name the script but
            # cannot certify what it looks like.
            unknown_codepoints.append(ord(ch))
        index += 1
    # Scripts are still collected for mapped codepoints.
    for ch in text:
        for name in confusables.scripts_for(ch):
            if name not in {"Common", "Inherited"} and name not in original_scripts:
                original_scripts.append(name)

    current = text
    chain: list[dict[str, Any]] = []
    depth = 0
    expansion_truncated = False
    seen: set[str] = set()
    while depth < _MAX_SKELETON_DEPTH and current not in seen:
        if len(current) > _MAX_SKELETON_EXPANSION:
            expansion_truncated = True
            break
        seen.add(current)
        output: list[str] = []
        changed = False
        index = 0
        while index < len(current):
            found = _map_unit(current, index, confusables)
            if found is not None:
                key, skeleton, scripts, note = found
                output.append("".join(chr(code) for code in skeleton))
                chain.append(
                    {
                        "from": [_codepoint_label(code) for code in key],
                        "to": [_codepoint_label(code) for code in skeleton],
                        "scripts": list(scripts),
                        "note": note,
                        "kind": "map",
                    }
                )
                if key != skeleton:
                    changed = True
                index += len(key)
            else:
                code = ord(current[index])
                fallback = _decompose_fallback(code)
                output.append("".join(chr(value) for value in fallback))
                chain.append(
                    {
                        "from": [_codepoint_label(code)],
                        "to": [_codepoint_label(value) for value in fallback],
                        "scripts": list(confusables.scripts_for(current[index])),
                        "note": "unmapped codepoint; NFD fallback recorded for review",
                        "kind": "unmapped",
                    }
                )
                if fallback != (code,):
                    changed = True
                index += 1
        next_text = "".join(output)
        if next_text == current or not changed:
            current = next_text
            break
        current = next_text
        depth += 1

    if len(current) > max(_MAX_SKELETON_EXPANSION, len(text) * 8):
        # Do NOT truncate: two long keys sharing a prefix must not appear to
        # share a skeleton. Record the cap as unknown coverage instead. The cap
        # is relative to the input so an already-long key is not penalised.
        expansion_truncated = True

    hit_limit = expansion_truncated or depth >= _MAX_SKELETON_DEPTH
    if hit_limit:
        unknown_scripts = tuple(
            list(unknown_scripts) + [f"SKELETON_DEPTH_LIMIT:{depth}"]
        )

    if unknown_codepoints or unknown_scripts:
        coverage = "partial" if (original_scripts and not hit_limit) else "unknown"
    else:
        coverage = "unknown" if hit_limit else "covered"

    return SkeletonResult(
        skeleton=current,
        codepoints=tuple(ord(ch) for ch in current),
        scripts=tuple(original_scripts),
        unknown_codepoints=tuple(unknown_codepoints),
        unknown_scripts=tuple(unknown_scripts),
        chain=tuple(chain),
        depth=depth,
        coverage=coverage,
    )


def analyze_visual_confusables(
    text: str,
    *,
    column: str | None = None,
    policy: ScriptPolicy | None = None,
    confusables: ConfusableMap | None = None,
) -> list[TextIssue]:
    """Return visual/script evidence for one already-transformed key component.

    * ``SCRIPT_NOT_AUTHORIZED`` is emitted when the component uses a script the
      key's policy does not authorize.
    * ``VISUAL_COVERAGE_UNKNOWN`` is emitted when the bundled map cannot fully
      classify the component. This is an explicit "cannot certify" state.

    Cross-key visual candidates are produced by the engine, which compares the
    profiles of *different* binary keys. This function only reports per-key
    script and coverage evidence.
    """

    confusables = confusables or load_confusable_map()
    skeleton = visual_skeleton(text, confusables)
    issues: list[TextIssue] = []

    observed_scripts = sorted(
        {script for ch in text for script in confusables.scripts_for(ch)}
    )
    if policy is not None:
        allowed = set(policy.allowed_scripts)
        unauthorized = [
            script
            for script in observed_scripts
            # Common punctuation/digits and Inherited combining marks do not by
            # themselves constitute a script-level authorization breach.
            if script not in allowed and script not in {"Common", "Inherited"}
        ]
        if unauthorized:
            issues.append(
                TextIssue(
                    code="SCRIPT_NOT_AUTHORIZED",
                    message=(
                        f"{policy.mode} 合同未授权文字体系："
                        + "、".join(unauthorized)
                    ),
                    details={
                        "policy_mode": policy.mode,
                        "namespace": policy.namespace,
                        "allowed_scripts": sorted(allowed),
                        "observed_scripts": observed_scripts,
                        "unauthorized_scripts": unauthorized,
                        "characters": [
                            item
                            for ch in text
                            for item in _char_script_summary(ch, confusables)
                            if set(item["scripts"]) & set(unauthorized)
                        ],
                        "skeleton_version": confusables.skeleton_version,
                    },
                    column=column,
                )
            )

    if skeleton.unknown_codepoints or skeleton.unknown_scripts:
        issues.append(
            TextIssue(
                code="VISUAL_COVERAGE_UNKNOWN",
                message=(
                    "内置混淆映射无法完整覆盖该键；不得据此宣称无视觉风险"
                ),
                details={
                    "unknown_codepoints": [
                        _codepoint_label(code)
                        for code in skeleton.unknown_codepoints
                    ],
                    "unknown_scripts": list(skeleton.unknown_scripts),
                    "skeleton_version": confusables.skeleton_version,
                    "map_version": confusables.map_version,
                    "coverage": skeleton.coverage,
                },
                column=column,
            )
        )
    return issues


def key_visual_profile(
    target_key: str, confusables: ConfusableMap | None = None
) -> dict[str, Any]:
    """Build the record-level visual profile stored next to a key result."""

    confusables = confusables or load_confusable_map()
    skeleton = visual_skeleton(target_key, confusables)
    return {
        "target_key_sha256": sha256_text(target_key),
        "skeleton": skeleton.skeleton,
        "skeleton_escaped": escaped_text(skeleton.skeleton),
        "skeleton_sha256": sha256_text(skeleton.skeleton),
        "skeleton_codepoints": [f"U+{code:04X}" for code in skeleton.codepoints],
        "scripts": list(skeleton.scripts),
        "unknown_codepoints": [f"U+{code:04X}" for code in skeleton.unknown_codepoints],
        "unknown_scripts": list(skeleton.unknown_scripts),
        "coverage": skeleton.coverage,
        "skeleton_version": confusables.skeleton_version,
        "map_version": confusables.map_version,
        "codepoints": [
            {
                "codepoint": _codepoint_label(ord(ch)),
                "name": _name(ch),
                "scripts": list(confusables.scripts_for(ch)),
                "escaped": escaped_text(ch),
            }
            for ch in target_key
        ],
        "chain": list(skeleton.chain),
    }


def compare_visual_keys(
    left: str,
    right: str,
    *,
    policy: ScriptPolicy | None = None,
    confusables: ConfusableMap | None = None,
) -> dict[str, Any]:
    """Compare two *different* binary keys for visual-confusable risk.

    The caller is responsible for never invoking this for keys that are equal;
    equal keys remain byte-level collisions (NORMALIZATION_COLLISION /
    DUPLICATE_KEY) and are handled by the engine.
    """

    confusables = confusables or load_confusable_map()
    left_profile = key_visual_profile(left, confusables)
    right_profile = key_visual_profile(right, confusables)
    same_skeleton = left_profile["skeleton"] == right_profile["skeleton"]

    left_scripts = set(left_profile["scripts"])
    right_scripts = set(right_profile["scripts"])
    shared_scripts = sorted(left_scripts & right_scripts)
    # Cross-script means one key carries a script the other does not. E.g.
    # "a@example.com" (Latin) vs "а@example.com" (Cyrillic + Latin) differ by
    # Cyrillic even though both share Latin for the domain.
    cross_script = bool(left_scripts and right_scripts) and bool(
        (left_scripts - right_scripts) or (right_scripts - left_scripts)
    )

    unknown = bool(
        left_profile["unknown_codepoints"]
        or right_profile["unknown_codepoints"]
        or left_profile["unknown_scripts"]
        or right_profile["unknown_scripts"]
    )

    return {
        "left_target_key_sha256": left_profile["target_key_sha256"],
        "right_target_key_sha256": right_profile["target_key_sha256"],
        "same_skeleton": same_skeleton,
        "cross_script": cross_script,
        "shared_scripts": shared_scripts,
        "left_scripts": list(left_profile["scripts"]),
        "right_scripts": list(right_profile["scripts"]),
        "unknown_coverage": unknown,
        "left": {
            "target_key_escaped": escaped_text(left),
            "skeleton_escaped": left_profile["skeleton_escaped"],
            "skeleton_codepoints": left_profile["skeleton_codepoints"],
            "codepoints": left_profile["codepoints"],
            "chain": left_profile["chain"],
            "coverage": left_profile["coverage"],
        },
        "right": {
            "target_key_escaped": escaped_text(right),
            "skeleton_escaped": right_profile["skeleton_escaped"],
            "skeleton_codepoints": right_profile["skeleton_codepoints"],
            "codepoints": right_profile["codepoints"],
            "chain": right_profile["chain"],
            "coverage": right_profile["coverage"],
        },
        "skeleton_version": confusables.skeleton_version,
        "map_version": confusables.map_version,
    }
