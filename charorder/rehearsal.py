"""Opt-in, whole-population rehearsal for versioned composite keys.

The rehearsal never trusts an ambiguous legacy U+001F-joined string as an
identity. Every new key is recomputed from the *original source components*
and the declared :class:`TransformSpec`. It produces two independent
compliance contracts per rule:

* ``legacy_blocked`` / ``legacy_clear`` — keep the legacy encoding; any record
  whose transformed component contains U+001F stays blocked pending source
  governance, and the ambiguous legacy string is never split back into a
  tuple.
* ``versioned_cutover`` — cut the whole rule over to the reversible v1
  framing, allowed only when every component is provable, every new key
  survives uniqueness / empty / control / length re-checks across the whole
  population, and every already-indexed inventory key is attributable to
  exactly one source record without mixing encodings.

Nothing here writes to a source or a target database; the rehearsal is pure
derivation over the in-memory scan result.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import TYPE_CHECKING

from .models import (
    CONTRACT_LEGACY_BLOCKED,
    CONTRACT_NOT_ELIGIBLE,
    CONTRACT_VERSIONED_CUTOVER,
    KEY_ENCODING_V1,
    CompositeKeyRehearsal,
    VersionedKeyRow,
)
from .transforms import (
    FRAME_MARKER,
    FRAME_PREFIX,
    FRAME_VERSION,
    UNIT_SEPARATOR,
    apply_transform,
    encode_versioned_key,
    escaped_text,
    is_versioned_key,
    sha256_text,
    utf8_bytes,
)

if TYPE_CHECKING:  # pragma: no cover
    from .models import KeyResult, KeyRule, ScanResult

# Contract A statuses.
LEGACY_CONTRACT_CLEAR = "legacy_clear"


def build_rehearsals(result: "ScanResult") -> list[CompositeKeyRehearsal]:
    """Build one rehearsal per rule that explicitly opts into v1 framing."""

    duplicate_refs = _duplicate_identity_refs(result)
    rehearsals: list[CompositeKeyRehearsal] = []
    for rule in result.config.keys:
        if rule.key_encoding != KEY_ENCODING_V1:
            continue
        rule_results = sorted(
            (item for item in result.key_results if item.rule_id == rule.id),
            key=lambda item: item.ordinal,
        )
        rehearsals.append(
            _build_rule_rehearsal(result.run_id, rule, rule_results, duplicate_refs)
        )
    return rehearsals


def _duplicate_identity_refs(result: "ScanResult") -> dict[str, set[str]]:
    """Source record_refs participating in a DUPLICATE_RECORD_ID finding."""

    grouped: dict[str, set[str]] = defaultdict(set)
    for finding in result.findings:
        if finding.code != "DUPLICATE_RECORD_ID":
            continue
        source_id = finding.source_id or ""
        for ref in finding.details.get("record_refs", []):
            grouped[source_id].add(ref)
    return grouped


def _rehearsal_id(run_id: str, rule_id: str) -> str:
    digest = hashlib.sha256(
        b"rehearsal|"
        + run_id.encode("ascii")
        + b"|"
        + rule_id.encode("utf-8")
    ).hexdigest()
    return "RH-" + digest[:16]


def _build_rule_rehearsal(
    run_id: str,
    rule: "KeyRule",
    results: list["KeyResult"],
    duplicate_refs: dict[str, set[str]],
) -> CompositeKeyRehearsal:
    rows: list[VersionedKeyRow] = []
    legacy_blocked_refs: list[str] = []
    payload_control_refs: list[str] = []
    empty_refs: list[str] = []
    overlength_refs: list[str] = []

    for item in results:
        blockers: list[str] = []
        notes: list[str] = []
        source_components = list(item.raw_values)
        missing = any(value is None for value in source_components)

        if missing:
            blockers.append("REHEARSAL_SOURCE_COMPONENT_MISSING")
        if item.record_ref in duplicate_refs.get(rule.source_id, set()):
            blockers.append("REHEARSAL_RECORD_IDENTITY_DUPLICATE")

        # Recompute transformed components from the authoritative source
        # components and the declared TransformSpec. The ambiguous legacy
        # string is never split to recover a tuple.
        transformed: list[str] | None = None
        if not missing:
            transformed = [
                apply_transform(value, rule.transform)
                for value in source_components
                if value is not None
            ]

        legacy_ambiguous = bool(transformed) and any(
            UNIT_SEPARATOR in component for component in transformed  # type: ignore[union-attr]
        )
        if legacy_ambiguous:
            blockers.append("LEGACY_COMPOSITE_AMBIGUITY")
            legacy_blocked_refs.append(item.record_ref)
            notes.append("legacy 字符串无法倒推分量；legacy 合同下保持 blocked")

        # Versioned key for this row, recomputed independently of the engine.
        source_provable = not missing and not (
            "REHEARSAL_RECORD_IDENTITY_DUPLICATE" in blockers
        )
        versioned_key = item.versioned_key if source_provable else None
        if versioned_key is not None and transformed is not None:
            # Cross-check the engine's frame against an independent rebuild.
            rebuilt = encode_versioned_key(transformed)
            if rebuilt != versioned_key or item.versioned_roundtrip_ok is not True:
                blockers.append("VERSIONED_ROUNDTRIP_FAILED")
                versioned_key = None

        defect_codes = _defect_codes(item)
        if versioned_key is not None:
            if "VERSIONED_KEY_EMPTY" in defect_codes:
                empty_refs.append(item.record_ref)
                blockers.append("VERSIONED_KEY_EMPTY")
            if "VERSIONED_KEY_TOO_LONG" in defect_codes:
                overlength_refs.append(item.record_ref)
                blockers.append("VERSIONED_KEY_TOO_LONG")
            if "VERSIONED_PAYLOAD_CONTROL" in defect_codes:
                # Reversible framing; audited but not itself a cutover block.
                payload_control_refs.append(item.record_ref)
                notes.append("VERSIONED_PAYLOAD_CONTROL")

        rows.append(
            VersionedKeyRow(
                key_result_id=item.key_result_id,
                source_id=item.source_id,
                rule_id=item.rule_id,
                ordinal=item.ordinal,
                record_ref=item.record_ref,
                record_id=item.record_id,
                source_components=source_components,
                transformed_components=transformed,
                legacy_key=item.target_key,
                legacy_key_sha256=item.key_sha256,
                legacy_key_bytes=item.key_bytes,
                versioned_key=versioned_key,
                versioned_key_escaped=item.versioned_key_escaped
                if versioned_key is not None
                else None,
                versioned_key_sha256=item.versioned_key_sha256
                if versioned_key is not None
                else None,
                versioned_key_bytes=item.versioned_key_bytes
                if versioned_key is not None
                else 0,
                versioned_key_chars=item.versioned_key_chars
                if versioned_key is not None
                else 0,
                roundtrip_ok=item.versioned_roundtrip_ok
                if versioned_key is not None
                else None,
                blockers=sorted(set(blockers)),
                notes=notes,
            )
        )

    # Whole-population uniqueness re-check of the new keys.
    versioned_collision_groups = _versioned_collisions(rule, rows)
    legacy_ambiguous_strings = _legacy_ambiguity(rows)

    # Target-index inventory checks.
    (
        unattributable,
        index_mix,
        inventory_collisions,
        inventory_blockers,
    ) = _inventory_checks(rule, rows)

    # ---- Contract A: stay on the legacy encoding --------------------------
    legacy_contract_blockers = sorted(
        {
            blocker
            for row in rows
            for blocker in row.blockers
            if blocker
            in {
                "LEGACY_COMPOSITE_AMBIGUITY",
                "REHEARSAL_SOURCE_COMPONENT_MISSING",
                "REHEARSAL_RECORD_IDENTITY_DUPLICATE",
            }
        }
    )
    legacy_contract = (
        CONTRACT_LEGACY_BLOCKED
        if legacy_contract_blockers
        else LEGACY_CONTRACT_CLEAR
    )

    # ---- Contract B: whole-rule versioned framing cutover -----------------
    versioned_blockers: set[str] = set()
    for row in rows:
        for blocker in row.blockers:
            # Legacy ambiguity is precisely what v1 framing resolves; it is
            # not a blocker for the versioned contract.
            if blocker == "LEGACY_COMPOSITE_AMBIGUITY":
                continue
            versioned_blockers.add(blocker)
    if versioned_collision_groups:
        versioned_blockers.add("VERSIONED_KEY_COLLISION")
    if empty_refs:
        versioned_blockers.add("VERSIONED_KEY_EMPTY")
    if overlength_refs:
        versioned_blockers.add("VERSIONED_KEY_TOO_LONG")
    versioned_blockers.update(inventory_blockers)
    versioned_contract_blockers = sorted(versioned_blockers)
    versioned_contract = (
        CONTRACT_VERSIONED_CUTOVER
        if not versioned_contract_blockers
        else CONTRACT_NOT_ELIGIBLE
    )

    rollback = _rollback_plan(rule, rows, versioned_contract)

    return CompositeKeyRehearsal(
        rehearsal_id=_rehearsal_id(run_id, rule.id),
        rule_id=rule.id,
        source_id=rule.source_id,
        encoding=rule.key_encoding,
        frame_version=FRAME_VERSION,
        frame_prefix_escaped=escaped_text(FRAME_PREFIX),
        columns=list(rule.columns),
        transform=rule.transform.as_dict(),
        unique=rule.unique,
        required=rule.required,
        max_bytes=rule.max_bytes,
        max_chars=rule.max_chars,
        rows=rows,
        legacy_contract=legacy_contract,
        legacy_contract_blockers=legacy_contract_blockers,
        blocked_record_refs=sorted(set(legacy_blocked_refs)),
        versioned_contract=versioned_contract,
        versioned_contract_blockers=versioned_contract_blockers,
        versioned_collision_groups=versioned_collision_groups,
        versioned_empty_record_refs=sorted(set(empty_refs)),
        versioned_overlength_record_refs=sorted(set(overlength_refs)),
        payload_control_record_refs=sorted(set(payload_control_refs)),
        inventory_size=len(rule.legacy_key_inventory),
        unattributable_inventory_keys=unattributable,
        index_encoding_mix=index_mix,
        inventory_versioned_collisions=inventory_collisions,
        legacy_ambiguous_strings=legacy_ambiguous_strings,
        rollback=rollback,
    )


def _defect_codes(item: "KeyResult") -> list[str]:
    return [defect.code for defect in item.defects]


def _versioned_collisions(
    rule: "KeyRule", rows: list[VersionedKeyRow]
) -> list[dict[str, object]]:
    groups: dict[str, list[VersionedKeyRow]] = defaultdict(list)
    for row in rows:
        if row.versioned_key is not None:
            groups[row.versioned_key].append(row)
    result: list[dict[str, object]] = []
    for framed_key, members in sorted(groups.items(), key=lambda kv: kv[0]):
        if len(members) < 2:
            continue
        distinct_tuples = {
            tuple(row.transformed_components or []) for row in members
        }
        digest = hashlib.sha256(
            b"v1-collision|" + rule.id.encode("utf-8") + b"|" + utf8_bytes(framed_key)
        ).hexdigest()
        result.append(
            {
                "group_id": "VC-" + digest[:16],
                "versioned_key": framed_key,
                "versioned_key_escaped": escaped_text(framed_key),
                "record_count": len(members),
                "distinct_component_tuples": len(distinct_tuples),
                "record_refs": [row.record_ref for row in members],
                "record_ids": [row.record_id for row in members],
                "reason_code": (
                    "VERSIONED_NORMALIZATION_COLLISION"
                    if len(distinct_tuples) > 1
                    else "VERSIONED_DUPLICATE_KEY"
                ),
            }
        )
    return result


def _legacy_ambiguity(rows: list[VersionedKeyRow]) -> list[dict[str, object]]:
    """Group rows by the *legacy* string and expose distinct source tuples.

    Two tuples such as ``(a\\x1fb, c)`` and ``(a, b\\x1fc)`` produce the same
    legacy bytes but remain distinct rows because identity comes from the
    source components, never from splitting the legacy string.
    """

    by_legacy: dict[str, list[VersionedKeyRow]] = defaultdict(list)
    for row in rows:
        if row.legacy_key is not None:
            by_legacy[row.legacy_key].append(row)
    ambiguous: list[dict[str, object]] = []
    for legacy_key, members in sorted(by_legacy.items(), key=lambda kv: kv[0]):
        distinct_tuples = {tuple(row.source_components) for row in members}
        if UNIT_SEPARATOR not in legacy_key or len(distinct_tuples) < 2:
            continue
        ambiguous.append(
            {
                "legacy_key_escaped": escaped_text(legacy_key),
                "legacy_key_sha256": sha256_text(legacy_key),
                "distinct_component_tuples": len(distinct_tuples),
                "record_refs": [row.record_ref for row in members],
                "tuples": [
                    [
                        escaped_text(part) if part is not None else None
                        for part in tuple_
                    ]
                    for tuple_ in sorted(distinct_tuples, key=lambda t: repr(t))
                ],
                "resolution": (
                    "legacy 合同：保持 blocked；不得据同一串合并为同一业务对象"
                ),
            }
        )
    return ambiguous


def _inventory_checks(
    rule: "KeyRule", rows: list[VersionedKeyRow]
) -> tuple[
    list[dict[str, object]],
    bool,
    list[dict[str, object]],
    list[str],
]:
    blockers: list[str] = []
    legacy_index: dict[str, list[VersionedKeyRow]] = defaultdict(list)
    versioned_index: dict[str, list[VersionedKeyRow]] = defaultdict(list)
    for row in rows:
        if row.legacy_key is not None:
            legacy_index[row.legacy_key].append(row)
        if row.versioned_key is not None:
            versioned_index[row.versioned_key].append(row)

    inventory_versioned = [
        key for key in rule.legacy_key_inventory if is_versioned_key(key)
    ]
    inventory_legacy = [
        key for key in rule.legacy_key_inventory if not is_versioned_key(key)
    ]
    # A single target index must never mix version-less legacy and framed v1
    # encodings without a version discriminator.
    index_mix = bool(inventory_versioned) and bool(inventory_legacy)
    if index_mix:
        blockers.append("TARGET_INDEX_ENCODING_MIX")

    # A legacy-looking key that starts with the frame marker but fails the
    # frame grammar would be silently misread as v1; flag it explicitly.
    marker_conflicts = [key for key in inventory_legacy if key.startswith(FRAME_MARKER)]
    if marker_conflicts:
        blockers.append("VERSION_MARKER_CONFLICT")

    unattributable: list[dict[str, object]] = []
    for key in rule.legacy_key_inventory:
        framed = is_versioned_key(key)
        candidates = (
            versioned_index.get(key, []) if framed else legacy_index.get(key, [])
        )
        if len(candidates) != 1:
            unattributable.append(
                {
                    "inventory_key_escaped": escaped_text(key),
                    "inventory_key_sha256": sha256_text(key),
                    "encoding": FRAME_VERSION if framed else "legacy",
                    "matching_records": len(candidates),
                    "reason": (
                        "no_source_match" if not candidates else "ambiguous_multiple_matches"
                    ),
                }
            )
    if unattributable:
        blockers.append("LEGACY_KEY_UNATTRIBUTABLE")

    # New v1 keys colliding with keys already present as v1 in the index.
    inventory_collisions: list[dict[str, object]] = []
    versioned_inventory_set = set(inventory_versioned)
    for framed_key, members in sorted(versioned_index.items(), key=lambda kv: kv[0]):
        if framed_key in versioned_inventory_set:
            inventory_collisions.append(
                {
                    "versioned_key_escaped": escaped_text(framed_key),
                    "record_refs": [row.record_ref for row in members],
                    "reason_code": "VERSIONED_INVENTORY_COLLISION",
                }
            )
    if inventory_collisions:
        blockers.append("VERSIONED_KEY_COLLISION")

    return (
        unattributable,
        index_mix,
        inventory_collisions,
        sorted(set(blockers)),
    )


def _rollback_plan(
    rule: "KeyRule",
    rows: list[VersionedKeyRow],
    versioned_contract: str,
) -> dict[str, object]:
    # Rollback evidence: the exact original components needed to rebuild the
    # legacy key, plus the transform spec, per record. No target writes occur.
    per_record = [
        {
            "record_ref": row.record_ref,
            "record_id": row.record_id,
            "source_columns": list(rule.columns),
            "original_components": row.source_components,
            "legacy_key": row.legacy_key,
            "legacy_key_sha256": row.legacy_key_sha256,
            "versioned_key_sha256": row.versioned_key_sha256,
            "rollback_action": (
                "以 original_components 经同一 TransformSpec 重算 legacy U+001F 键；"
                "不得从 legacy 串反向拆分"
            ),
        }
        for row in rows
        if row.versioned_key is not None
    ]
    return {
        "strategy": "per_record_source_recompute",
        "transform": rule.transform.as_dict(),
        "frame_version": FRAME_VERSION,
        "cutover_contract": versioned_contract,
        "record_count": len(per_record),
        "records": per_record,
        "forbidden": [
            "不得仅凭 legacy U+001F 字符串拆分旧对象",
            "不得在同一目标索引混用无版本区分的 legacy/v1 键",
            "不得因编码可逆而跳过唯一性与长度门禁",
        ],
    }
