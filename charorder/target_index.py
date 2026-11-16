"""Offline target-unique-index rehearsal and adjudication enforcement.

The rehearsal builds one *projection view* per declared target index: every
affected target key is re-checked for uniqueness and byte/char length in the
same view. Reviewed adjudications (merge / split) are validated against the
current input snapshot and rule digests before they are allowed to reshape the
projection. Nothing is written back to any source.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from .models import (
    AdjudicationDocument,
    AppConfig,
    KeyAdjudication,
    KeyResult,
    KeyRule,
    ProjectedTargetRow,
    ReplacementAssignment,
    TargetCollisionGroup,
    TargetIndexRehearsal,
    TargetIndexSpec,
)
from .transforms import escaped_text, sanitize_text, sha256_text, utf8_bytes

FindingSink = Callable[..., None]


def rule_digest(rule: KeyRule) -> str:
    """Content digest of a rule's key semantics, used to bind adjudications."""

    payload = {
        "rule_id": rule.id,
        "source_id": rule.source_id,
        "columns": list(rule.columns),
        "transform": rule.transform.as_dict(),
        "destination": rule.destination,
        "max_bytes": rule.max_bytes,
        "max_chars": rule.max_chars,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return digest


def _identity(result: KeyResult) -> tuple[str, str, str]:
    return result.source_id, result.rule_id, result.record_ref


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_expiry(expires_at: str | None) -> datetime | None:
    if not expires_at:
        return None
    return datetime.fromisoformat(expires_at.replace("Z", "+00:00"))


def rehearse_index(
    config: AppConfig,
    spec: TargetIndexSpec,
    key_results: list[KeyResult],
    input_sha256: dict[str, str],
    run_id: str,
    add_finding: FindingSink,
) -> TargetIndexRehearsal:
    evaluated_at = _now_iso()
    rule_lookup = config.key_map
    rule_digests = {rule.id: rule_digest(rule) for rule in config.keys}
    doc = next(
        (item for item in config.adjudications if item.index_id == spec.id), None
    )

    # ---- document-level binding / expiry (once per index) ----------------
    doc_stale = False
    doc_block_reasons: list[str] = []
    if doc is not None:
        if doc.config_sha256 != config.config_sha256:
            doc_stale = True
            doc_block_reasons.append("ADJUDICATION_CONFIG_MISMATCH")
        if dict(doc.input_sha256) != dict(sorted(input_sha256.items())):
            doc_stale = True
            doc_block_reasons.append("ADJUDICATION_INPUT_MISMATCH")
        expiry = _parse_expiry(doc.expires_at)
        if expiry is not None and expiry <= datetime.now(timezone.utc):
            doc_stale = True
            doc_block_reasons.append("ADJUDICATION_EXPIRED")
        if doc_stale:
            add_finding(
                "TARGET_ADJUDICATION_STALE",
                (
                    f"目标索引 {spec.id} 的裁决台账绑定失效（"
                    + ", ".join(doc_block_reasons)
                    + "），其中所有裁决均不得放行。"
                ),
                details={
                    "index_id": spec.id,
                    "reasons": doc_block_reasons,
                    "adjudication_file": str(doc.path),
                    "doc_sha256": doc.doc_sha256,
                    "expires_at": doc.expires_at,
                },
            )

    # ---- collect candidate key results for this index --------------------
    rule_ids = set(spec.rule_ids)
    candidates = [
        result
        for result in key_results
        if result.rule_id in rule_ids and result.target_key is not None
    ]

    by_key: dict[str, list[KeyResult]] = defaultdict(list)
    for result in candidates:
        by_key[result.target_key].append(result)

    groups: list[TargetCollisionGroup] = []
    decision_by_key: dict[str, KeyAdjudication] = {}
    if doc is not None:
        for decision in doc.decisions:
            decision_by_key[decision.target_key] = decision

    # source-record occupancy across all decisions in this index. This is a
    # structural contradiction independent of binding freshness, so it is
    # evaluated even when the document is stale.
    occupied: dict[tuple[str, str, str], str] = {}
    if doc is not None:
        for decision in doc.decisions:
            for member in decision.members:
                identity = (member.source_id, member.rule_id, member.record_ref)
                if identity in occupied and occupied[identity] != decision.adjudication_id:
                    add_finding(
                        "TARGET_ADJUDICATION_CONFLICT",
                        (
                            f"来源记录 {member.source_id}/{member.rule_id}/"
                            f"{member.record_ref} 同时被裁决 "
                            f"{occupied[identity]} 与 {decision.adjudication_id} 占用，"
                            "同一旧记录不得参与两组矛盾裁决。"
                        ),
                        source_id=member.source_id,
                        rule_id=member.rule_id,
                        record_ref=member.record_ref,
                        details={
                            "index_id": spec.id,
                            "identity": list(identity),
                            "adjudication_ids": [
                                occupied[identity],
                                decision.adjudication_id,
                            ],
                        },
                    )
                else:
                    occupied[identity] = decision.adjudication_id

    def _group_id(target_key: str) -> str:
        digest = hashlib.sha256(
            b"target-collision|"
            + run_id.encode("ascii")
            + b"|"
            + spec.id.encode("utf-8")
            + b"|"
            + utf8_bytes(target_key)
        ).hexdigest()
        return "T-" + digest[:16]

    # ---- build collision groups and adjudicate them ----------------------
    for target_key in sorted(by_key):
        participants = sorted(
            by_key[target_key],
            key=lambda item: (item.source_id, item.rule_id, item.ordinal),
        )
        if len(participants) < 2:
            continue
        group = TargetCollisionGroup(
            group_id=_group_id(target_key),
            index_id=spec.id,
            target_key=sanitize_text(target_key),
            target_key_escaped=escaped_text(sanitize_text(target_key)),
            target_key_bytes=len(utf8_bytes(target_key)),
            reason_code=_group_reason(participants),
            participants=participants,
            raw_variants=sorted({item.raw_display for item in participants}),
            sources=sorted({item.source_id for item in participants}),
            rule_ids=sorted({item.rule_id for item in participants}),
        )
        add_finding(
            "TARGET_INDEX_COLLISION",
            (
                f"目标唯一索引 {spec.id} 中 {len(participants)} 条跨来源记录映射到同一目标键 "
                f"{group.target_key_escaped}，必须经人工裁决后才能建索引。"
            ),
            details={
                "index_id": spec.id,
                "group_id": group.group_id,
                "target_key_escaped": group.target_key_escaped,
                "target_key_sha256": sha256_text(target_key),
                "sources": group.sources,
                "rule_ids": group.rule_ids,
                "record_count": len(participants),
                "distinct_raw_count": len(group.raw_variants),
            },
        )
        _adjudicate_group(
            config=config,
            spec=spec,
            group=group,
            doc=doc,
            decision=decision_by_key.get(target_key),
            doc_stale=doc_stale,
            occupied=occupied,
            rule_digests=rule_digests,
            add_finding=add_finding,
        )
        groups.append(group)

    # ---- build the provisional single projection view --------------------
    collision_keys = {group.target_key for group in groups}

    def _build_projection() -> list[ProjectedTargetRow]:
        rows: list[ProjectedTargetRow] = []
        for group in groups:
            if group.decision in {"merge", "split"} and not group.block_reasons:
                rows.extend(group.projected_targets)
            else:
                # blocked groups remain projected as their raw colliding key so
                # reviewers can see exactly which rows the unique index rejects.
                for participant in group.participants:
                    rows.append(
                        _row(
                            spec,
                            target_key=participant.target_key or group.target_key,
                            provenance=[_provenance(participant, rule_digests)],
                            origin="blocked",
                            group=group,
                        )
                    )
        for target_key in sorted(by_key):
            if target_key in collision_keys:
                continue
            for result in by_key[target_key]:
                rows.append(
                    _row(
                        spec,
                        target_key=target_key,
                        provenance=[_provenance(result, rule_digests)],
                        origin="untouched",
                    )
                )
        return rows

    projection = _build_projection()

    # ---- global uniqueness re-check over the whole projection ------------
    rows_by_key: dict[str, list[ProjectedTargetRow]] = defaultdict(list)
    for row in projection:
        rows_by_key[row.target_key].append(row)

    projection_duplicates: list[dict[str, Any]] = []
    replacement_collision_seen: set[tuple[str, str, str]] = set()
    for key in sorted(rows_by_key):
        rows = rows_by_key[key]
        if len(rows) < 2:
            continue
        origins = {row.origin for row in rows}
        group_ids = {row.collision_group_id for row in rows if row.collision_group_id}
        # Open/blocked collision groups are already reported per group.
        if origins == {"blocked"} and len(group_ids) == 1:
            continue
        replacement_rows = [row for row in rows if row.origin == "replacement"]
        if replacement_rows:
            for row in replacement_rows:
                dedupe_key = (row.index_id, row.target_key, row.collision_group_id or "")
                if dedupe_key in replacement_collision_seen:
                    continue
                replacement_collision_seen.add(dedupe_key)
                add_finding(
                    "TARGET_REPLACEMENT_COLLISION",
                    (
                        f"目标索引 {spec.id} 的替代键 {row.target_key_escaped} "
                        "在完整投影中再次撞键，替代方案不能放行。"
                    ),
                    details={
                        "index_id": spec.id,
                        "target_key_escaped": row.target_key_escaped,
                        "target_key_sha256": sha256_text(row.target_key),
                        "collision_group_id": row.collision_group_id,
                        "adjudication_id": row.adjudication_id,
                        "row_count": len(rows),
                        "origins": sorted(origins),
                    },
                )
                if row.collision_group_id:
                    match = next(
                        (g for g in groups if g.group_id == row.collision_group_id), None
                    )
                    if match is not None:
                        match.block_reasons.append("TARGET_REPLACEMENT_COLLISION")
                        match.decision = "invalid"
        else:
            add_finding(
                "TARGET_PROJECTION_DUPLICATE",
                (
                    f"目标索引 {spec.id} 的完整投影中仍有 {len(rows)} 行共享键 "
                    f"{escaped_text(key)}，不允许只移除旧碰撞而留下新碰撞。"
                ),
                details={
                    "index_id": spec.id,
                    "target_key_escaped": escaped_text(key),
                    "target_key_sha256": sha256_text(key),
                    "row_count": len(rows),
                    "origins": sorted(origins),
                },
            )
        projection_duplicates.append(
            {
                "target_key_escaped": escaped_text(key),
                "target_key_sha256": sha256_text(key),
                "row_count": len(rows),
                "origins": sorted(origins),
            }
        )

    # ---- global length re-check over the whole projection ----------------
    projection_overlength: list[dict[str, Any]] = []
    for row in projection:
        over_bytes = (
            spec.max_bytes is not None and row.key_bytes > spec.max_bytes
        )
        over_chars = (
            spec.max_chars is not None and row.key_chars > spec.max_chars
        )
        row.over_bytes = over_bytes
        row.over_chars = over_chars
        if not (over_bytes or over_chars):
            continue
        if row.origin == "replacement":
            code = "TARGET_REPLACEMENT_OVERLENGTH"
            message = (
                f"目标索引 {spec.id} 的替代键 {row.target_key_escaped} 为 "
                f"{row.key_bytes} 字节 / {row.key_chars} 字符，超出索引长度约束。"
            )
            if row.collision_group_id:
                match = next(
                    (g for g in groups if g.group_id == row.collision_group_id), None
                )
                if match is not None:
                    match.block_reasons.append(code)
                    match.decision = "invalid"
        else:
            code = "TARGET_PROJECTION_OVERLENGTH"
            message = (
                f"目标索引 {spec.id} 投影键 {row.target_key_escaped} 为 "
                f"{row.key_bytes} 字节 / {row.key_chars} 字符，超出索引长度约束。"
            )
        projection_overlength.append(
            {
                "target_key_escaped": row.target_key_escaped,
                "key_bytes": row.key_bytes,
                "key_chars": row.key_chars,
                "max_bytes": spec.max_bytes,
                "max_chars": spec.max_chars,
                "origin": row.origin,
                "collision_group_id": row.collision_group_id,
            }
        )
        add_finding(
            code,
            message,
            details={
                "index_id": spec.id,
                "target_key_escaped": row.target_key_escaped,
                "key_bytes": row.key_bytes,
                "key_chars": row.key_chars,
                "max_bytes": spec.max_bytes,
                "max_chars": spec.max_chars,
                "origin": row.origin,
                "collision_group_id": row.collision_group_id,
            },
        )

    # Global cascade checks may have invalidated merge/split groups. Rebuild
    # the projection so invalidated groups fall back to their raw blocked rows,
    # then flag length violations on the rows that replaced them.
    finalized_projection = _build_projection()
    if [
        (row.target_key, row.origin, row.collision_group_id)
        for row in finalized_projection
    ] != [
        (row.target_key, row.origin, row.collision_group_id) for row in projection
    ]:
        projection = finalized_projection
        known = {
            (item["target_key_escaped"], item["origin"])
            for item in projection_overlength
        }
        for row in projection:
            over_bytes = spec.max_bytes is not None and row.key_bytes > spec.max_bytes
            over_chars = spec.max_chars is not None and row.key_chars > spec.max_chars
            row.over_bytes = over_bytes
            row.over_chars = over_chars
            if not (over_bytes or over_chars):
                continue
            if (row.target_key_escaped, row.origin) in known:
                continue
            known.add((row.target_key_escaped, row.origin))
            code = (
                "TARGET_REPLACEMENT_OVERLENGTH"
                if row.origin == "replacement"
                else "TARGET_PROJECTION_OVERLENGTH"
            )
            projection_overlength.append(
                {
                    "target_key_escaped": row.target_key_escaped,
                    "key_bytes": row.key_bytes,
                    "key_chars": row.key_chars,
                    "max_bytes": spec.max_bytes,
                    "max_chars": spec.max_chars,
                    "origin": row.origin,
                    "collision_group_id": row.collision_group_id,
                }
            )
            add_finding(
                code,
                (
                    f"目标索引 {spec.id} 投影键 {row.target_key_escaped} 为 "
                    f"{row.key_bytes} 字节 / {row.key_chars} 字符，超出索引长度约束。"
                ),
                details={
                    "index_id": spec.id,
                    "target_key_escaped": row.target_key_escaped,
                    "key_bytes": row.key_bytes,
                    "key_chars": row.key_chars,
                    "max_bytes": spec.max_bytes,
                    "max_chars": spec.max_chars,
                    "origin": row.origin,
                    "collision_group_id": row.collision_group,
                },
            )
    else:
        projection = finalized_projection

    # ---- finalize group state after global cascade checks ----------------
    block_reasons: list[str] = []
    for group in groups:
        if group.block_reasons or group.decision in {"open", "invalid"}:
            for reason in group.block_reasons or (
                ["TARGET_ADJUDICATION_MISSING"] if group.decision == "open" else []
            ):
                block_reasons.append(f"{group.group_id}:{reason}")

    register = _adjudication_register(spec, groups, doc, doc_stale)
    blocked = bool(groups) and any(
        group.decision in {"open", "invalid"} or group.block_reasons
        for group in groups
    )
    blocked = blocked or bool(projection_duplicates) or bool(projection_overlength)

    return TargetIndexRehearsal(
        spec=spec,
        groups=groups,
        projection=projection,
        projection_duplicates=projection_duplicates,
        projection_overlength=projection_overlength,
        adjudication_register=register,
        block_reasons=sorted(set(block_reasons)),
        blocked=blocked,
        projected_row_count=len(projection),
        evaluated_at=evaluated_at,
        stale=doc_stale,
    )


def _group_reason(participants: list[KeyResult]) -> str:
    distinct_sources = {item.source_id for item in participants}
    if len(distinct_sources) > 1:
        return "CROSS_SOURCE_COLLISION"
    distinct_raw = {item.raw_display for item in participants}
    if len(distinct_raw) > 1:
        return "NORMALIZATION_COLLISION"
    return "DUPLICATE_KEY"


def _adjudicate_group(
    *,
    config: AppConfig,
    spec: TargetIndexSpec,
    group: TargetCollisionGroup,
    doc: AdjudicationDocument | None,
    decision: KeyAdjudication | None,
    doc_stale: bool,
    occupied: dict[tuple[str, str, str], str],
    rule_digests: dict[str, str],
    add_finding: FindingSink,
) -> None:
    if doc is None or decision is None:
        group.decision = "open"
        group.block_reasons.append("TARGET_ADJUDICATION_MISSING")
        add_finding(
            "TARGET_ADJUDICATION_MISSING",
            (
                f"目标索引 {spec.id} 碰撞组 {group.group_id}（键 "
                f"{group.target_key_escaped}）没有对应裁决，目标唯一索引必须阻断。"
            ),
            details={
                "index_id": spec.id,
                "group_id": group.group_id,
                "target_key_escaped": group.target_key_escaped,
            },
        )
        return
    if doc_stale:
        group.decision = "invalid"
        group.adjudication_id = decision.adjudication_id
        group.block_reasons.append("TARGET_ADJUDICATION_STALE")
        return

    group.adjudication_id = decision.adjudication_id
    group.adjudication = decision
    participant_index = {_identity(p): p for p in group.participants}
    member_identities = {
        (m.source_id, m.rule_id, m.record_ref) for m in decision.members
    }
    participant_identities = set(participant_index)

    invalid_reasons: list[str] = []
    unknown = sorted(member_identities - participant_identities)
    if unknown:
        invalid_reasons.append("MEMBER_IDENTITY_NOT_FOUND")
    missing = sorted(participant_identities - member_identities)
    if missing:
        invalid_reasons.append("MEMBER_IDENTITY_MISSING")

    # digest / raw / key binding against this very run
    for member in decision.members:
        participant = participant_index.get(
            (member.source_id, member.rule_id, member.record_ref)
        )
        if participant is None:
            continue
        if rule_digests.get(member.rule_id) != member.rule_digest:
            invalid_reasons.append("RULE_DIGEST_MISMATCH")
        if participant.target_key != member.target_key:
            invalid_reasons.append("TARGET_KEY_MISMATCH")
        if participant.raw_display != member.raw_display:
            invalid_reasons.append("RAW_VALUE_MISMATCH")

    # same source record claimed by two contradictory decisions
    conflicted = sorted(
        {
            identity
            for identity in member_identities
            if occupied.get(identity) not in (None, decision.adjudication_id)
        }
    )
    if conflicted:
        invalid_reasons.append("IDENTITY_DOUBLE_OCCUPANCY")

    invalid_reasons = sorted(set(invalid_reasons))
    if invalid_reasons:
        group.decision = "invalid"
        group.block_reasons.extend(
            f"TARGET_ADJUDICATION_INVALID:{reason}" for reason in invalid_reasons
        )
        add_finding(
            "TARGET_ADJUDICATION_INVALID",
            (
                f"目标索引 {spec.id} 碰撞组 {group.group_id} 的裁决 "
                f"{decision.adjudication_id} 引用失效（"
                + ", ".join(invalid_reasons)
                + "），目标唯一索引必须阻断。"
            ),
            details={
                "index_id": spec.id,
                "group_id": group.group_id,
                "adjudication_id": decision.adjudication_id,
                "reasons": invalid_reasons,
                "unknown_identities": [list(item) for item in unknown],
                "missing_identities": [list(item) for item in missing],
                "conflicted_identities": [list(item) for item in conflicted],
            },
        )
        return

    if decision.decision == "merge":
        group.decision = "merge"
        group.projected_targets = [
            _row(
                spec,
                target_key=group.target_key,
                provenance=[
                    _provenance(participant_index[identity], rule_digests)
                    for identity in sorted(member_identities)
                ],
                origin="merge",
                group=group,
                adjudication=decision,
            )
        ]
        return

    # split: one distinct, verifiable replacement per entity
    group.decision = "split"
    rows: list[ProjectedTargetRow] = []
    seen_replacement: dict[str, ReplacementAssignment] = {}
    for replacement in decision.replacements:
        identity = (
            replacement.source_id,
            replacement.rule_id,
            replacement.record_ref,
        )
        participant = participant_index[identity]
        if replacement.replacement_key == group.target_key:
            group.block_reasons.append("TARGET_REPLACEMENT_COLLISION:STILL_SHARED_KEY")
        seen_replacement[replacement.replacement_key] = replacement
        rows.append(
            _row(
                spec,
                target_key=replacement.replacement_key,
                provenance=[_provenance(participant, rule_digests)],
                origin="replacement",
                group=group,
                adjudication=decision,
            )
        )
    if len(seen_replacement) != len(decision.replacements):
        group.block_reasons.append("TARGET_REPLACEMENT_COLLISION:DUPLICATE_WITHIN_GROUP")
    group.projected_targets = rows


def _provenance(
    result: KeyResult, rule_digests: dict[str, str]
) -> dict[str, Any]:
    return {
        "key_result_id": result.key_result_id,
        "source_id": result.source_id,
        "rule_id": result.rule_id,
        "record_ref": result.record_ref,
        "record_id": result.record_id,
        "raw_values": list(result.raw_values),
        "raw_display": result.raw_display,
        "declared_target_key": result.target_key,
        "declared_target_key_escaped": result.target_key_escaped,
        "declared_key_bytes": result.key_bytes,
        "rule_digest": rule_digests.get(result.rule_id),
    }


def _row(
    spec: TargetIndexSpec,
    *,
    target_key: str,
    provenance: list[dict[str, Any]],
    origin: str,
    group: TargetCollisionGroup | None = None,
    adjudication: KeyAdjudication | None = None,
) -> ProjectedTargetRow:
    safe_key = sanitize_text(target_key)
    return ProjectedTargetRow(
        index_id=spec.id,
        target_key=safe_key,
        target_key_escaped=escaped_text(safe_key),
        key_bytes=len(utf8_bytes(safe_key)),
        key_chars=len(safe_key),
        provenance=provenance,
        origin=origin,
        collision_group_id=group.group_id if group is not None else None,
        adjudication_id=(
            adjudication.adjudication_id
            if adjudication is not None
            else group.adjudication_id if group is not None else None
        ),
    )


def _adjudication_register(
    spec: TargetIndexSpec,
    groups: list[TargetCollisionGroup],
    doc: AdjudicationDocument | None,
    doc_stale: bool,
) -> list[dict[str, Any]]:
    if doc is None:
        return []
    group_by_decision = {
        group.adjudication_id: group for group in groups if group.adjudication_id
    }
    register: list[dict[str, Any]] = []
    for decision in doc.decisions:
        group = group_by_decision.get(decision.adjudication_id)
        register.append(
            {
                "adjudication_id": decision.adjudication_id,
                "target_key_escaped": escaped_text(decision.target_key),
                "decision": decision.decision,
                "reviewed_by": decision.reviewed_by,
                "reviewed_at": decision.reviewed_at,
                "expires_at": doc.expires_at,
                "doc_sha256": doc.doc_sha256,
                "stale": doc_stale,
                "member_count": len(decision.members),
                "replacement_count": len(decision.replacements),
                "group_id": group.group_id if group is not None else None,
                "applied": (
                    group is not None
                    and group.decision in {"merge", "split"}
                    and not group.block_reasons
                ),
                "block_reasons": list(group.block_reasons) if group is not None else [
                    "TARGET_ADJUDICATION_INVALID:NO_MATCHING_GROUP"
                ],
            }
        )
    register.sort(key=lambda item: item["adjudication_id"])
    return register
