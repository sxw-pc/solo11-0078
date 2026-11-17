"""Rule-adjustment preflight: search whole rule configurations.

The optimizer is intentionally independent from the baseline scan.  Every
candidate rule selection is re-evaluated on the complete set of records of the
affected sources, in the same transform order as the regular engine
(``compute_target_key``).  It never edits, merges, drops or re-keys individual
records; only whole ``TransformSpec`` choices are allowed.

Hard constraints, all enforced for every candidate configuration:

* required components must be present;
* a unique rule must map its records to distinct target keys;
* different entities in the same target table must not share a key;
* ``max_bytes`` / ``max_chars`` must hold;
* transformed components must not contain the reserved ``U+001F`` separator;
* every authorized cross-table link must have byte-identical keys on both
  sides;
* every caller-declared forbidden pair must differ;
* by default, no *unauthorized* cross-table pair may share a key.

Two independent objectives are solved over the set of feasible whole-rule
selections: (1) fewest records whose target key changes, and (2) smallest
total UTF-8 byte count across all related target keys.  Both break ties by the
caller-provided candidate order.  When the search budget is exhausted the
result is explicitly marked provisional / unknown, never optimal or cleared.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .models import (
    AppConfig,
    AuthorizedLink,
    KeyResult,
    KeyRule,
    PreflightEvaluation,
    PreflightKeyEvidence,
    PreflightResult,
    PreflightSpec,
    RecordRef,
    SourceLoad,
    SourceRecord,
    TransformSpec,
    rule_summary,
    rule_summary_digest,
)
from .transforms import (
    compute_target_key,
    escaped_text,
    sha256_text,
)

_OBJECTIVES = ("min_changed_records", "min_total_bytes")
_PROVISIONAL_EXIT = 10
_OPTIMAL_EXIT = 0
_NO_FEASIBLE_EXIT = 20
_BLOCKED_EXIT = 30
_MAX_DIAGNOSTICS = 40
_MAX_WITNESS_CATEGORIES = 24


@dataclass(frozen=True)
class _Variant:
    key: str | None
    key_bytes: int
    key_chars: int
    changed: bool
    missing_required: bool
    separator: bool
    too_long_bytes: bool
    too_long_chars: bool
    empty: bool


@dataclass
class _Choice:
    """One concrete whole-rule selection (candidate index per rule)."""

    rank: int
    combo: tuple[int, ...]
    by_rule: dict[str, int]


@dataclass
class _Eval:
    feasible: bool
    changed_records: int
    total_bytes: int
    violations: list[dict[str, Any]]
    checks: dict[str, Any]


def optimize(
    config: AppConfig,
    loads: Sequence[SourceLoad],
    key_results: Sequence[KeyResult],
    *,
    run_id: str,
    config_sha256: str,
) -> PreflightResult | None:
    """Run the rule-adjustment preflight. Returns ``None`` when not configured."""

    spec = config.preflight
    if spec is None:
        return None

    source_digest = _source_digest(loads)
    candidate_rules = [rule for rule in config.keys if rule.selectable]
    candidate_rule_ids = [rule.id for rule in candidate_rules]
    candidate_order = _candidate_order(candidate_rules)
    total_combinations = 1
    for rule in candidate_rules:
        total_combinations *= len(rule.candidates)

    base = PreflightResult(
        run_id=run_id,
        config_sha256=config_sha256,
        source_digest=source_digest,
        rules_sha256=rule_summary_digest(config.keys),
        constraint_digest=spec.constraint_sha256,
        stale=False,
        stale_reasons=[],
        candidate_rule_ids=candidate_rule_ids,
        total_combinations=total_combinations,
        examined_combinations=0,
        budget_exhausted=False,
        candidate_order=candidate_order,
        objective_results={objective: None for objective in _OBJECTIVES},
        witness=None,
        state="unknown",
        notes=[],
        config_summary=_config_summary(config, source_digest, spec),
    )

    # ---- identity and binding validation ---------------------------------
    records_by_source: dict[str, dict[str, SourceRecord]] = {}
    ambiguous: list[dict[str, Any]] = []
    for load in loads:
        seen: dict[str, SourceRecord] = {}
        for record in load.records:
            if record.record_ref in seen:
                ambiguous.append(
                    {
                        "source_id": load.spec.id,
                        "record_ref": record.record_ref,
                        "reason": "record_ref appears more than once in this source",
                    }
                )
                continue
            seen[record.record_ref] = record
        records_by_source[load.spec.id] = seen

    stale_reasons: list[str] = []
    for source_id, expected in sorted(spec.expected_sources_sha256.items()):
        actual = next(
            (load.sha256 for load in loads if load.spec.id == source_id), None
        )
        if actual is None:
            stale_reasons.append(f"绑定的源 {source_id} 不在本次输入中")
        elif actual != expected:
            stale_reasons.append(
                f"源 {source_id} 的 SHA-256 已变化：预期 {expected[:16]}…，"
                f"实际 {actual[:16]}…"
            )
    # Every source referenced by any candidate or relation identity must be
    # present in this run; a silent substitution of a source is stale evidence.
    bound_sources = {
        rule.source_id for rule in config.keys if rule.selectable
    }
    for ref in _all_refs(spec):
        bound_sources.add(ref.source_id)
    present_sources = {load.spec.id for load in loads}
    for source_id in sorted(bound_sources - present_sources):
        stale_reasons.append(f"清单绑定的源 {source_id} 不在本次输入中")
    # If the caller bound the exact source set with a digest, any change to
    # the inputs, or to the rules, invalidates the whole preflight.
    if spec.expected_source_digest and spec.expected_source_digest != source_digest:
        stale_reasons.append(
            "源摘要与预检清单绑定值不一致："
            f"预期 {spec.expected_source_digest[:16]}…，"
            f"实际 {source_digest[:16]}…"
        )
    # Bind the rule summary too: a change to a transform, candidate list,
    # uniqueness flag, or length limit invalidates the preflight.
    if spec.expected_rules_sha256:
        current_rules_digest = rule_summary_digest(config.keys)
        if current_rules_digest != spec.expected_rules_sha256:
            stale_reasons.append(
                "规则摘要与预检清单绑定值不一致："
                f"预期 {spec.expected_rules_sha256[:16]}…，"
                f"实际 {current_rules_digest[:16]}…"
            )

    identity_errors: list[dict[str, Any]] = []
    for link in spec.authorized_links:
        identity_errors.extend(
            _validate_ref(link.left, records_by_source, config)
        )
        identity_errors.extend(
            _validate_ref(link.right, records_by_source, config)
        )
    for pair in spec.forbidden_pairs:
        identity_errors.extend(
            _validate_ref(pair.left, records_by_source, config)
        )
        identity_errors.extend(
            _validate_ref(pair.right, records_by_source, config)
        )
    identity_errors.extend(
        {
            "reason": "ambiguous_record_identity",
            **item,
        }
        for item in ambiguous
    )

    contradiction_notes: list[str] = []
    ref_links: dict[tuple[str, str, str], list[AuthorizedLink]] = {}
    for link in spec.authorized_links:
        ref_links.setdefault(link.left.key(), []).append(link)
        ref_links.setdefault(link.right.key(), []).append(link)
    for ref_key, links in sorted(ref_links.items()):
        if len(links) > 1:
            contradiction_notes.append(
                "记录身份在已授权关联中出现多次，不满足一对一："
                f"{ref_key[0]}/{ref_key[1]}/{ref_key[2]}"
            )
    authorized_pairs = {
        _pair_key(link.left, link.right) for link in spec.authorized_links
    }
    for pair in spec.forbidden_pairs:
        if _pair_key(pair.left, pair.right) in authorized_pairs:
            contradiction_notes.append(
                f"记录对 {pair.pair_id} 同时出现在已授权关联与禁止同键清单中"
            )

    if stale_reasons:
        base.stale = True
        base.stale_reasons = stale_reasons
        base.state = "stale"
        base.notes = [
            "输入或规则清单与预检清单绑定的摘要不一致，预检结果不得用于放行。",
        ]
        for objective in _OBJECTIVES:
            base.objective_results[objective] = None
        return base
    if identity_errors:
        base.state = "identity_invalid"
        base.notes = [
            "存在无法解析或重复的记录身份；过期或歧义的关联身份不能给出放行结论。",
        ]
        base.witness = {"identity_errors": identity_errors[:50]}
        return base
    if contradiction_notes:
        base.state = "constraint_invalid"
        base.notes = contradiction_notes
        return base

    # ---- per-rule record inventory and precomputed variants --------------
    rule_records: dict[str, list[SourceRecord]] = {
        rule.id: list(records_by_source.get(rule.source_id, {}).values())
        for rule in config.keys
    }
    # Preserve source order for deterministic evaluation.
    for rule in config.keys:
        rule_records[rule.id].sort(key=lambda record: record.ordinal)

    variants: dict[str, list[list[_Variant]]] = {}
    options: dict[str, tuple[TransformSpec, ...]] = {}
    for rule in config.keys:
        opts = rule.candidates if rule.selectable else (rule.transform,)
        options[rule.id] = opts
        variants[rule.id] = [
            [_make_variant(rule, record, spec_) for record in rule_records[rule.id]]
            for spec_ in opts
        ]

    # Old keys are recomputed from the original transform on the same loads.
    old_keys: dict[str, list[_Variant]] = {
        rule.id: [
            _make_variant(rule, record, rule.transform)
            for record in rule_records[rule.id]
        ]
        for rule in config.keys
    }

    # Records participating in relation constraints must exist; ids already
    # validated. Build a lookup for fast constraint checks.
    rule_ref_index: dict[tuple[str, str], int] = {}
    for rule in config.keys:
        for index, record in enumerate(rule_records[rule.id]):
            rule_ref_index[(rule.id, record.record_ref)] = index

    related_rule_ids = set(candidate_rule_ids)
    for ref in _all_refs(spec):
        related_rule_ids.add(ref.rule_id)
    # Records in the same target table as a related rule are part of the same
    # uniqueness namespace and therefore relevant to the objective metrics and
    # evidence, even if their transform is fixed.
    related_units = {
        rule.target_unit
        for rule in config.keys
        if rule.id in related_rule_ids
    }
    for rule in config.keys:
        if rule.target_unit in related_units:
            related_rule_ids.add(rule.id)
    related_rule_ids = {rule_id for rule_id in related_rule_ids if rule_id in options}

    baseline_by_ref = {
        (result.rule_id, result.record_ref): result for result in key_results
    }

    def variant_for(ref: RecordRef, choice: _Choice) -> _Variant | None:
        rule = config.key_map[ref.rule_id]
        if not rule.selectable:
            option_index = 0
        else:
            option_index = choice.by_rule[rule.id]
        position = rule_ref_index.get((ref.rule_id, ref.record_ref))
        if position is None:
            return None
        return variants[ref.rule_id][option_index][position]

    def evaluate(choice: _Choice) -> _Eval:
        violations: list[dict[str, Any]] = []
        checks: dict[str, Any] = {
            "records_checked": 0,
            "rules_checked": 0,
            "unique_rules_checked": 0,
            "authorized_links_checked": 0,
            "forbidden_pairs_checked": 0,
            "cross_table_pairs_checked": 0,
            "target_tables_checked": 0,
            "hard_constraint_codes": [],
            "verified": True,
        }
        codes: set[str] = set()

        def add_violation(code: str, message: str, **details: Any) -> None:
            codes.add(code)
            if len(violations) < _MAX_DIAGNOSTICS:
                violations.append({"code": code, "message": message, **details})

        # Hard per-record constraints for every rule, using the selected spec.
        per_rule: dict[str, list[tuple[SourceRecord, _Variant]]] = {}
        for rule in config.keys:
            option_index = choice.by_rule.get(rule.id, 0) if rule.selectable else 0
            selected = options[rule.id][option_index]
            rows: list[tuple[SourceRecord, _Variant]] = []
            for record, variant in zip(
                rule_records[rule.id], variants[rule.id][option_index]
            ):
                rows.append((record, variant))
                checks["records_checked"] += 1
                if variant.missing_required:
                    add_violation(
                        "REQUIRED_VALUE_MISSING",
                        f"规则 {rule.id} 的必需分量缺失",
                        rule_id=rule.id,
                        record_ref=record.record_ref,
                        record_id=record.record_id,
                        transform=selected.as_dict(),
                    )
                if variant.separator:
                    add_violation(
                        "COMPOSITE_SEPARATOR",
                        f"规则 {rule.id} 的变换结果含保留分隔符 U+001F",
                        rule_id=rule.id,
                        record_ref=record.record_ref,
                        record_id=record.record_id,
                        transform=selected.as_dict(),
                    )
                if variant.too_long_bytes:
                    add_violation(
                        "KEY_TOO_LONG_BYTES",
                        f"规则 {rule.id} 的目标键超过 max_bytes={rule.max_bytes}",
                        rule_id=rule.id,
                        record_ref=record.record_ref,
                        record_id=record.record_id,
                        key_bytes=variant.key_bytes,
                        limit_bytes=rule.max_bytes,
                        transform=selected.as_dict(),
                    )
                if variant.too_long_chars:
                    add_violation(
                        "KEY_TOO_LONG_CHARS",
                        f"规则 {rule.id} 的目标键超过 max_chars={rule.max_chars}",
                        rule_id=rule.id,
                        record_ref=record.record_ref,
                        record_id=record.record_id,
                        key_chars=variant.key_chars,
                        limit_chars=rule.max_chars,
                        transform=selected.as_dict(),
                    )
            per_rule[rule.id] = rows
            checks["rules_checked"] += 1

        # Per-rule uniqueness (whole rule recomputation, not only link ends).
        for rule in config.keys:
            if not rule.unique:
                continue
            checks["unique_rules_checked"] += 1
            groups: dict[str, list[tuple[SourceRecord, _Variant]]] = {}
            for record, variant in per_rule[rule.id]:
                if variant.key is not None:
                    groups.setdefault(variant.key, []).append((record, variant))
            for key, members in sorted(groups.items()):
                if len(members) > 1:
                    add_violation(
                        "UNIQUE_COLLISION",
                        f"规则 {rule.id} 在整表重算后出现 {len(members)} 条同键记录",
                        rule_id=rule.id,
                        key_escaped=escaped_text(key),
                        records=[
                            {
                                "record_ref": record.record_ref,
                                "record_id": record.record_id,
                            }
                            for record, _ in members[:20]
                        ],
                    )

        # Different entities in the same target table must not share a key.
        unit_rules: dict[str, list[KeyRule]] = {}
        for rule in config.keys:
            unit_rules.setdefault(rule.target_unit, []).append(rule)
        for unit, rules in sorted(unit_rules.items()):
            if len(rules) < 2:
                continue
            checks["target_tables_checked"] += 1
            groups = {}
            for rule in rules:
                for record, variant in per_rule[rule.id]:
                    if variant.key is not None:
                        groups.setdefault(variant.key, []).append(
                            (rule, record)
                        )
            for key, members in sorted(groups.items()):
                if len(members) < 2:
                    continue
                distinct = {(rule.id, record.record_ref) for rule, record in members}
                if len(distinct) > 1:
                    add_violation(
                        "TARGET_TABLE_COLLISION",
                        f"目标表 {unit} 中出现不同实体的同键记录",
                        target_table=unit,
                        key_escaped=escaped_text(key),
                        records=[
                            {
                                "rule_id": rule.id,
                                "record_ref": record.record_ref,
                                "record_id": record.record_id,
                            }
                            for rule, record in members[:20]
                        ],
                    )

        # Authorized links: both sides must be byte-identical.
        for link in spec.authorized_links:
            checks["authorized_links_checked"] += 1
            left_variant = variant_for(link.left, choice)
            right_variant = variant_for(link.right, choice)
            left_key = None if left_variant is None else left_variant.key
            right_key = None if right_variant is None else right_variant.key
            if left_key is None or right_key is None or left_key != right_key:
                add_violation(
                    "AUTHORIZED_LINK_MISMATCH",
                    f"已授权关联 {link.link_id} 两端目标键不相等",
                    link_id=link.link_id,
                    left={**link.left.as_dict(), "key_escaped": _esc(left_key)},
                    right={**link.right.as_dict(), "key_escaped": _esc(right_key)},
                )
            elif spec.forbid_unauthorized_cross_table:
                # The byte-level equality is a necessary condition, but only
                # the authorized pair, not every record with the same key,
                # may share it. A third record in either table also matching
                # is caught by the cross-table / uniqueness checks below.
                checks.setdefault("authorized_link_keys", {})[
                    link.link_id
                ] = sha256_text(left_key)

        # Forbidden pairs must never share a key.
        for pair in spec.forbidden_pairs:
            checks["forbidden_pairs_checked"] += 1
            left_variant = variant_for(pair.left, choice)
            right_variant = variant_for(pair.right, choice)
            left_key = None if left_variant is None else left_variant.key
            right_key = None if right_variant is None else right_variant.key
            if left_key is not None and left_key == right_key:
                add_violation(
                    "FORBIDDEN_PAIR_COLLISION",
                    f"禁止同键的记录对 {pair.pair_id} 生成了相同目标键",
                    pair_id=pair.pair_id,
                    key_escaped=escaped_text(left_key),
                    left=link_ref_detail(pair.left, left_key),
                    right=link_ref_detail(pair.right, right_key),
                )

        # Unauthorized cross-table matches: every rule in the run is
        # recomputed, so an adjustable rule can accidentally meet a static
        # rule's key in another target table.
        if spec.forbid_unauthorized_cross_table:
            by_key: dict[str, list[tuple[str, str, str | None, str]]] = {}
            for rule in config.keys:
                option_index = (
                    choice.by_rule[rule.id] if rule.selectable else 0
                )
                for record, variant in zip(
                    rule_records[rule.id], variants[rule.id][option_index]
                ):
                    if variant.key is not None:
                        by_key.setdefault(variant.key, []).append(
                            (
                                rule.target_unit,
                                rule.id,
                                record.record_ref,
                                rule.source_id,
                            )
                        )
            for key, members in sorted(by_key.items()):
                if len(members) < 2:
                    continue
                for left, right in itertools.combinations(members, 2):
                    if left[0] == right[0]:
                        continue
                    checks["cross_table_pairs_checked"] += 1
                    left_ref = RecordRef(
                        source_id=left[3], rule_id=left[1], record_ref=left[2] or ""
                    )
                    right_ref = RecordRef(
                        source_id=right[3], rule_id=right[1], record_ref=right[2] or ""
                    )
                    if _pair_key(left_ref, right_ref) in authorized_pairs:
                        continue
                    add_violation(
                        "UNAUTHORIZED_CROSS_TABLE_MATCH",
                        "未授权的跨表记录在新变换下意外同键",
                        key_escaped=escaped_text(key),
                        left=left_ref.as_dict(),
                        right=right_ref.as_dict(),
                    )

        changed_records = 0
        total_bytes = 0
        for rule_id in sorted(related_rule_ids):
            rule = config.key_map[rule_id]
            option_index = choice.by_rule[rule_id] if rule.selectable else 0
            for position, variant in enumerate(variants[rule_id][option_index]):
                old = old_keys[rule_id][position]
                if variant.key is not None:
                    total_bytes += variant.key_bytes
                if old.key != variant.key:
                    changed_records += 1
            checks.setdefault("objective_rules", []).append(rule_id)

        checks["hard_constraint_codes"] = sorted(codes)
        checks["verified"] = not violations
        return _Eval(
            feasible=not violations,
            changed_records=changed_records,
            total_bytes=total_bytes,
            violations=violations,
            checks=checks,
        )

    # ---- exhaustive / budgeted enumeration --------------------------------
    budget = spec.max_combinations
    examined = 0
    best: dict[str, dict[str, Any]] = {
        objective: {"metric": None, "rank": None} for objective in _OBJECTIVES
    }
    feasible_count = 0
    best_choices: dict[str, _Choice] = {}
    witness_categories: dict[str, dict[str, Any]] = {}
    witness_counts: dict[str, int] = {}
    budget_exhausted = False
    examined_rank_last = -1

    ranges = [range(len(rule.candidates)) for rule in candidate_rules]
    for rank, combo in enumerate(itertools.product(*ranges)):
        if examined >= budget:
            budget_exhausted = True
            break
        examined += 1
        examined_rank_last = rank
        by_rule = {
            rule.id: combo[index] for index, rule in enumerate(candidate_rules)
        }
        choice = _Choice(rank=rank, combo=combo, by_rule=by_rule)
        evaluation = evaluate(choice)
        if not evaluation.feasible:
            for violation in evaluation.violations:
                code = violation["code"]
                witness_counts[code] = witness_counts.get(code, 0) + 1
                if code not in witness_categories and len(
                    witness_categories
                ) < _MAX_WITNESS_CATEGORIES:
                    witness_categories[code] = {
                        "code": code,
                        "message": violation.get("message", code),
                        "combination_rank": rank,
                        "selected_transforms": {
                            rule.id: options[rule.id][by_rule[rule.id]].as_dict()
                            for rule in candidate_rules
                        },
                        "details": {
                            key: value
                            for key, value in violation.items()
                            if key not in {"code", "message"}
                        },
                    }
            continue

        feasible_count += 1
        for objective in _OBJECTIVES:
            metric = (
                evaluation.changed_records
                if objective == "min_changed_records"
                else evaluation.total_bytes
            )
            current = best[objective]
            if (
                current["metric"] is None
                or metric < current["metric"]
                or (
                    metric == current["metric"]
                    and (current["rank"] is None or rank < current["rank"])
                )
            ):
                best[objective] = {"metric": metric, "rank": rank}
                best_choices[objective] = choice
    if examined < total_combinations and examined >= budget:
        budget_exhausted = True

    examined_rank_last = examined - 1 if examined else -1
    base.examined_combinations = examined
    base.budget_exhausted = budget_exhausted
    base.total_combinations = total_combinations

    # ---- build objective results -----------------------------------------
    objective_results: dict[str, PreflightEvaluation | None] = {}
    for objective in _OBJECTIVES:
        choice = best_choices.get(objective)
        if choice is None:
            objective_results[objective] = None
            continue
        evaluation = evaluate(choice)
        assert evaluation.feasible, "selected combination must be re-verifiable"
        evidence, evidence_ok = _build_evidence(
            config,
            rule_records,
            old_keys,
            variants,
            options,
            choice,
            related_rule_ids,
            baseline_by_ref,
            rule_ref_index,
        )
        metric_value = (
            evaluation.changed_records
            if objective == "min_changed_records"
            else evaluation.total_bytes
        )
        proof = {
            "optimality": "unknown" if budget_exhausted else "proven_exhaustive",
            "search_budget": budget,
            "examined_combinations": examined,
            "total_combinations": total_combinations,
            "examined_rank_range": [0, examined_rank_last] if examined else [],
            "feasible_combinations_examined": feasible_count,
            "objective_metric": objective,
            "best_metric": metric_value,
            "tie_break": "candidate_order",
            "selected_rank": choice.rank,
            "selected_combo": list(choice.combo),
            "unexamined_combinations": max(0, total_combinations - examined),
        }
        checks = dict(evaluation.checks)
        checks["relations"] = {
            "authorized_links_satisfied": all(
                _link_satisfied(link, variant_for(link.left, choice), variant_for(link.right, choice))
                for link in spec.authorized_links
            ),
            "forbidden_pairs_clear": all(
                not _same_non_null_key(variant_for(pair.left, choice), variant_for(pair.right, choice))
                for pair in spec.forbidden_pairs
            ),
            "authorized_links": len(spec.authorized_links),
            "forbidden_pairs": len(spec.forbidden_pairs),
            "forbid_unauthorized_cross_table": spec.forbid_unauthorized_cross_table,
        }
        checks["evidence_verified"] = evidence_ok
        if not evidence_ok:
            # A recomputation mismatch means the candidate cannot be certified;
            # never present it as optimal or cleared.
            objective_results[objective] = PreflightEvaluation(
                objective=objective,
                status="evidence_failed",
                selected_transforms={
                    rule.id: options[rule.id][
                        choice.by_rule[rule.id] if rule.selectable else 0
                    ]
                    for rule in config.keys
                },
                exit_code=_BLOCKED_EXIT,
                changed_records=evaluation.changed_records,
                total_bytes=evaluation.total_bytes,
                key_evidence=evidence,
                checks=checks,
                diagnostics=evaluation.violations[:20],
                combination_rank=choice.rank,
                exhaustive=not budget_exhausted,
                proof=proof,
                provisional=budget_exhausted,
                examined_combinations=examined,
            )
            continue
        status = (
            "provisional"
            if budget_exhausted
            else "optimal"
        )
        objective_results[objective] = PreflightEvaluation(
            objective=objective,
            status=status,
            selected_transforms={
                rule.id: options[rule.id][
                    choice.by_rule[rule.id] if rule.selectable else 0
                ]
                for rule in config.keys
            },
            exit_code=_PROVISIONAL_EXIT if budget_exhausted else _OPTIMAL_EXIT,
            changed_records=evaluation.changed_records,
            total_bytes=evaluation.total_bytes,
            key_evidence=evidence,
            checks=checks,
            diagnostics=evaluation.violations[:20],
            combination_rank=choice.rank,
            exhaustive=not budget_exhausted,
            proof=proof,
            provisional=budget_exhausted,
            examined_combinations=examined,
        )
    base.objective_results = objective_results
    base.relation_summary = {
        "authorized_links": len(spec.authorized_links),
        "forbidden_pairs": len(spec.forbidden_pairs),
        "forbid_unauthorized_cross_table": spec.forbid_unauthorized_cross_table,
        "related_records": sum(
            len(rule_records[rule_id]) for rule_id in sorted(related_rule_ids)
        ),
        "rules": sorted(related_rule_ids),
        "authorized_link_ids": [
            link.link_id for link in spec.authorized_links
        ],
        "forbidden_pair_ids": [pair.pair_id for pair in spec.forbidden_pairs],
    }
    base.evidence_verified = (
        feasible_count > 0
        and all(
            item is not None and item.checks.get("evidence_verified", False)
            for item in objective_results.values()
        )
    )

    if budget_exhausted:
        if feasible_count:
            base.state = "provisional"
            base.notes = [
                "搜索预算耗尽：仅报告已验证可行的暂定组合。",
                "最优性 unknown；不得据此宣称最优、无解或放行。",
            ]
        else:
            base.state = "unknown"
            base.notes = [
                "搜索预算耗尽且已检查范围内没有可行组合。",
                "最优性与可行性均 unknown；不得宣称无解或放行。",
            ]
        base.witness = (
            {
                "categories": witness_categories,
                "counts": witness_counts,
                "note": "仅覆盖已检查组合，不构成无解证明。",
            }
            if witness_categories
            else None
        )
    elif feasible_count == 0:
        base.state = "no_feasible"
        base.notes = [
            "已穷尽全部候选组合，没有任何组合满足硬约束。",
            "工具不自动合并、删除或为某行指定替代键；需回到源数据或业务授权处理。",
        ]
        base.witness = {
            "categories": witness_categories,
            "counts": witness_counts,
            "note": "已穷尽全部组合；每类冲突给出可复核见证。",
            "exhaustive": True,
            "examined_combinations": examined,
        }
        for objective in _OBJECTIVES:
            base.objective_results[objective] = None
        base.evidence_verified = False
    else:
        base.state = "optimal"
        base.notes = [
            "已穷尽全部候选组合，两个业务目标均得到可证最优解。",
            "两个目标独立求解，可能选择不同规则配置。",
        ]
    return base


# ---------------------------------------------------------------------------
# helpers


def _source_digest(loads: Sequence[SourceLoad]) -> str:
    payload = [
        {
            "source_id": load.spec.id,
            "sha256": load.sha256,
            "size_bytes": load.size_bytes,
            "records": len(load.records),
        }
        for load in sorted(loads, key=lambda item: item.spec.id)
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def compute_source_digest(loads: Sequence[SourceLoad]) -> str:
    """Public, deterministic digest of the input snapshot used for binding."""

    return _source_digest(loads)


def _candidate_order(rules: Sequence[KeyRule]) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": rule.id,
            "source_id": rule.source_id,
            "target_table": rule.target_unit,
            "transform": rule.transform.as_dict(),
            "candidates": [
                {"index": index, "transform": candidate.as_dict()}
                for index, candidate in enumerate(rule.candidates)
            ],
        }
        for rule in rules
    ]


def _config_summary(
    config: AppConfig,
    source_digest: str,
    spec: PreflightSpec,
) -> dict[str, Any]:
    return {
        "project": config.project.name,
        "target": config.project.target,
        "config_sha256": config.config_sha256,
        "source_digest": source_digest,
        "rules_sha256": rule_summary_digest(config.keys),
        "constraint_digest": spec.constraint_sha256,
        "rules": [rule_summary(rule) for rule in config.keys],
        "constraints": spec.as_dict(),
    }


def _make_variant(
    rule: KeyRule, record: SourceRecord, spec: TransformSpec
) -> _Variant:
    raw_components = tuple(record.values.get(column) for column in rule.columns)
    computation = compute_target_key(rule.columns, raw_components, spec)
    if computation.target_key is None:
        return _Variant(
            key=None,
            key_bytes=0,
            key_chars=0,
            changed=False,
            missing_required=rule.required,
            separator=False,
            too_long_bytes=False,
            too_long_chars=False,
            empty=False,
        )
    key = computation.target_key
    return _Variant(
        key=key,
        key_bytes=computation.key_bytes,
        key_chars=computation.key_chars,
        changed=computation.changed,
        missing_required=False,
        separator=bool(computation.separator_columns),
        too_long_bytes=rule.max_bytes is not None
        and computation.key_bytes > rule.max_bytes,
        too_long_chars=rule.max_chars is not None
        and computation.key_chars > rule.max_chars,
        empty=computation.empty,
    )


def _build_evidence(
    config: AppConfig,
    rule_records: dict[str, list[SourceRecord]],
    old_keys: dict[str, list[_Variant]],
    variants: dict[str, list[list[_Variant]]],
    options: dict[str, tuple[TransformSpec, ...]],
    choice: _Choice,
    related_rule_ids: set[str],
    baseline_by_ref: dict[tuple[str, str], KeyResult],
    rule_ref_index: dict[tuple[str, str], int],
) -> tuple[list[PreflightKeyEvidence], bool]:
    evidence: list[PreflightKeyEvidence] = []
    verified = True
    for rule in config.keys:
        if rule.id not in related_rule_ids:
            continue
        option_index = choice.by_rule[rule.id] if rule.selectable else 0
        selected = options[rule.id][option_index]
        rows = rule_records[rule.id]
        for position, record in enumerate(rows):
            old = old_keys[rule.id][position]
            new = variants[rule.id][option_index][position]
            # Independent re-derivation directly from the selected TransformSpec.
            direct = _make_variant(rule, record, selected)
            if (
                direct.key != new.key
                or direct.key_bytes != new.key_bytes
                or direct.key_chars != new.key_chars
                or direct.changed != new.changed
            ):
                verified = False
            baseline = baseline_by_ref.get((rule.id, record.record_ref))
            old_key = old.key
            old_bytes = old.key_bytes
            if baseline is not None:
                # The baseline scan must agree with the preflight's old-key view
                # (both use the original transform on the same loads).
                if (
                    baseline.target_key != old_key
                    or baseline.key_bytes != old_bytes
                    or baseline.changed != old.changed
                ):
                    verified = False
            defects: list[str] = []
            if new.missing_required:
                defects.append("REQUIRED_VALUE_MISSING")
            if new.separator:
                defects.append("COMPOSITE_SEPARATOR")
            if new.too_long_bytes:
                defects.append("KEY_TOO_LONG_BYTES")
            if new.too_long_chars:
                defects.append("KEY_TOO_LONG_CHARS")
            if new.empty:
                defects.append("EMPTY_KEY")
            evidence.append(
                PreflightKeyEvidence(
                    rule_id=rule.id,
                    source_id=rule.source_id,
                    record_ref=record.record_ref,
                    record_id=record.record_id,
                    old_key=old_key,
                    old_bytes=old_bytes,
                    new_key=new.key,
                    new_bytes=new.key_bytes,
                    changed=old_key != new.key,
                    transform=selected,
                    defects=defects,
                )
            )
    return evidence, verified


def _validate_ref(
    ref: RecordRef,
    records_by_source: dict[str, dict[str, SourceRecord]],
    config: AppConfig,
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    rule = config.key_map.get(ref.rule_id)
    if rule is None:
        errors.append(
            {
                "reason": "unknown_rule",
                **ref.as_dict(),
            }
        )
        return errors
    if rule.source_id != ref.source_id:
        errors.append(
            {
                "reason": "source_rule_mismatch",
                "expected_source_id": rule.source_id,
                **ref.as_dict(),
            }
        )
    if ref.record_ref not in records_by_source.get(ref.source_id, {}):
        errors.append(
            {
                "reason": "record_ref_not_found",
                **ref.as_dict(),
                "source": ref.source_id,
            }
        )
    return errors


def _all_refs(spec: PreflightSpec) -> Iterable[RecordRef]:
    for link in spec.authorized_links:
        yield link.left
        yield link.right
    for pair in spec.forbidden_pairs:
        yield pair.left
        yield pair.right


def _pair_key(left: RecordRef, right: RecordRef) -> tuple[tuple[str, str, str], tuple[str, str, str]]:
    a = left.key()
    b = right.key()
    return (a, b) if a <= b else (b, a)


def _link_satisfied(
    link: AuthorizedLink, left: _Variant | None, right: _Variant | None
) -> bool:
    return (
        left is not None
        and right is not None
        and left.key is not None
        and left.key == right.key
    )


def _same_non_null_key(left: _Variant | None, right: _Variant | None) -> bool:
    return (
        left is not None
        and right is not None
        and left.key is not None
        and left.key == right.key
    )


def _esc(value: str | None) -> str | None:
    return None if value is None else escaped_text(value)


def link_ref_detail(ref: RecordRef, key: str | None) -> dict[str, Any]:
    return {**ref.as_dict(), "key_escaped": _esc(key)}


def ref_digest(ref: RecordRef) -> str:
    return sha256_text(
        f"{ref.source_id}\x1f{ref.rule_id}\x1f{ref.record_ref}"
    )


__all__ = ["optimize", "compute_source_digest"]
