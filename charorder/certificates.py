"""Rule-level future-key ordering compatibility certificates.

A certificate answers a question the snapshot scan cannot: over a *declared
domain of future raw keys*, does mapping each raw key through the existing
:func:`charorder.transforms.apply_transform` pipeline preserve the declared
legacy ordering and the distinct identity of every key under the target
binary UTF-8 ordering?

The module never opens a target database. Target keys are replayed through the
same transform pipeline used for loaded records, and every ordering decision
is made on whole strings (or whole composite keys built with U+001F), never on
individual code points in isolation.

Three outcomes are possible:

* ``proven`` — the full finite domain was enumerated and every distinct raw
  key pair was checked; strict order and unique identity hold for all of them.
* ``counterexample`` — a real, replayable inversion or confluence pair exists
  in the domain; the pair itself is attached so callers can replay it.
* ``unknown`` — only a bounded search ran (the domain exceeded the configured
  limits) and no counterexample was found. Absence of evidence is not a proof.
"""

from __future__ import annotations

import hashlib
import json
import itertools
from typing import Any, Iterable

from . import UNICODE_VERSION
from .models import (
    DomainComponent,
    FutureDomainSpec,
    KeyRule,
    OrderingCertificate,
    SnapshotOrderObservation,
    TransformSpec,
)
from .transforms import UNIT_SEPARATOR, apply_transform, escaped_text

TARGET_ORDER = "binary_utf8"
CERTIFICATE_SCHEMA = "charorder/ordering_certificate/v1"


def legacy_compare(raw_a: str, raw_b: str, legacy_order: str) -> int:
    """Compare two full raw composite keys under the declared legacy semantics."""

    if legacy_order == "binary_utf8":
        left = raw_a.encode("utf-8")
        right = raw_b.encode("utf-8")
    elif legacy_order == "codepoint":
        if raw_a == raw_b:
            return 0
        return -1 if raw_a < raw_b else 1
    else:  # guarded by config validation
        raise ValueError(f"未知旧比较语义：{legacy_order}")
    if left == right:
        return 0
    return -1 if left < right else 1


def target_compare(target_a: str, target_b: str) -> int:
    """Compare two target keys by their binary UTF-8 byte order."""

    left = target_a.encode("utf-8")
    right = target_b.encode("utf-8")
    if left == right:
        return 0
    return -1 if left < right else 1


def domain_member_count(domain: FutureDomainSpec) -> int:
    """Number of raw composite keys the Cartesian product would generate."""

    total = 1
    for component in domain.components:
        upper = component.max_length if component.max_length is not None else 0
        alphabet = len(component.charset)
        count = 0
        for length in range(component.min_length, upper + 1):
            count += alphabet ** length
        total *= count
    return total


def domain_digest(domain: FutureDomainSpec) -> str:
    payload = {
        "schema": "charorder/future_domain/v1",
        "legacy_order": domain.legacy_order,
        "components": [
            {
                "column": component.column,
                "charset": [
                    "".join(f"U+{ord(ch):04X}" for ch in token)
                    for token in component.charset
                ],
                "min_length": component.min_length,
                "max_length": component.max_length,
            }
            for component in domain.components
        ],
    }
    rendered = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def transform_digest(spec: TransformSpec) -> str:
    rendered = json.dumps(
        {"schema": "charorder/transform/v1", **spec.as_dict()},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _component_strings(
    component: DomainComponent, limit: int
) -> Iterable[str]:
    """Yield alphabet strings in lexicographic order, capped at ``limit``.

    The cap is applied while generating so that declaring a large domain never
    materializes the full Cartesian product in memory.
    """

    upper = component.max_length if component.max_length is not None else 0
    yielded = 0
    for length in range(component.min_length, upper + 1):
        if yielded >= limit:
            return
        for product in itertools.product(component.charset, repeat=length):
            if yielded >= limit:
                return
            yielded += 1
            yield "".join(product)


def _streaming_product(
    iterables: list[Iterable[str]],
) -> Iterable[tuple[str, ...]]:
    """Lazy cartesian product: never materializes the iterables up front."""

    if not iterables:
        yield ()
        return
    first, rest = iterables[0], iterables[1:]
    for head in first:
        for tail in _streaming_product(rest):
            yield (head, *tail)


def _iter_domain_members(
    domain: FutureDomainSpec, member_budget: int
) -> Iterable[tuple[str, ...]]:
    """Yield raw component tuples in deterministic product order, up to budget.

    Uses nested streaming generators (not a materialized Cartesian product) so
    the configured member budget bounds both work and memory on large domains.
    """

    per_component = [
        _component_strings(component, member_budget)
        for component in domain.components
    ]
    yielded = 0
    for combo in _streaming_product(per_component):
        if yielded >= member_budget:
            return
        yielded += 1
        yield combo


def _build_raw_key(components: tuple[str, ...]) -> str:
    return UNIT_SEPARATOR.join(components)


def _build_target_key(components: tuple[str, ...], spec: TransformSpec) -> str:
    transformed = [apply_transform(component, spec) for component in components]
    return UNIT_SEPARATOR.join(transformed)


def evaluate_rule(rule: KeyRule) -> OrderingCertificate | None:
    """Evaluate the declared future domain for one rule, or skip if undeclared."""

    if rule.future_domain is None:
        return None
    return build_certificate(rule, rule.future_domain)


def build_certificate(
    rule: KeyRule, domain: FutureDomainSpec
) -> OrderingCertificate:
    spec = rule.transform
    digest = domain_digest(domain)
    t_digest = transform_digest(spec)
    certificate_id = _certificate_id(rule, digest, t_digest)
    base: dict[str, Any] = dict(
        certificate_id=certificate_id,
        rule_id=rule.id,
        source_id=rule.source_id,
        domain=domain,
        domain_digest=digest,
        transform_digest=t_digest,
        transform=spec,
        unicode_version=UNICODE_VERSION,
        target_order=TARGET_ORDER,
        pair_budget=domain.pair_budget,
        member_budget=domain.exhaustive_member_limit,
    )

    invalid_reason = _validate_domain(rule, domain)
    if invalid_reason is not None:
        try:
            declared_count = domain_member_count(domain)
        except (OverflowError, ValueError):
            declared_count = 0
        return OrderingCertificate(
            status="invalid_domain",
            license="blocked",
            exhaustive=False,
            domain_member_count=declared_count,
            eligible_member_count=0,
            excluded_count=0,
            excluded_reasons={},
            excluded_examples=(),
            pairs_checked=0,
            budget_exhausted=False,
            counterexample=None,
            invalid_reason=invalid_reason,
            notes=("无效域不产生任何保序结论，旧范围边界/游标不得直译。",),
            **base,
        )

    total_members = domain_member_count(domain)
    exhaustive = total_members <= domain.exhaustive_member_limit

    excluded_reasons: dict[str, int] = {}
    excluded_examples: list[dict[str, Any]] = []
    eligible: list[tuple[tuple[str, ...], str, str]] = []
    seen_raw_keys: set[str] = set()
    enumerated = 0
    member_budget_hit = False

    for components in _iter_domain_members(domain, domain.exhaustive_member_limit):
        enumerated += 1
        raw_key = _build_raw_key(components)
        if raw_key in seen_raw_keys:
            _record_exclusion(
                excluded_reasons, excluded_examples, components,
                "raw_domain_collision", components,
            )
            continue
        seen_raw_keys.add(raw_key)

        reason = _exclusion_reason(rule, components)
        if reason is not None:
            _record_exclusion(
                excluded_reasons, excluded_examples, components, reason, components
            )
            continue

        target_key = _build_target_key(components, spec)
        eligible.append((components, raw_key, target_key))

    if enumerated >= domain.exhaustive_member_limit and total_members > enumerated:
        member_budget_hit = True

    non_empty = [entry for entry in eligible if entry[1] != ""]
    if not non_empty:
        return OrderingCertificate(
            status="invalid_domain",
            license="blocked",
            exhaustive=False,
            domain_member_count=total_members,
            eligible_member_count=len(eligible),
            excluded_count=sum(excluded_reasons.values()),
            excluded_reasons=excluded_reasons,
            excluded_examples=tuple(excluded_examples[:20]),
            pairs_checked=0,
            budget_exhausted=member_budget_hit,
            counterexample=None,
            invalid_reason=(
                "域内成员在长度/编码/分隔符门禁后全部被排除（或仅剩空串键），"
                "无可证明的非空键域。超限键、无法编码键必须明确排除，不能参与保序证明。"
            ),
            notes=("空可证域不能授权直译。",),
            **base,
        )
    eligible = non_empty

    # Canonical deterministic order: target binary UTF-8 bytes, then raw key.
    eligible.sort(key=lambda item: (item[2].encode("utf-8"), item[1]))

    pairs_checked = 0
    counterexample: dict[str, Any] | None = None
    pair_budget_hit = False
    break_out = False
    for i in range(len(eligible)):
        if break_out:
            break
        components_a, raw_a, target_a = eligible[i]
        for j in range(i + 1, len(eligible)):
            if pairs_checked >= domain.pair_budget:
                pair_budget_hit = True
                break_out = True
                break
            components_b, raw_b, target_b = eligible[j]
            pairs_checked += 1
            counterexample = _classify_pair(
                domain, spec,
                components_a, raw_a, target_a,
                components_b, raw_b, target_b,
            )
            if counterexample is not None:
                break_out = True
                break

    budget_exhausted = member_budget_hit or pair_budget_hit
    excluded_count = sum(excluded_reasons.values())

    if counterexample is not None:
        status = "counterexample"
        license_ = "blocked"
        notes = (
            "反例中的两个原键均在声明域内，目标键由 apply_transform 重放生成；"
            "旧范围边界/seek 游标不得直译。",
        )
    elif exhaustive and not budget_exhausted:
        status = "proven"
        license_ = "direct_translation"
        notes = (
            "已对声明有限域的全部成员逐对证明：严格顺序保持且目标键唯一，"
            f"共检查 {pairs_checked} 个不同原键对；直译许可仍受碰撞与长度门禁约束。",
        )
    else:
        status = "unknown"
        license_ = "not_established"
        notes = (
            "域规模超出穷尽限制或配对预算耗尽，仅完成有界反例搜索；"
            "未找到反例不等于已证保序，直译不予授权，应维持旧排序或做目标侧全域过滤。",
        )

    return OrderingCertificate(
        status=status,
        license=license_,
        exhaustive=exhaustive and not budget_exhausted,
        domain_member_count=total_members,
        eligible_member_count=len(eligible),
        excluded_count=excluded_count,
        excluded_reasons=excluded_reasons,
        excluded_examples=tuple(excluded_examples[:20]),
        pairs_checked=pairs_checked,
        budget_exhausted=budget_exhausted,
        counterexample=counterexample,
        invalid_reason=None,
        notes=notes,
        **base,
    )


def _validate_domain(rule: KeyRule, domain: FutureDomainSpec) -> str | None:
    if [component.column for component in domain.components] != list(rule.columns):
        return (
            "future_domain 分量列与规则 columns 不一致；"
            "复合键必须按完整字符串与逐分量 U+001F 拼接规则求值。"
        )
    for component in domain.components:
        if not component.charset:
            return f"分量 {component.column} 的 charset 为空，域不可核验。"
        if component.max_length is not None and component.max_length < component.min_length:
            return f"分量 {component.column} 的 min_length 大于 max_length。"
        for token in component.charset:
            for ch in token:
                if 0xD800 <= ord(ch) < 0xE000:
                    return (
                        f"分量 {component.column} 的 charset 含孤立代理码位 "
                        f"U+{ord(ch):04X}，目标 binary UTF-8 键无法编码，必须显式排除。"
                    )
    # Unbounded component => the domain is not a finite, exhaustible set.
    for component in domain.components:
        if component.max_length is None:
            return (
                f"分量 {component.column} 未声明 max_length，域不是有限集；"
                "规则级证书只接受可核验的有限原键域。"
            )
    return None


def _exclusion_reason(
    rule: KeyRule, components: tuple[str, ...]
) -> str | None:
    for component in components:
        if UNIT_SEPARATOR in component:
            return "unit_separator_in_raw_domain"
        try:
            component.encode("utf-8")
        except UnicodeEncodeError:
            return "unencodable_key"

    target_components = [
        apply_transform(component, rule.transform) for component in components
    ]
    for value in target_components:
        if UNIT_SEPARATOR in value:
            return "composite_separator_after_transform"
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return "unencodable_target_key"

    target_key = UNIT_SEPARATOR.join(target_components)
    target_bytes = target_key.encode("utf-8")
    if rule.max_bytes is not None and len(target_bytes) > rule.max_bytes:
        return "over_max_bytes"
    if rule.max_chars is not None and len(target_key) > rule.max_chars:
        return "over_max_chars"
    return None


def _classify_pair(
    domain: FutureDomainSpec,
    spec: TransformSpec,
    components_a: tuple[str, ...],
    raw_a: str,
    target_a: str,
    components_b: tuple[str, ...],
    raw_b: str,
    target_b: str,
) -> dict[str, Any] | None:
    # Normalize the evidence ordering to the legacy order so the reported
    # comparison labels read "raw A < raw B" regardless of the scan order.
    if legacy_compare(raw_a, raw_b, domain.legacy_order) > 0:
        return _classify_pair(
            domain,
            spec,
            components_b,
            raw_b,
            target_b,
            components_a,
            raw_a,
            target_a,
        )

    legacy = legacy_compare(raw_a, raw_b, domain.legacy_order)
    target = target_compare(target_a, target_b)

    if raw_a == raw_b:
        return None

    if target == 0:
        return _counterexample_payload(
            kind="confluence",
            domain=domain,
            spec=spec,
            components_a=components_a,
            raw_a=raw_a,
            target_a=target_a,
            components_b=components_b,
            raw_b=raw_b,
            target_b=target_b,
            detail="不同原键经变换后合流为同一目标 binary UTF-8 键，唯一身份不再保持。",
        )
    if legacy != 0 and legacy != target:
        return _counterexample_payload(
            kind="order_inversion",
            domain=domain,
            spec=spec,
            components_a=components_a,
            raw_a=raw_a,
            target_a=target_a,
            components_b=components_b,
            raw_b=raw_b,
            target_b=target_b,
            detail="旧顺序与目标 binary UTF-8 顺序方向相反，旧范围边界/游标无法直译。",
        )
    return None


def _counterexample_payload(
    *,
    kind: str,
    domain: FutureDomainSpec,
    spec: TransformSpec,
    components_a: tuple[str, ...],
    raw_a: str,
    target_a: str,
    components_b: tuple[str, ...],
    raw_b: str,
    target_b: str,
    detail: str,
) -> dict[str, Any]:
    replayed_a = _build_target_key(components_a, spec)
    replayed_b = _build_target_key(components_b, spec)
    return {
        "kind": kind,
        "detail": detail,
        "legacy_order": domain.legacy_order,
        "target_order": TARGET_ORDER,
        "legacy_comparison": _cmp_label(
            legacy_compare(raw_a, raw_b, domain.legacy_order)
        ),
        "target_comparison": _cmp_label(target_compare(target_a, target_b)),
        "raw_a": _key_evidence(components_a, raw_a),
        "raw_b": _key_evidence(components_b, raw_b),
        "target_a_escaped": escaped_text(target_a),
        "target_b_escaped": escaped_text(target_b),
        "target_a_utf8_hex": target_a.encode("utf-8").hex(),
        "target_b_utf8_hex": target_b.encode("utf-8").hex(),
        "replay_matches_pipeline": replayed_a == target_a and replayed_b == target_b,
    }


def _key_evidence(components: tuple[str, ...], raw_key: str) -> dict[str, Any]:
    return {
        "components": [escaped_text(value) for value in components],
        "raw_key_escaped": escaped_text(raw_key),
        "raw_utf8_hex": raw_key.encode("utf-8").hex(),
    }


def _cmp_label(value: int) -> str:
    if value < 0:
        return "less_than"
    if value > 0:
        return "greater_than"
    return "equal"


def _record_exclusion(
    counts: dict[str, int],
    examples: list[dict[str, Any]],
    components: tuple[str, ...],
    reason: str,
    _components: tuple[str, ...],
) -> None:
    counts[reason] = counts.get(reason, 0) + 1
    if len(examples) < 20:
        examples.append(
            {
                "reason": reason,
                "components": [escaped_text(value) for value in components],
            }
        )


def _certificate_id(
    rule: KeyRule, domain_hash: str, transform_hash: str
) -> str:
    raw = "|".join(
        [
            CERTIFICATE_SCHEMA,
            rule.id,
            rule.source_id,
            domain_hash,
            transform_hash,
            UNICODE_VERSION,
            TARGET_ORDER,
        ]
    )
    return "OC-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def observe_snapshot(
    rule: KeyRule,
    key_results: list[Any],
    *,
    legacy_order: str = "binary_utf8",
    example_limit: int = 20,
) -> SnapshotOrderObservation:
    """Ordering evidence derived *only* from keys present in the snapshot.

    This deliberately does not prove anything about future keys: a snapshot
    containing a single row can never witness an inversion, even when the
    declared transform is non-order-preserving on the wider domain.
    """

    rows = [
        item
        for item in key_results
        if item.rule_id == rule.id and item.target_key is not None
    ]
    rows.sort(key=lambda item: item.ordinal)

    if not rows:
        return SnapshotOrderObservation(
            rule_id=rule.id,
            state="no_records",
            records=0,
            inversion_count=0,
            confluence_count=0,
            examples=(),
        )

    inversion_count = 0
    confluence_count = 0
    examples: list[dict[str, Any]] = []

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            left = rows[i]
            right = rows[j]
            raw_left = UNIT_SEPARATOR.join(value for value in left.raw_values if value is not None)
            raw_right = UNIT_SEPARATOR.join(value for value in right.raw_values if value is not None)
            legacy = legacy_compare(raw_left, raw_right, legacy_order)
            target = target_compare(left.target_key, right.target_key)

            if target == 0 and raw_left != raw_right:
                confluence_count += 1
                if len(examples) < example_limit:
                    examples.append(
                        {
                            "kind": "confluence",
                            "record_ref_a": left.record_ref,
                            "record_ref_b": right.record_ref,
                            "raw_a": escaped_text(raw_left),
                            "raw_b": escaped_text(raw_right),
                            "target_escaped": left.target_key_escaped,
                        }
                    )
            elif legacy != 0 and legacy != target:
                inversion_count += 1
                if len(examples) < example_limit:
                    examples.append(
                        {
                            "kind": "order_inversion",
                            "record_ref_a": left.record_ref,
                            "record_ref_b": right.record_ref,
                            "raw_a": escaped_text(raw_left),
                            "raw_b": escaped_text(raw_right),
                            "target_a_escaped": left.target_key_escaped,
                            "target_b_escaped": right.target_key_escaped,
                            "legacy_comparison": _cmp_label(legacy),
                            "target_comparison": _cmp_label(target),
                        }
                    )

    if inversion_count:
        state = "inversion_observed"
    elif confluence_count:
        state = "confluence_observed"
    else:
        state = "no_inversion_observed"

    return SnapshotOrderObservation(
        rule_id=rule.id,
        state=state,
        records=len(rows),
        inversion_count=inversion_count,
        confluence_count=confluence_count,
        examples=tuple(examples),
    )
