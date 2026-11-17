"""Tests for rule-level future-key ordering compatibility certificates."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from charorder.certificates import (
    build_certificate,
    domain_digest,
    domain_member_count,
    evaluate_rule,
    legacy_compare,
    observe_snapshot,
    target_compare,
)
from charorder.config import load_config
from charorder.engine import scan
from charorder.errors import ConfigError
from charorder.ingest import load_sources
from charorder.models import (
    DomainComponent,
    FutureDomainSpec,
    KeyRule,
    TransformSpec,
)
from charorder.transforms import UNIT_SEPARATOR, apply_transform, make_target_key

from tests.support import minimal_config, write_config


def make_domain(
    charset: list[str],
    *,
    columns: tuple[str, ...] = ("v",),
    min_length: int = 1,
    max_length: int = 1,
    legacy_order: str = "binary_utf8",
    member_limit: int = 20_000,
    pair_budget: int = 200_000,
) -> FutureDomainSpec:
    components = tuple(
        DomainComponent(
            column=column,
            charset=tuple(charset),
            min_length=min_length,
            max_length=max_length,
        )
        for column in columns
    )
    return FutureDomainSpec(
        components=components,
        legacy_order=legacy_order,
        exhaustive_member_limit=member_limit,
        pair_budget=pair_budget,
    )


def make_rule(
    spec: TransformSpec,
    domain: FutureDomainSpec | None,
    *,
    columns: tuple[str, ...] = ("v",),
    max_bytes: int | None = None,
    max_chars: int | None = None,
    rule_id: str = "k1",
) -> KeyRule:
    return KeyRule(
        id=rule_id,
        label=rule_id,
        source_id="s1",
        columns=columns,
        transform=spec,
        max_bytes=max_bytes,
        max_chars=max_chars,
        future_domain=domain,
    )


class ReplayHelperTests(unittest.TestCase):
    def test_legacy_and_target_comparators(self) -> None:
        self.assertEqual(legacy_compare("B", "a", "binary_utf8"), -1)
        self.assertEqual(legacy_compare("B", "a", "codepoint"), -1)
        self.assertEqual(target_compare("b", "a"), 1)
        self.assertEqual(legacy_compare("x", "x", "codepoint"), 0)

    def test_domain_member_count_is_cartesian_product(self) -> None:
        domain = make_domain(["a", "b"], min_length=0, max_length=2)
        # 1 (len 0) + 2 (len 1) + 4 (len 2)
        self.assertEqual(domain_member_count(domain), 7)

    def test_domain_digest_is_stable_and_distinct(self) -> None:
        d1 = make_domain(["a", "b"])
        d2 = make_domain(["a", "b"])
        d3 = make_domain(["a", "c"])
        self.assertEqual(domain_digest(d1), domain_digest(d2))
        self.assertNotEqual(domain_digest(d1), domain_digest(d3))


class LowerInversionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = TransformSpec(normalization="NFC", case="lower", trim=False)
        self.domain = make_domain(["B", "a"], min_length=1, max_length=1)

    def test_certificate_finds_ba_inversion_replayed_by_apply_transform(self) -> None:
        certificate = build_certificate(make_rule(self.spec, self.domain), self.domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.license, "blocked")
        self.assertTrue(certificate.exhaustive)
        counterexample = certificate.counterexample
        self.assertIsNotNone(counterexample)
        self.assertEqual(counterexample["kind"], "order_inversion")
        # The exact B/a story from the issue.
        self.assertEqual(apply_transform("B", self.spec), "b")
        self.assertEqual(apply_transform("a", self.spec), "a")
        self.assertTrue("B" < "a")
        self.assertFalse("b" < "a")
        self.assertEqual(counterexample["legacy_comparison"], "less_than")
        self.assertEqual(counterexample["target_comparison"], "greater_than")
        self.assertTrue(counterexample["replay_matches_pipeline"])

    def test_snapshot_with_only_b_sees_no_inversion_but_certificate_blocks(self) -> None:
        # A snapshot containing a single key 'B' cannot witness the inversion.
        from charorder.models import KeyResult

        result_b = KeyResult(
            key_result_id="K-test",
            source_id="s1",
            rule_id="k1",
            ordinal=1,
            record_ref="row:1",
            record_id="1",
            raw_values=("B",),
            raw_display="'B'",
            target_key="b",
            target_key_escaped="'b'",
            key_sha256=None,
            key_bytes=1,
            key_chars=1,
            changed=True,
        )
        observation = observe_snapshot(make_rule(self.spec, None), [result_b])
        self.assertEqual(observation.state, "no_inversion_observed")
        self.assertEqual(observation.records, 1)

        certificate = build_certificate(make_rule(self.spec, self.domain), self.domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.license, "blocked")

    def test_evaluate_rule_returns_none_without_domain(self) -> None:
        self.assertIsNone(evaluate_rule(make_rule(self.spec, None)))


class NfcCombiningBoundaryTests(unittest.TestCase):
    def test_nfc_reorders_combining_mark_boundary(self) -> None:
        spec = TransformSpec(normalization="NFC", case="none", trim=False)
        domain = make_domain([chr(0x0340), chr(0x0374)], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.license, "blocked")
        counterexample = certificate.counterexample
        self.assertEqual(counterexample["kind"], "order_inversion")
        self.assertTrue(counterexample["replay_matches_pipeline"])
        # Whole-string judgement, not per-code-point.
        raw_a = chr(0x0340)
        raw_b = chr(0x0374)
        self.assertTrue(raw_a < raw_b)
        self.assertFalse(apply_transform(raw_a, spec) < apply_transform(raw_b, spec))

    def test_nfd_cross_combining_character_boundary_inversion(self) -> None:
        spec = TransformSpec(normalization="NFD", case="none", trim=False)
        acute = "́"  # U+0301 combining acute accent
        domain = make_domain(["À", "A", acute], min_length=1, max_length=2)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "counterexample")
        counterexample = certificate.counterexample
        self.assertEqual(counterexample["kind"], "order_inversion")
        decomposed = "A" + acute
        self.assertFalse("À" < decomposed)
        self.assertTrue(
            apply_transform("À", spec) < apply_transform(decomposed, spec)
        )
        self.assertTrue(counterexample["replay_matches_pipeline"])


class WidthFoldTests(unittest.TestCase):
    def test_width_fold_inversion_on_full_string(self) -> None:
        spec = TransformSpec(
            normalization="none", case="none", width_fold=True, trim=False
        )
        domain = make_domain([chr(0xFF01), chr(0x3001)], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.counterexample["kind"], "order_inversion")
        self.assertTrue(certificate.counterexample["replay_matches_pipeline"])

    def test_width_fold_confluence_fullwidth_ascii(self) -> None:
        spec = TransformSpec(
            normalization="NFC", case="lower", width_fold=True, trim=False
        )
        domain = make_domain(["A", "Ａ"], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.counterexample["kind"], "confluence")
        self.assertEqual(
            apply_transform("Ａ", spec), apply_transform("A", spec)
        )


class CasefoldConfluenceTests(unittest.TestCase):
    def test_casefold_merges_sharp_s_domain(self) -> None:
        spec = TransformSpec(normalization="NFC", case="casefold", trim=False)
        # Two concrete word members, declared as explicit charset sequences.
        domain = FutureDomainSpec(
            components=(
                DomainComponent(
                    column="v",
                    charset=("Straße", "STRASSE"),
                    min_length=1,
                    max_length=1,
                ),
            ),
            legacy_order="binary_utf8",
            exhaustive_member_limit=20_000,
            pair_budget=200_000,
        )
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.license, "blocked")
        self.assertEqual(certificate.counterexample["kind"], "confluence")
        self.assertEqual(
            apply_transform("Straße", spec), apply_transform("STRASSE", spec)
        )
        self.assertTrue(certificate.counterexample["replay_matches_pipeline"])


class CompositeKeyTests(unittest.TestCase):
    def test_composite_key_evaluated_whole_with_unit_separator(self) -> None:
        spec = TransformSpec(
            normalization="NFC", case="lower", width_fold=True, trim=False
        )
        columns = ("c1", "c2")
        domain = make_domain(
            ["A", "Ａ", "b"], columns=columns, min_length=1, max_length=1
        )
        rule = make_rule(spec, domain, columns=columns)
        certificate = build_certificate(rule, domain)
        self.assertEqual(certificate.status, "counterexample")
        self.assertEqual(certificate.counterexample["kind"], "confluence")
        # Replay through the exact composite pipeline used by the engine.
        self.assertEqual(
            make_target_key(["Ａ", "b"], spec),
            make_target_key(["A", "b"], spec),
        )
        self.assertIn(UNIT_SEPARATOR, make_target_key(["A", "b"], spec))

    def test_snapshot_observation_uses_full_composite_key(self) -> None:
        from charorder.models import KeyResult

        spec = TransformSpec(
            normalization="NFC", case="lower", width_fold=True, trim=False
        )
        columns = ("c1", "c2")
        rule = make_rule(spec, None, columns=columns)

        def kr(rid: str, raw: tuple[str, ...], target: str) -> KeyResult:
            return KeyResult(
                key_result_id="K" + rid,
                source_id="s1",
                rule_id="k1",
                ordinal=int(rid),
                record_ref="row" + rid,
                record_id=rid,
                raw_values=raw,
                raw_display=str(raw),
                target_key=target,
                target_key_escaped=repr(target),
                key_sha256=None,
                key_bytes=len(target.encode()),
                key_chars=len(target),
                changed=True,
            )

        rows = [
            kr("1", ("Ａ", "b"), make_target_key(["Ａ", "b"], spec)),
            kr("2", ("A", "b"), make_target_key(["A", "b"], spec)),
        ]
        observation = observe_snapshot(rule, rows)
        self.assertEqual(observation.state, "confluence_observed")
        self.assertEqual(observation.confluence_count, 1)

    def test_composite_domain_must_match_rule_columns(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        mismatched = make_domain(["a"], columns=("other",))
        rule = make_rule(spec, mismatched, columns=("v",))
        certificate = build_certificate(rule, mismatched)
        self.assertEqual(certificate.status, "invalid_domain")
        self.assertEqual(certificate.license, "blocked")
        self.assertIn("columns", certificate.invalid_reason)


class ProvenDomainTests(unittest.TestCase):
    def test_identity_transform_on_alphabet_is_fully_proven(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", "b", "c", "d"], min_length=1, max_length=2)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "proven")
        self.assertEqual(certificate.license, "direct_translation")
        self.assertTrue(certificate.exhaustive)
        self.assertFalse(certificate.budget_exhausted)
        self.assertEqual(certificate.counterexample, None)
        self.assertEqual(certificate.eligible_member_count, 20)
        # All distinct pairs were checked: n choose 2.
        self.assertEqual(certificate.pairs_checked, 20 * 19 // 2)

    def test_proven_certificate_binds_domain_and_transform_digests(self) -> None:
        spec = TransformSpec(normalization="NFC", case="lower", trim=False)
        domain = make_domain(["a", "b", "c"], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.domain_digest, domain_digest(domain))
        self.assertEqual(len(certificate.domain_digest), 64)
        self.assertEqual(certificate.target_order, "binary_utf8")
        self.assertTrue(certificate.unicode_version)


class BudgetExhaustionTests(unittest.TestCase):
    def test_member_budget_exhaustion_is_unknown_not_proven(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(
            ["a", "b", "c"], min_length=1, max_length=6, member_limit=50
        )
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "unknown")
        self.assertEqual(certificate.license, "not_established")
        self.assertFalse(certificate.exhaustive)
        self.assertTrue(certificate.budget_exhausted)
        self.assertEqual(certificate.eligible_member_count, 50)
        self.assertIsNone(certificate.counterexample)
        self.assertTrue(any("未找到反例不等于已证保序" in note for note in certificate.notes))

    def test_pair_budget_exhaustion_is_unknown(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(
            ["a", "b", "c"], min_length=1, max_length=4, member_limit=100, pair_budget=10
        )
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "unknown")
        self.assertEqual(certificate.pairs_checked, 10)
        self.assertTrue(certificate.budget_exhausted)

    def test_clean_small_domain_is_proven_even_with_large_budget(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(
            ["a", "b"], min_length=1, max_length=3, member_limit=1, pair_budget=1
        )
        certificate = build_certificate(make_rule(spec, domain), domain)
        # Domain has 14 members but only 1 fits the member budget -> unknown.
        self.assertEqual(certificate.status, "unknown")

    def test_huge_domain_is_bounded_in_memory_and_stays_unknown(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        # 2^30+ members would OOM a materialized product; enumeration is capped.
        domain = make_domain(["a", "b"], min_length=1, max_length=30, member_limit=25)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertGreater(certificate.domain_member_count, 1_000_000_000)
        self.assertLessEqual(certificate.eligible_member_count, 25)
        self.assertEqual(certificate.status, "unknown")
        self.assertFalse(certificate.exhaustive)
        self.assertTrue(certificate.budget_exhausted)


class ExclusionTests(unittest.TestCase):
    def test_surrogate_charset_is_invalid_domain(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", "\ud800"], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        self.assertEqual(certificate.status, "invalid_domain")
        self.assertEqual(certificate.license, "blocked")
        self.assertIn("代理码位", certificate.invalid_reason)

    def test_overlength_keys_are_excluded_and_reason_recorded(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", "b"], min_length=1, max_length=3)
        rule = make_rule(spec, domain, max_bytes=1)
        certificate = build_certificate(rule, domain)
        self.assertIn("over_max_bytes", certificate.excluded_reasons)
        self.assertGreater(certificate.excluded_count, 0)

    def test_domain_with_only_empty_survivor_is_invalid(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", "b"], min_length=0, max_length=3)
        rule = make_rule(spec, domain, max_bytes=0)
        certificate = build_certificate(rule, domain)
        self.assertEqual(certificate.status, "invalid_domain")
        self.assertEqual(certificate.license, "blocked")

    def test_unit_separator_in_domain_is_excluded(self) -> None:
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", UNIT_SEPARATOR], min_length=1, max_length=1)
        certificate = build_certificate(make_rule(spec, domain), domain)
        reasons = set(certificate.excluded_reasons)
        self.assertTrue(
            {"unit_separator_in_raw_domain", "composite_separator_after_transform"}
            & reasons
        )


class EngineAndPlanIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(
        self,
        rows: list[str],
        *,
        transform: dict,
        future_domain: dict | None,
        header: str = "id,v",
        unique: bool = True,
        max_bytes: int | None = None,
    ) -> Path:
        (self.root / "data.csv").write_text(
            header + "\n" + "\n".join(rows) + "\n", encoding="utf-8"
        )
        key = {
            "id": "k1",
            "label": "k1",
            "source": "s1",
            "columns": ["v"],
            "destination": "t.v",
            "transform": transform,
            "unique": unique,
            "required": True,
        }
        if max_bytes is not None:
            key["max_bytes"] = max_bytes
        if future_domain is not None:
            key["future_domain"] = future_domain
        config = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[key],
        )
        return write_config(self.root / "config.json", config)

    def test_snapshot_clean_but_certificate_counterexample_blocks_direct_translation(
        self,
    ) -> None:
        path = self._config(
            ["1,B"],
            transform={
                "normalization": "NFC",
                "case": "lower",
                "width_fold": False,
                "trim": False,
                "collapse_whitespace": False,
                "invisible": "keep",
            },
            future_domain={
                "legacy_order": "binary_utf8",
                "components": [
                    {"column": "v", "charset": ["B", "a"], "min_length": 1, "max_length": 1}
                ],
            },
        )
        config = load_config(path)
        result = scan(config, load_sources(config))

        observation = result.snapshot_observations[0]
        self.assertEqual(observation.state, "no_inversion_observed")
        certificate = result.ordering_certificates[0]
        self.assertEqual(certificate.status, "counterexample")

        plan_rule = result.plan["rules"][0]
        self.assertFalse(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertEqual(plan_rule["cutover_permission"]["license"], "blocked")
        self.assertEqual(
            result.plan["cutover_permissions"]["k1"]["license"], "blocked"
        )

    def test_proven_domain_grants_direct_translation_when_snapshot_gates_clean(
        self,
    ) -> None:
        path = self._config(
            ["1,a", "2,b"],
            transform={
                "normalization": "none",
                "case": "none",
                "width_fold": False,
                "trim": False,
                "collapse_whitespace": False,
                "invisible": "keep",
            },
            future_domain={
                "components": [
                    {"column": "v", "charset": ["a", "b", "c"], "min_length": 1, "max_length": 1}
                ],
            },
        )
        config = load_config(path)
        result = scan(config, load_sources(config))
        certificate = result.ordering_certificates[0]
        self.assertEqual(certificate.status, "proven")
        plan_rule = result.plan["rules"][0]
        self.assertTrue(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertEqual(
            plan_rule["cutover_permission"]["license"], "direct_translation"
        )

    def test_proven_certificate_still_blocked_by_collision_gate(self) -> None:
        path = self._config(
            ["1,a", "2,a"],
            transform={
                "normalization": "none",
                "case": "none",
                "width_fold": False,
                "trim": False,
                "collapse_whitespace": False,
                "invisible": "keep",
            },
            future_domain={
                "components": [
                    {"column": "v", "charset": ["a", "b"], "min_length": 1, "max_length": 1}
                ],
            },
        )
        config = load_config(path)
        result = scan(config, load_sources(config))
        certificate = result.ordering_certificates[0]
        self.assertEqual(certificate.status, "proven")
        plan_rule = result.plan["rules"][0]
        self.assertFalse(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertTrue(plan_rule["cutover_permission"]["snapshot_gate_blocked"])

    def test_unknown_certificate_keeps_legacy_ordering_license(self) -> None:
        path = self._config(
            ["1,aaa"],
            transform={
                "normalization": "none",
                "case": "none",
                "width_fold": False,
                "trim": False,
                "collapse_whitespace": False,
                "invisible": "keep",
            },
            future_domain={
                "exhaustive_member_limit": 5,
                "pair_budget": 5,
                "components": [
                    {"column": "v", "charset": ["a", "b", "c"], "min_length": 1, "max_length": 6}
                ],
            },
        )
        config = load_config(path)
        result = scan(config, load_sources(config))
        certificate = result.ordering_certificates[0]
        self.assertEqual(certificate.status, "unknown")
        plan_rule = result.plan["rules"][0]
        self.assertFalse(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertEqual(
            plan_rule["cutover_permission"]["license"], "not_established"
        )

    def test_no_domain_declared_means_no_proof_and_no_license(self) -> None:
        path = self._config(
            ["1,a", "2,b"],
            transform={
                "normalization": "none",
                "case": "none",
                "width_fold": False,
                "trim": False,
                "collapse_whitespace": False,
                "invisible": "keep",
            },
            future_domain=None,
        )
        config = load_config(path)
        result = scan(config, load_sources(config))
        self.assertEqual(result.ordering_certificates, [])
        plan_rule = result.plan["rules"][0]
        self.assertFalse(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertEqual(
            plan_rule["cutover_permission"]["basis"], "no_certificate_declared"
        )
        self.assertEqual(
            result.summary["snapshot_order_observations"]["no_inversion_observed"], 1
        )


class FutureDomainConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "data.csv").write_text("id,v\n1,a\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _load(self, future_domain: dict) -> Any:
        config = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "k1",
                    "label": "k1",
                    "source": "s1",
                    "columns": ["v"],
                    "destination": "t.v",
                    "transform": {"normalization": "none", "case": "none"},
                    "future_domain": future_domain,
                }
            ],
        )
        return load_config(write_config(self.root / "config.json", config))

    def test_valid_domain_parses(self) -> None:
        config = self._load(
            {
                "components": [
                    {"column": "v", "charset": ["a", "b"], "min_length": 1, "max_length": 2}
                ]
            }
        )
        domain = config.keys[0].future_domain
        self.assertIsNotNone(domain)
        self.assertEqual(domain.legacy_order, "binary_utf8")
        self.assertEqual(domain.components[0].charset, ("a", "b"))

    def test_surrogate_charset_rejected_at_config_time(self) -> None:
        # A lone surrogate cannot even be serialized into UTF-8 JSON, so the
        # config-level rejection is exercised through the direct spec path and
        # a malformed JSON escape path below.
        spec = TransformSpec(normalization="none", case="none", trim=False)
        domain = make_domain(["a", "\ud800"], min_length=1, max_length=1)
        rule = make_rule(spec, domain)
        certificate = build_certificate(rule, domain)
        self.assertEqual(certificate.status, "invalid_domain")

        # And the config parser itself rejects the escaped surrogate form.
        config = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "k1",
                    "label": "k1",
                    "source": "s1",
                    "columns": ["v"],
                    "destination": "t.v",
                    "transform": {"normalization": "none", "case": "none"},
                    "future_domain": {
                        "components": [
                            {
                                "column": "v",
                                "charset": ["a", "\ud800"],
                                "max_length": 1,
                            }
                        ]
                    },
                }
            ],
        )
        path = self.root / "config.json"
        path.write_text(
            json.dumps(config, ensure_ascii=False).encode("utf-8", "surrogatepass").decode(
                "utf-8", "surrogatepass"
            ),
            encoding="utf-8",
            errors="surrogatepass",
        )
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_component_count_mismatch_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "分量数"):
            self._load(
                {
                    "components": [
                        {"column": "v", "charset": ["a"], "max_length": 1},
                        {"column": "x", "charset": ["b"], "max_length": 1},
                    ]
                }
            )

    def test_unknown_legacy_order_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "legacy_order"):
            self._load(
                {
                    "legacy_order": "icu",
                    "components": [
                        {"column": "v", "charset": ["a"], "max_length": 1}
                    ],
                }
            )

    def test_unbounded_max_length_rejected_by_certificate(self) -> None:
        config = self._load(
            {
                "components": [
                    {"column": "v", "charset": ["a", "b"], "min_length": 1, "max_length": None}
                ]
            }
        )
        certificate = evaluate_rule(config.keys[0])
        self.assertEqual(certificate.status, "invalid_domain")
        self.assertIn("有限集", certificate.invalid_reason)

    def test_unknown_future_domain_field_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "未知字段"):
            self._load(
                {
                    "components": [
                        {"column": "v", "charset": ["a"], "max_length": 1}
                    ],
                    "guess": True,
                }
            )


class ArtifactConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_certificate_artifact_plan_and_ledger_are_consistent(self) -> None:
        from charorder.artifacts import execute
        import sqlite3

        (self.root / "data.csv").write_text("id,v\n1,B\n", encoding="utf-8")
        config = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "lower_key",
                    "label": "lower_key",
                    "source": "s1",
                    "columns": ["v"],
                    "destination": "t.v",
                    "transform": {
                        "normalization": "NFC",
                        "case": "lower",
                        "trim": False,
                        "invisible": "keep",
                    },
                    "future_domain": {
                        "components": [
                            {"column": "v", "charset": ["B", "a"],
                             "min_length": 1, "max_length": 1}
                        ]
                    },
                }
            ],
        )
        loaded = load_config(write_config(self.root / "config.json", config))
        result, _, output = execute(loaded, self.root / "run")

        cert_doc = json.loads((output / "certificates.json").read_text("utf-8"))
        cert = cert_doc["certificates"][0]
        self.assertEqual(cert["status"], "counterexample")
        self.assertEqual(cert["license"], "blocked")

        plan = json.loads((output / "plan.json").read_text("utf-8"))
        plan_rule = plan["rules"][0]
        self.assertFalse(plan_rule["cutover_permission"]["direct_translation_allowed"])
        self.assertEqual(
            plan["cutover_permissions"]["lower_key"]["license"],
            cert_doc["cutover_permissions"]["lower_key"]["license"],
        )

        connection = sqlite3.connect(
            (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        try:
            row = connection.execute(
                "SELECT status, license FROM ordering_certificates WHERE rule_id = ?",
                ("lower_key",),
            ).fetchone()
            self.assertEqual(row, ("counterexample", "blocked"))
            snap = connection.execute(
                "SELECT state FROM snapshot_order_observations WHERE rule_id = ?",
                ("lower_key",),
            ).fetchone()
            self.assertEqual(snap[0], "no_inversion_observed")
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
            )
        finally:
            connection.close()

        html = (output / "report.html").read_text("utf-8")
        self.assertIn("未来键域排序兼容证书", html)
        self.assertIn("不允许直译", html)
        markdown = (output / "report.md").read_text("utf-8")
        self.assertIn("未来域证书与直译许可", markdown)
        # Three evidence kinds are kept distinct.
        self.assertIn("当前快照观察", markdown)
        self.assertIn("无证明", result.plan["steps"][6]["detail"])


if __name__ == "__main__":
    unittest.main()
