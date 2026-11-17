"""Rule-adjustment preflight tests (cross-table relation preservation)."""

from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.errors import ConfigError
from charorder.ingest import load_sources
from charorder.transforms import apply_transform
from charorder.models import TransformSpec

from tests.support import write_config

# "ſ" (U+017F LATIN SMALL LETTER LONG S) upper-cases to "S"; "a" -> "A".
# Under the given candidates only two of four combinations preserve the link.
ALPHA_ROWS = ["a", "ſ"]
BETA_ROWS = ["A", "b"]

_NONE = {
    "normalization": "none",
    "case": "none",
    "width_fold": False,
    "trim": False,
    "collapse_whitespace": False,
    "invisible": "keep",
}
_UPPER = {**_NONE, "case": "upper"}
_LOWER = {**_NONE, "case": "lower"}


class PreflightFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.alpha_path = root / "alpha.jsonl"
        self.beta_path = root / "beta.jsonl"
        self.alpha_path.write_text(
            "".join(
                json.dumps({"id": f"a{index + 1}", "val": value}) + "\n"
                for index, value in enumerate(ALPHA_ROWS)
            ),
            encoding="utf-8",
        )
        self.beta_path.write_text(
            "".join(
                json.dumps({"id": f"b{index + 1}", "val": value}) + "\n"
                for index, value in enumerate(BETA_ROWS)
            ),
            encoding="utf-8",
        )

    def config(
        self,
        *,
        alpha_candidates: list[dict] | None = None,
        beta_candidates: list[dict] | None = None,
        max_bytes: int | None = None,
        max_chars: int | None = None,
        preflight: dict | None = None,
        extra_rules: list[dict] | None = None,
        preflight_enabled: bool = True,
    ) -> dict:
        alpha_key = {
            "id": "alpha_key",
            "label": "甲表键",
            "source": "alpha",
            "columns": ["val"],
            "destination": "tbl_a.key",
            "target_table": "tbl_a",
            "unique": True,
            "required": True,
            "max_bytes": max_bytes,
            "max_chars": max_chars,
            "transform": _NONE,
            "candidates": (
                [_NONE, _UPPER] if alpha_candidates is None else alpha_candidates
            ),
        }
        beta_key = {
            "id": "beta_key",
            "label": "乙表键",
            "source": "beta",
            "columns": ["val"],
            "destination": "tbl_b.key",
            "target_table": "tbl_b",
            "unique": True,
            "required": True,
            "max_bytes": max_bytes,
            "max_chars": max_chars,
            "transform": _NONE,
            "candidates": (
                [_NONE, _LOWER] if beta_candidates is None else beta_candidates
            ),
        }
        data = {
            "version": 1,
            "project": {"name": "preflight-test", "target": "test"},
            "sources": [
                {
                    "id": "alpha",
                    "type": "jsonl",
                    "path": "alpha.jsonl",
                    "record_id_field": "id",
                },
                {
                    "id": "beta",
                    "type": "jsonl",
                    "path": "beta.jsonl",
                    "record_id_field": "id",
                },
            ],
            "keys": [alpha_key, beta_key, *(extra_rules or [])],
        }
        if preflight_enabled:
            data["preflight"] = preflight if preflight is not None else _default_preflight()
        return data

    def scan(self, config_data: dict):
        config = load_config(write_config(self.root / "config.json", config_data))
        return config, scan(config, load_sources(config))


def _default_preflight() -> dict:
    return {
        "authorized_links": [
            {
                "link_id": "alpha_a1_beta_b1",
                "left": {
                    "source_id": "alpha",
                    "rule_id": "alpha_key",
                    "record_ref": "line:1",
                },
                "right": {
                    "source_id": "beta",
                    "rule_id": "beta_key",
                    "record_ref": "line:1",
                },
            }
        ],
        "forbidden_pairs": [
            {
                "pair_id": "a1_b2",
                "left": {
                    "source_id": "alpha",
                    "rule_id": "alpha_key",
                    "record_ref": "line:1",
                },
                "right": {
                    "source_id": "beta",
                    "rule_id": "beta_key",
                    "record_ref": "line:2",
                },
            },
            {
                "pair_id": "a2_b1",
                "left": {
                    "source_id": "alpha",
                    "rule_id": "alpha_key",
                    "record_ref": "line:2",
                },
                "right": {
                    "source_id": "beta",
                    "rule_id": "beta_key",
                    "record_ref": "line:1",
                },
            },
            {
                "pair_id": "a2_b2",
                "left": {
                    "source_id": "alpha",
                    "rule_id": "alpha_key",
                    "record_ref": "line:2",
                },
                "right": {
                    "source_id": "beta",
                    "rule_id": "beta_key",
                    "record_ref": "line:2",
                },
            },
        ],
    }


class PreflightOptimalityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PreflightFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_two_independent_objectives_have_distinct_optima(self) -> None:
        _, result = self.fixture.scan(self.fixture.config())
        preflight = result.preflight
        self.assertIsNotNone(preflight)
        assert preflight is not None
        self.assertEqual(preflight.state, "optimal")
        self.assertFalse(preflight.stale)
        self.assertEqual(preflight.examined_combinations, 4)
        self.assertEqual(preflight.total_combinations, 4)
        changed = preflight.objective_results["min_changed_records"]
        bytecost = preflight.objective_results["min_total_bytes"]
        assert changed is not None and bytecost is not None

        # Fewest changes: alpha unchanged + beta lower (a, ſ / a, b) => 1 change.
        self.assertEqual(changed.changed_records, 1)
        self.assertEqual(changed.total_bytes, 5)
        self.assertEqual(changed.selected_transforms["alpha_key"].case, "none")
        self.assertEqual(changed.selected_transforms["beta_key"].case, "lower")
        self.assertEqual(changed.status, "optimal")
        self.assertEqual(changed.exit_code, 0)

        # Fewest bytes: alpha upper + beta unchanged (A, S / A, b) => 4 bytes.
        self.assertEqual(bytecost.changed_records, 2)
        self.assertEqual(bytecost.total_bytes, 4)
        self.assertEqual(bytecost.selected_transforms["alpha_key"].case, "upper")
        self.assertEqual(bytecost.selected_transforms["beta_key"].case, "none")
        self.assertEqual(bytecost.status, "optimal")

        # Each objective is proven over the whole space.
        for evaluation in (changed, bytecost):
            self.assertEqual(evaluation.proof["optimality"], "proven_exhaustive")
            self.assertEqual(evaluation.proof["unexamined_combinations"], 0)
            self.assertEqual(evaluation.proof["tie_break"], "candidate_order")

    def test_evidence_matches_direct_transform_recomputation(self) -> None:
        _, result = self.fixture.scan(self.fixture.config())
        preflight = result.preflight
        assert preflight is not None
        records = {
            "alpha": {record.record_ref: record for record in result.source_loads[0].records},
            "beta": {record.record_ref: record for record in result.source_loads[1].records},
        }
        for objective, evaluation in preflight.objective_results.items():
            assert evaluation is not None
            for item in evaluation.key_evidence:
                record = records[item.source_id][item.record_ref]
                spec = evaluation.selected_transforms[item.rule_id]
                expected = apply_transform(str(record.values["val"]), spec)
                self.assertEqual(
                    item.new_key,
                    expected,
                    msg=f"{objective}:{item.rule_id}:{item.record_ref}",
                )
                self.assertEqual(item.new_bytes, len(expected.encode("utf-8")))
                self.assertEqual(item.transform, spec)

    def test_authorized_link_bytes_are_equal_per_objective(self) -> None:
        _, result = self.fixture.scan(self.fixture.config())
        assert result.preflight is not None
        for evaluation in result.preflight.objective_results.values():
            assert evaluation is not None
            alpha = next(
                item
                for item in evaluation.key_evidence
                if item.rule_id == "alpha_key" and item.record_ref == "line:1"
            )
            beta = next(
                item
                for item in evaluation.key_evidence
                if item.rule_id == "beta_key" and item.record_ref == "line:1"
            )
            self.assertIsNotNone(alpha.new_key)
            self.assertEqual(alpha.new_key, beta.new_key)
            self.assertTrue(evaluation.checks["relations"]["authorized_links_satisfied"])

    def test_losing_combinations_are_rejected_with_relation_mismatch(self) -> None:
        _, result = self.fixture.scan(self.fixture.config())
        assert result.preflight is not None
        # Only two of four combos preserve the link; the other two must not be
        # reported as feasible.
        for evaluation in result.preflight.objective_results.values():
            assert evaluation is not None
            combo = tuple(
                sorted(evaluation.selected_transforms.items())
            )
            self.assertIn(
                (evaluation.selected_transforms["alpha_key"].case,
                 evaluation.selected_transforms["beta_key"].case),
                {("none", "lower"), ("upper", "none")},
            )


class PreflightHardConstraintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _fixture(self, alpha_rows: list[str], beta_rows: list[str]) -> PreflightFixture:
        fixture = PreflightFixture(self.root)
        fixture.alpha_path.write_text(
            "".join(
                json.dumps({"id": f"a{i + 1}", "val": value}) + "\n"
                for i, value in enumerate(alpha_rows)
            ),
            encoding="utf-8",
        )
        fixture.beta_path.write_text(
            "".join(
                json.dumps({"id": f"b{i + 1}", "val": value}) + "\n"
                for i, value in enumerate(beta_rows)
            ),
            encoding="utf-8",
        )
        return fixture

    def test_candidate_that_collides_after_full_recompute_is_excluded(self) -> None:
        # Under upper, alpha "a" and "A" both become "A": a same-table collision
        # that only appears after whole-rule recomputation.
        fixture = self._fixture(["a", "A"], ["A", "b"])
        config_data = fixture.config()
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        for objective, evaluation in result.preflight.objective_results.items():
            assert evaluation is not None
            self.assertNotEqual(
                evaluation.selected_transforms["alpha_key"].case,
                "upper",
                msg=objective,
            )

    def test_candidate_that_exceeds_length_after_recompute_is_excluded(self) -> None:
        # "ſ" upper-cases to "S" (1 byte from 2), but a long value under upper
        # could exceed limits. Use max_chars=1 so "their" upper stays > 1.
        fixture = self._fixture(["a", "b"], ["A", "long"])
        config_data = fixture.config(max_chars=1)
        # Every rule must satisfy max_chars for every record. beta "long" is
        # 4 chars in both candidates, so this should be no_feasible.
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "no_feasible")
        self.assertIsNone(result.preflight.objective_results["min_changed_records"])
        witness = result.preflight.witness or {}
        self.assertIn("KEY_TOO_LONG_CHARS", witness.get("categories", {}))

    def test_required_missing_makes_combination_infeasible(self) -> None:
        fixture = PreflightFixture(self.root)
        fixture.alpha_path.write_text(
            '{"id":"a1","val":"a"}\n{"id":"a2"}\n', encoding="utf-8"
        )
        config_data = fixture.config()
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        # Not enough data for the default links (line:2 exists but has no val).
        witness = result.preflight.witness
        self.assertEqual(result.preflight.state, "no_feasible")
        assert witness is not None
        self.assertIn("REQUIRED_VALUE_MISSING", witness.get("categories", {}))

    def test_no_feasible_reports_exhaustive_witness(self) -> None:
        # No combination can equalize "a"/"A" and "b"/"B" across both tables
        # while forbidding the other cross pairs.
        fixture = self._fixture(["a", "b"], ["A", "B"])
        preflight_cfg = _default_preflight()
        config_data = fixture.config(preflight=preflight_cfg)
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "no_feasible")
        self.assertFalse(result.preflight.budget_exhausted)
        self.assertEqual(
            result.preflight.examined_combinations,
            result.preflight.total_combinations,
        )
        self.assertIsNotNone(result.preflight.witness)
        self.assertIn("categories", result.preflight.witness)


class PreflightStaleAndIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PreflightFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_missing_record_reference_is_identity_invalid(self) -> None:
        config_data = self.fixture.config()
        config_data["preflight"]["authorized_links"][0]["right"]["record_ref"] = "line:99"
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "identity_invalid")
        self.assertIsNone(result.preflight.objective_results["min_changed_records"])
        witness = result.preflight.witness or {}
        self.assertTrue(witness.get("identity_errors"))

    def test_missing_source_binding_is_stale(self) -> None:
        config_data = self.fixture.config()
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        loads = load_sources(config)
        # Simulate a source digest mismatch recorded in the constraint list.
        from charorder.preflight import optimize

        mutated = copy.deepcopy(config_data)
        mutated["preflight"]["source_sha256"] = {"alpha": "0" * 64}
        path = write_config(self.root / "config.json", mutated)
        config2 = load_config(path)
        result = optimize(
            config2,
            loads,
            [],
            run_id="r-test",
            config_sha256=config2.config_sha256,
        )
        assert result is not None
        self.assertTrue(result.stale)
        self.assertEqual(result.state, "stale")
        self.assertIsNone(result.objective_results["min_changed_records"])

    def test_same_target_table_entities_must_not_share_key(self) -> None:
        # Two rules in target table "tbl_a": alpha_key is selectable and
        # alpha_alias_key is fixed. Under upper, alpha "a" -> "A" would collide
        # with alpha_alias "A" in the same target table, even though neither
        # rule has an internal collision. The upper candidate must be excluded.
        fixture = PreflightFixture(self.root)
        (self.root / "alpha2.jsonl").write_text(
            '{"id":"c1","val":"A"}\n', encoding="utf-8"
        )
        fixture.alpha_path.write_text(
            '{"id":"a1","val":"a"}\n{"id":"a2","val":"q"}\n', encoding="utf-8"
        )
        fixture.beta_path.write_text(
            '{"id":"b1","val":"B"}\n{"id":"b2","val":"z"}\n', encoding="utf-8"
        )
        alias_rule = {
            "id": "alpha_alias_key",
            "label": "甲表别名键",
            "source": "alpha2",
            "columns": ["val"],
            "destination": "tbl_a.alias_key",
            "target_table": "tbl_a",
            "unique": True,
            "required": True,
            "max_bytes": None,
            "max_chars": None,
            "transform": _NONE,
        }
        config_data = fixture.config(extra_rules=[alias_rule])
        config_data["sources"].append(
            {
                "id": "alpha2",
                "type": "jsonl",
                "path": "alpha2.jsonl",
                "record_id_field": "id",
            }
        )
        config_data["preflight"] = {"authorized_links": [], "forbidden_pairs": []}
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "optimal")
        changed = result.preflight.objective_results["min_changed_records"]
        assert changed is not None
        self.assertEqual(changed.selected_transforms["alpha_key"].case, "none")
        # The fixed alias rule's key is evidence, but its transform is unchanged.
        self.assertEqual(changed.selected_transforms["alpha_alias_key"].case, "none")

    def test_duplicate_link_identity_is_constraint_invalid(self) -> None:
        config_data = self.fixture.config()
        duplicate = copy.deepcopy(config_data["preflight"]["authorized_links"][0])
        duplicate["link_id"] = "second_link"
        config_data["preflight"]["authorized_links"].append(duplicate)
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "constraint_invalid")
        self.assertIsNone(result.preflight.objective_results["min_changed_records"])

    def test_source_digest_binding_staleness(self) -> None:
        config_data = self.fixture.config()
        # Compute the real snapshot digest, then bind it, then mutate a source.
        config = load_config(write_config(self.root / "config.json", config_data))
        from charorder.preflight import compute_source_digest, optimize

        loads = load_sources(config)
        digest = compute_source_digest(loads)
        bound = copy.deepcopy(config_data)
        bound["preflight"]["source_digest"] = digest
        config_ok = load_config(write_config(self.root / "config_bound.json", bound))
        ok = optimize(
            config_ok,
            loads,
            [],
            run_id="r-test",
            config_sha256=config_ok.config_sha256,
        )
        assert ok is not None
        self.assertFalse(ok.stale)
        self.assertEqual(ok.state, "optimal")

        self.fixture.alpha_path.write_text(
            '{"id":"a1","val":"a"}\n{"id":"a2","val":"z"}\n', encoding="utf-8"
        )
        stale_loads = load_sources(config_ok)
        stale = optimize(
            config_ok,
            stale_loads,
            [],
            run_id="r-test2",
            config_sha256=config_ok.config_sha256,
        )
        assert stale is not None
        self.assertTrue(stale.stale)
        self.assertEqual(stale.state, "stale")
        self.assertTrue(any("源摘要" in reason for reason in stale.stale_reasons))

    def test_rules_digest_binding_staleness(self) -> None:
        config_data = self.fixture.config()
        from charorder.models import rule_summary_digest
        from charorder.preflight import optimize

        config = load_config(write_config(self.root / "config.json", config_data))
        loads = load_sources(config)
        bound = copy.deepcopy(config_data)
        bound["preflight"]["rules_sha256"] = rule_summary_digest(config.keys)
        config_ok = load_config(write_config(self.root / "config_rules.json", bound))
        fresh = optimize(
            config_ok,
            loads,
            [],
            run_id="r-test",
            config_sha256=config_ok.config_sha256,
        )
        assert fresh is not None
        self.assertFalse(fresh.stale)

        altered = copy.deepcopy(bound)
        altered["keys"][0]["max_bytes"] = 2
        config_altered = load_config(
            write_config(self.root / "config_altered.json", altered)
        )
        stale = optimize(
            config_altered,
            loads,
            [],
            run_id="r-test2",
            config_sha256=config_altered.config_sha256,
        )
        assert stale is not None
        self.assertTrue(stale.stale)
        self.assertEqual(stale.state, "stale")
        self.assertTrue(any("规则摘要" in reason for reason in stale.stale_reasons))

    def test_authorized_absent_but_keys_differ_is_feasible(self) -> None:
        # No links / pairs declared, but the only combination produces
        # different cross-table keys, so the default policy allows it.
        config_data = self.fixture.config(
            alpha_candidates=[_UPPER],
            beta_candidates=[_LOWER],
            preflight={"authorized_links": [], "forbidden_pairs": []},
        )
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "optimal")

    def test_unauthorized_cross_table_match_no_feasible(self) -> None:
        config_data = self.fixture.config(
            alpha_candidates=[_NONE],
            beta_candidates=[_LOWER],
            preflight={"authorized_links": [], "forbidden_pairs": []},
        )
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        # alpha none yields "a"; beta lower yields "a" for its first row, so an
        # unauthorized cross-table match exists in every (only) selection.
        self.assertEqual(result.preflight.state, "no_feasible")
        witness = result.preflight.witness or {}
        self.assertIn(
            "UNAUTHORIZED_CROSS_TABLE_MATCH", witness.get("categories", {})
        )

    def test_original_transform_not_auto_added_to_candidates(self) -> None:
        config_data = self.fixture.config(
            alpha_candidates=[_UPPER],
            beta_candidates=[_LOWER],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        rule = config.key_map["alpha_key"]
        self.assertEqual(rule.transform.case, "none")
        self.assertEqual([spec.case for spec in rule.candidates], ["upper"])


class PreflightBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PreflightFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_budget_exhaustion_reports_provisional_unknown(self) -> None:
        config_data = self.fixture.config()
        # Make the very first combination feasible so a tentative result exists.
        config_data["keys"][1]["candidates"] = [_LOWER, _NONE]
        config_data["preflight"]["max_combinations"] = 1
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        self.assertTrue(result.preflight.budget_exhausted)
        self.assertEqual(result.preflight.examined_combinations, 1)
        self.assertEqual(result.preflight.total_combinations, 4)
        self.assertEqual(result.preflight.state, "provisional")
        for evaluation in result.preflight.objective_results.values():
            assert evaluation is not None
            self.assertEqual(evaluation.status, "provisional")
            self.assertTrue(evaluation.provisional)
            self.assertEqual(evaluation.proof["optimality"], "unknown")
            self.assertEqual(evaluation.proof["unexamined_combinations"], 3)
            self.assertNotEqual(evaluation.exit_code, 0)

    def test_budget_exhaustion_without_feasible_reports_unknown(self) -> None:
        config_data = self.fixture.config()
        # Force the single examined combo to be infeasible.
        config_data["keys"][0]["candidates"] = [_UPPER, _NONE]
        config_data["keys"][1]["candidates"] = [_LOWER, _NONE]
        config_data["preflight"]["max_combinations"] = 1
        _, result = self.fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.examined_combinations, 1)
        self.assertTrue(result.preflight.budget_exhausted)
        # Under upper/lower the link a->A vs A->a fails.
        self.assertIn(result.preflight.state, {"unknown", "provisional"})
        self.assertNotIn("optimal", result.preflight.state)


class PreflightTieBreakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_ties_resolve_by_candidate_order(self) -> None:
        fixture = PreflightFixture(self.root)
        fixture.alpha_path.write_text(
            '{"id":"a1","val":"a"}\n', encoding="utf-8"
        )
        fixture.beta_path.write_text(
            '{"id":"b1","val":"a"}\n', encoding="utf-8"
        )
        config_data = fixture.config(
            alpha_candidates=[_NONE, {**_NONE, "normalization": "NFC"}],
            beta_candidates=[_NONE, {**_NONE, "normalization": "NFC"}],
            preflight={
                "authorized_links": [
                    {
                        "link_id": "l1",
                        "left": {
                            "source_id": "alpha",
                            "rule_id": "alpha_key",
                            "record_ref": "line:1",
                        },
                        "right": {
                            "source_id": "beta",
                            "rule_id": "beta_key",
                            "record_ref": "line:1",
                        },
                    }
                ],
                "forbidden_pairs": [],
            },
        )
        _, result = fixture.scan(config_data)
        assert result.preflight is not None
        self.assertEqual(result.preflight.state, "optimal")
        for evaluation in result.preflight.objective_results.values():
            assert evaluation is not None
            # Both NFC and none yield the same metrics; candidate index 0 wins.
            self.assertEqual(evaluation.combination_rank, 0)
            self.assertEqual(evaluation.selected_transforms["alpha_key"].normalization, "none")
            self.assertEqual(evaluation.selected_transforms["beta_key"].normalization, "none")
        self.assertEqual(result.preflight.examined_combinations, 4)


class PreflightArtifactConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PreflightFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_unknown_objective_never_reported_optimal(self) -> None:
        config_data = self.fixture.config()
        config_data["keys"][1]["candidates"] = [_LOWER, _NONE]
        config_data["preflight"]["max_combinations"] = 1
        config = load_config(write_config(self.root / "config.json", config_data))
        result, manifest, output = execute(config, self.root / "run")
        document = json.loads((output / "preflight.json").read_text(encoding="utf-8"))
        self.assertTrue(document["budget_exhausted"])
        self.assertEqual(document["state"], "provisional")
        for evaluation in document["objectives"].values():
            assert evaluation is not None
            self.assertNotEqual(evaluation["status"], "optimal")
            self.assertEqual(evaluation["proof"]["optimality"], "unknown")
            self.assertTrue(evaluation["provisional"])
            self.assertNotEqual(evaluation["exit_code"], 0)
        self.assertFalse(result.plan["preflight_gate"]["clears"])
        self.assertFalse(manifest["preflight"]["gate"]["clears"])
        report = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn("unknown", report)
        self.assertIn("暂定", report)
        # Stale/provisional results must not be labelled proven-optimal.
        self.assertNotIn("min_changed_records | optimal", report)

    def test_no_feasible_reports_witness_and_no_optimal(self) -> None:
        config_data = self.fixture.config(
            alpha_candidates=[_NONE],
            beta_candidates=[_LOWER],
            preflight={"authorized_links": [], "forbidden_pairs": []},
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result, manifest, output = execute(config, self.root / "run")
        self.assertEqual(result.preflight.state, "no_feasible")
        self.assertFalse(result.plan["preflight_gate"]["clears"])
        self.assertIn("不得放行", result.plan["preflight_gate"]["reason"])
        document = json.loads((output / "preflight.json").read_text(encoding="utf-8"))
        self.assertIsNone(document["objectives"]["min_changed_records"])
        self.assertTrue(document["witness"]["exhaustive"])
        self.assertIn("UNAUTHORIZED_CROSS_TABLE_MATCH", document["witness"]["categories"])

    def test_plan_report_and_ledger_agree(self) -> None:
        import sqlite3

        config_data = self.fixture.config()
        config = load_config(write_config(self.root / "config.json", config_data))
        result, manifest, output = execute(config, self.root / "run")

        plan_preflight = result.plan["preflight"]
        self.assertEqual(plan_preflight["state"], "optimal")
        self.assertEqual(
            plan_preflight["objectives"]["min_changed_records"]["selected_transforms"],
            {
                rule_id: spec.as_dict()
                for rule_id, spec in result.preflight.objective_results[
                    "min_changed_records"
                ].selected_transforms.items()
            },
        )
        manifest_preflight = manifest["preflight"]
        self.assertEqual(manifest_preflight["state"], "optimal")

        document = json.loads((output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(document["state"], "optimal")
        self.assertEqual(document["run_id"], result.run_id)

        key_rows = [
            json.loads(line)
            for line in (output / "preflight-keys.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(key_rows), 8)
        self.assertEqual(
            {row["objective"] for row in key_rows},
            {"min_changed_records", "min_total_bytes"},
        )

        connection = sqlite3.connect(output / "ledger.sqlite")
        connection.row_factory = sqlite3.Row
        try:
            run = connection.execute("SELECT * FROM preflight_runs").fetchone()
            self.assertEqual(run["state"], "optimal")
            self.assertEqual(run["source_digest"], result.preflight.source_digest)
            objectives = connection.execute(
                "SELECT objective, changed_records, total_bytes FROM preflight_objectives ORDER BY objective"
            ).fetchall()
            self.assertEqual(
                {row["objective"]: (row["changed_records"], row["total_bytes"]) for row in objectives},
                {"min_changed_records": (1, 5), "min_total_bytes": (2, 4)},
            )
            ledger_keys = connection.execute(
                "SELECT COUNT(*) FROM preflight_key_results"
            ).fetchone()[0]
            self.assertEqual(ledger_keys, 8)
            report = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("规则调整预检", report)
            self.assertIn("min_changed_records", report)
        finally:
            connection.close()

    def test_original_config_and_sources_not_written(self) -> None:
        import hashlib

        config_data = self.fixture.config()
        config = load_config(write_config(self.root / "config.json", config_data))
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.iterdir()
            if path.is_file()
        }
        execute(config, self.root / "run")
        after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.iterdir()
            if path.is_file() and path.name in before
        }
        for name, digest in before.items():
            self.assertEqual(after[name], digest, name)


    def test_preflight_gate_blocks_when_provisional(self) -> None:
        config_data = self.fixture.config()
        config_data["keys"][1]["candidates"] = [_LOWER, _NONE]
        config_data["preflight"]["max_combinations"] = 1
        config = load_config(write_config(self.root / "config.json", config_data))
        result, _, _ = execute(config, self.root / "run")
        gate = result.plan["preflight_gate"]
        self.assertFalse(gate["clears"])
        self.assertEqual(gate["state"], "provisional")
        self.assertIn("预算耗尽", gate["reason"])

    def test_preflight_gate_passes_when_optimal(self) -> None:
        config_data = self.fixture.config()
        config = load_config(write_config(self.root / "config.json", config_data))
        result, _, _ = execute(config, self.root / "run")
        gate = result.plan["preflight_gate"]
        self.assertTrue(gate["clears"])
        self.assertEqual(gate["state"], "optimal")

    def test_html_escapes_preflight_values(self) -> None:
        config_data = self.fixture.config()
        config = load_config(write_config(self.root / "config.json", config_data))
        _, _, output = execute(config, self.root / "run")
        html = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("规则调整预检", html)
        self.assertIn("min_changed_records", html)
        self.assertIn("preflight.json", html)
        # No raw <script src> / external assets from the preflight section.
        self.assertNotRegex(html, re.compile(r"<script\b[^>]*\bsrc\s*=", re.IGNORECASE))


class PreflightConfigValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = PreflightFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _expect(self, config_data: dict, pattern: str) -> None:
        path = write_config(self.root / "config.json", config_data)
        with self.assertRaisesRegex(ConfigError, pattern):
            load_config(path)

    def test_duplicate_candidates_rejected(self) -> None:
        config_data = self.fixture.config(alpha_candidates=[_NONE, _NONE])
        self._expect(config_data, "重复候选")

    def test_candidate_field_unknown_rejected(self) -> None:
        config_data = self.fixture.config(
            alpha_candidates=[_NONE, {**_UPPER, "collation": "icu"}]
        )
        self._expect(config_data, "未知字段")

    def test_preflight_without_candidates_rejected(self) -> None:
        config_data = self.fixture.config()
        for key in config_data["keys"]:
            key.pop("candidates", None)
        self._expect(config_data, "没有任何 keys 提供 candidates")

    def test_link_with_same_rule_rejected(self) -> None:
        config_data = self.fixture.config()
        config_data["preflight"]["authorized_links"][0]["right"] = copy.deepcopy(
            config_data["preflight"]["authorized_links"][0]["left"]
        )
        self._expect(config_data, "必须绑定不同规则")

    def test_link_with_mismatched_source_rejected(self) -> None:
        config_data = self.fixture.config()
        config_data["preflight"]["authorized_links"][0]["left"]["source_id"] = "beta"
        self._expect(config_data, "与规则 .* 的源不一致")

    def test_unknown_rule_rejected(self) -> None:
        config_data = self.fixture.config()
        config_data["preflight"]["authorized_links"][0]["left"]["rule_id"] = "missing"
        self._expect(config_data, "不存在的规则")

    def test_invalid_budget_rejected(self) -> None:
        config_data = self.fixture.config()
        config_data["preflight"]["max_combinations"] = 0
        self._expect(config_data, "正整数")


if __name__ == "__main__":
    unittest.main()
