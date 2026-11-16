from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from charorder.config import load_config
from charorder.engine import scan
from charorder.ingest import load_sources

from tests.support import DEMO_CONFIG, ci_key, minimal_config, write_config


class DemoEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(DEMO_CONFIG)
        cls.result = scan(cls.config, load_sources(cls.config))

    def test_summary_and_verdict(self) -> None:
        summary = self.result.summary
        self.assertEqual(self.result.verdict, "blocked")
        self.assertEqual(summary["source_count"], 3)
        self.assertEqual(summary["record_count"], 31)
        self.assertEqual(summary["key_rule_count"], 7)
        self.assertEqual(summary["keys_evaluated"], 72)
        self.assertGreaterEqual(summary["collision_groups"], 10)
        self.assertGreater(summary["findings_by_severity"]["high"], 0)
        self.assertTrue(self.result.run_id.startswith("r-"))
        self.assertEqual(len(self.result.run_id), 22)

    def test_expected_risk_codes_are_present(self) -> None:
        codes = self.result.summary["findings_by_code"]
        for expected in {
            "SOURCE_INVALID_BYTES",
            "NORMALIZATION_COLLISION",
            "DUPLICATE_KEY",
            "KEY_TOO_LONG_BYTES",
            "INVISIBLE_CHARACTER",
            "BIDI_CONTROL",
            "CONTROL_CHARACTER",
            "ABNORMAL_WHITESPACE",
            "MOJIBAKE_SUSPECT",
            "REPLACEMENT_CHARACTER",
            "REQUIRED_VALUE_MISSING",
            "EMPTY_KEY",
        }:
            self.assertIn(expected, codes)

    def test_collision_reasons_distinguish_duplicate_and_fold(self) -> None:
        sku = next(
            group
            for group in self.result.collisions
            if group.rule_id == "product_sku_unique"
            and group.target_key == "SKU-001"
        )
        self.assertEqual(sku.reason_code, "NORMALIZATION_COLLISION")
        self.assertEqual(len(sku.participants), 2)

        email_duplicate = next(
            group
            for group in self.result.collisions
            if group.rule_id == "customer_email_ci"
            and group.target_key == "li.lei@example.com"
        )
        self.assertEqual(email_duplicate.reason_code, "DUPLICATE_KEY")
        self.assertEqual(len(email_duplicate.raw_variants), 1)

    def test_plan_is_deterministic_and_contains_gate(self) -> None:
        second = scan(self.config, load_sources(self.config))
        self.assertEqual(second.run_id, self.result.run_id)
        self.assertEqual(
            json.dumps(second.plan, ensure_ascii=False, sort_keys=True),
            json.dumps(self.result.plan, ensure_ascii=False, sort_keys=True),
        )
        self.assertFalse(self.result.plan["gate"]["passes"])
        self.assertEqual(self.result.plan["gate"]["fail_on"], "high")
        self.assertEqual(len(self.result.plan["steps"]), 7)
        self.assertIn("forbidden_actions", self.result.plan)
        self.assertNotIn("generated_at", self.result.plan)

    def test_plan_fingerprints_match_sources(self) -> None:
        fingerprints = {
            item["source_id"]: item for item in self.result.plan["source_fingerprints"]
        }
        for load in self.result.source_loads:
            self.assertEqual(fingerprints[load.spec.id]["sha256"], load.sha256)

    def test_key_results_contain_target_hashes_and_byte_lengths(self) -> None:
        result = next(
            item
            for item in self.result.key_results
            if item.rule_id == "customer_email_ci" and item.record_id == "C-1001"
        )
        self.assertEqual(result.target_key, "jose@example.com")
        self.assertTrue(result.changed)
        self.assertEqual(len(result.key_sha256 or ""), 64)
        self.assertEqual(result.key_bytes, len("jose@example.com".encode("utf-8")))
        self.assertIsNotNone(result.target_key_escaped)

    def test_collision_findings_match_groups(self) -> None:
        collision_findings = [
            finding
            for finding in self.result.findings
            if finding.code in {"NORMALIZATION_COLLISION", "DUPLICATE_KEY"}
        ]
        self.assertEqual(len(collision_findings), len(self.result.collisions))
        self.assertTrue(all(finding.details.get("group_id") for finding in collision_findings))


class TargetedEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scan_csv(
        self,
        rows: list[str],
        *,
        keys: list[dict],
        header: str = "id,email",
        config_extra: dict | None = None,
    ):
        path = self.root / "data.csv"
        path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=keys,
        )
        if config_extra:
            config_data.update(config_extra)
        config_path = write_config(self.root / "config.json", config_data)
        config = load_config(config_path)
        return scan(config, load_sources(config))

    def test_casefold_collision_and_overlength(self) -> None:
        result = self._scan_csv(
            ["1,Straße@example.com", "2,STRASSE@example.com"],
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"], max_bytes=10)],
        )
        self.assertEqual(len(result.collisions), 1)
        self.assertEqual(result.collisions[0].reason_code, "NORMALIZATION_COLLISION")
        self.assertEqual(
            result.summary["findings_by_code"]["KEY_TOO_LONG_BYTES"], 2
        )

    def test_empty_key_is_flagged(self) -> None:
        result = self._scan_csv(
            ["1,"],
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"], required=True)],
        )
        self.assertEqual(result.collisions, [])
        self.assertEqual(result.summary["findings_by_code"]["EMPTY_KEY"], 1)
        self.assertEqual(result.verdict, "review")

    def test_missing_required_value_is_high_and_skips_collisions(self) -> None:
        path = self.root / "data.jsonl"
        path.write_text(
            '{"id":"1"}\n'
            '{"id":"2"}\n',
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"], required=True)],
        )
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        result = scan(config, load_sources(config))
        self.assertEqual(result.collisions, [])
        self.assertEqual(
            result.summary["findings_by_code"]["REQUIRED_VALUE_MISSING"], 2
        )
        self.assertEqual(result.verdict, "blocked")

    def test_null_optional_key_is_skipped(self) -> None:
        path = self.root / "data.jsonl"
        path.write_text(
            '{"id":"1","email":null}\n{"id":"2","email":null}\n',
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[
                ci_key(
                    key_id="email",
                    source_id="s1",
                    columns=["email"],
                    required=False,
                )
            ],
        )
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        result = scan(config, load_sources(config))
        self.assertEqual(result.collisions, [])
        self.assertEqual(result.summary["non_null_keys"], 0)
        self.assertEqual(result.verdict, "pass")

    def test_composite_collision_and_unit_separator(self) -> None:
        path = self.root / "data.csv"
        path.write_text(
            "id,name,company\n1,ACME,Tokyo\n2,acme,tokyo\n",
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="compound", source_id="s1", columns=["name", "company"])],
        )
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        result = scan(config, load_sources(config))
        self.assertEqual(len(result.collisions), 1)
        self.assertEqual(result.collisions[0].target_key, "acme\x1ftokyo")

    def test_duplicate_record_ids_are_flagged(self) -> None:
        result = self._scan_csv(
            ["dup,a@example.com", "dup,b@example.com"],
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"], unique=False)],
        )
        self.assertIn("DUPLICATE_RECORD_ID", result.summary["findings_by_code"])
        finding = next(
            item for item in result.findings if item.code == "DUPLICATE_RECORD_ID"
        )
        self.assertEqual(finding.details["record_id"], "dup")
        self.assertEqual(len(finding.details["record_refs"]), 2)

    def test_clean_data_passes_gate(self) -> None:
        result = self._scan_csv(
            ["1,alpha@example.com", "2,beta@example.com"],
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"])],
        )
        self.assertEqual(result.verdict, "pass")
        self.assertTrue(result.plan["gate"]["passes"])
        self.assertEqual(result.summary["findings_total"], 0)
        self.assertTrue(all(rule["status"] == "ready" for rule in result.plan["rules"]))

    def test_severity_override_changes_verdict(self) -> None:
        result = self._scan_csv(
            ["1, a@example.com "],
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"])],
            config_extra={"severity_overrides": {"ABNORMAL_WHITESPACE": "low"}},
        )
        whitespace = [
            finding for finding in result.findings if finding.code == "ABNORMAL_WHITESPACE"
        ]
        self.assertTrue(whitespace)
        self.assertTrue(all(finding.severity == "low" for finding in whitespace))
        self.assertEqual(result.verdict, "pass_with_notes")

    def test_source_parse_error_becomes_high_finding(self) -> None:
        path = self.root / "data.jsonl"
        path.write_text(
            '{"id":"1","email":"a@example.com"}\nnot-json\n', encoding="utf-8"
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"])],
        )
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        result = scan(config, load_sources(config))
        finding = next(
            item for item in result.findings if item.code == "SOURCE_PARSE_ERROR"
        )
        self.assertEqual(finding.severity, "high")
        self.assertEqual(result.verdict, "blocked")


if __name__ == "__main__":
    unittest.main()
