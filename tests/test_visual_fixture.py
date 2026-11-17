"""End-to-end acceptance tests for the synthetic visual-confusable fixture.

Four acceptance points from the task:
1. visual risk is separate from byte-level collisions;
2. script authorization is traceable;
3. unknown map coverage never becomes a false "no risk" certificate;
4. review status is consistent across plan, artifacts and the SQLite ledger.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.ingest import load_sources
from charorder.transforms import load_confusable_map
from charorder.verify import verify_run

from tests.support import ROOT

VISUAL_CONFIG = ROOT / "fixtures" / "visual" / "config.json"


class VisualFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(VISUAL_CONFIG)
        cls.result = scan(cls.config, load_sources(cls.config))

    def test_fixture_covers_all_required_shapes(self) -> None:
        candidates = {(candidate.rule_id, candidate.skeleton) for candidate in self.result.visual_candidates}
        # Latin/Cyrillic a.
        self.assertIn(("authorized_mixed_key", "a@example.com"), candidates)
        # Multi-codepoint ligature.
        self.assertIn(("mapping_gap_key", "file"), candidates)
        # Mapping chain is carried for each member, not just a flat skeleton.
        ligature = next(
            candidate for candidate in self.result.visual_candidates
            if candidate.rule_id == "mapping_gap_key"
        )
        ligature_member = next(
            member for member in ligature.members
            if member["target_key"] == "ﬁle"
        )
        chain_text = json.dumps(ligature_member["mapping_chain"])
        self.assertIn("U+FB01", chain_text)
        # Combining/composed variant without NFC.
        self.assertTrue(
            any(rule_id == "combining_key" for rule_id, _ in candidates)
        )
        # A real exact collision still exists, separately from visual ones.
        collision_codes = {group.reason_code for group in self.result.collisions}
        self.assertIn("NORMALIZATION_COLLISION", collision_codes)
        self.assertIn("DUPLICATE_KEY", collision_codes)
        self.assertIn("VISUAL_COVERAGE_UNKNOWN", self.result.summary["findings_by_code"])

    def test_exact_collisions_are_never_reported_as_visual_only(self) -> None:
        exact_groups = {
            group.target_key: group
            for group in self.result.collisions
        }
        # Straße / STRASSE collapse to identical bytes in the strict rule.
        group = exact_groups["strasse@example.com"]
        self.assertEqual(group.reason_code, "NORMALIZATION_COLLISION")
        # No visual candidate for an identical-bytes pair.
        for candidate in self.result.visual_candidates:
            if candidate.rule_id == "strict_latin_key":
                self.assertNotIn(
                    "strasse@example.com",
                    {member["target_key"] for member in candidate.members},
                )

    def test_target_keys_are_unchanged_by_visual_preflight(self) -> None:
        keys = {
            (item.rule_id, item.record_ref): item.target_key
            for item in self.result.key_results
        }
        self.assertEqual(keys[("strict_latin_key", "row:2")], "a@example.com")
        self.assertEqual(keys[("strict_latin_key", "row:3")], "а@example.com")
        self.assertEqual(keys[("mapping_gap_key", "row:2")], "ﬁle")
        self.assertEqual(keys[("mapping_gap_key", "row:3")], "file")
        self.assertEqual(keys[("mapping_gap_key", "row:4")], "李雷")

    def test_script_authorization_is_traceable(self) -> None:
        findings = [
            finding
            for finding in self.result.findings
            if finding.code == "SCRIPT_NOT_AUTHORIZED"
        ]
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.rule_id, "strict_latin_key")
            self.assertTrue(finding.source_id)
            self.assertTrue(finding.record_ref)
            self.assertIn("allowed_scripts", finding.details)
            self.assertIn("observed_scripts", finding.details)
            self.assertIn("unauthorized_scripts", finding.details)
            self.assertIn("Cyrillic", finding.details["unauthorized_scripts"])
        # The authorized_mixed rule never emits a script block.
        self.assertFalse(
            any(
                finding.rule_id == "authorized_mixed_key"
                for finding in findings
            )
        )

    def test_unknown_coverage_does_not_certify(self) -> None:
        summary = self.result.summary
        self.assertGreater(summary["visual_coverage_unknown_findings"], 0)
        self.assertEqual(
            self.result.plan["visual_confusables"]["certificate"], "none"
        )
        self.assertFalse(self.result.plan["gate"]["passes"])
        unknown_findings = [
            finding
            for finding in self.result.findings
            if finding.code == "VISUAL_COVERAGE_UNKNOWN"
        ]
        self.assertTrue(unknown_findings)
        for finding in unknown_findings:
            self.assertIn("不得据此宣称无视觉风险", finding.message)

    def test_review_state_consistent_across_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result, _, output = execute(self.config, Path(temp) / "run")
            verify_run(output)
            plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            visual = json.loads(
                (output / "visual_confusables.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                plan["gate"]["visual_pending_reviews"],
                result.summary["visual_pending_reviews"],
            )
            self.assertEqual(
                visual["counts"]["pending_reviews"],
                result.summary["visual_pending_reviews"],
            )
            self.assertEqual(
                manifest["summary"]["visual_pending_reviews"],
                result.summary["visual_pending_reviews"],
            )
            self.assertEqual(
                plan["visual_confusables"]["map_sha256"],
                load_confusable_map().map_sha256,
            )
            connection = sqlite3.connect(
                (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
            )
            connection.row_factory = sqlite3.Row
            try:
                rows = connection.execute(
                    "SELECT * FROM visual_candidates ORDER BY candidate_id"
                ).fetchall()
                self.assertEqual(len(rows), plan["visual_confusables"]["candidate_groups"])
                for row in rows:
                    self.assertEqual(row["status"], "review_required")
                    self.assertEqual(row["map_version"], load_confusable_map().map_version)
                    self.assertEqual(
                        row["skeleton_version"],
                        load_confusable_map().skeleton_version,
                    )
                collision_rows = connection.execute(
                    "SELECT COUNT(*) FROM collisions"
                ).fetchone()[0]
                self.assertEqual(
                    collision_rows, result.summary["collision_groups"]
                )
                # Visual tables never masquerade as collision tables.
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM visual_candidate_members"
                    ).fetchone()[0],
                    result.summary["visual_candidate_records"],
                )
            finally:
                connection.close()

    def test_report_contains_required_evidence_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            _, _, output = execute(self.config, Path(temp) / "run")
            report_md = (output / "report.md").read_text(encoding="utf-8")
            report_html = (output / "report.html").read_text(encoding="utf-8")
            for text in (
                "视觉混淆候选",
                "不是数据库唯一碰撞",
                "骨架版本",
                "原文（转义）",
                "码位",
                "脚本",
                "记录引用",
            ):
                self.assertIn(text, report_md)
            for text in ("VISUAL CONFUSABLE", "视觉混淆候选", "只读", "映射"):
                self.assertIn(text, report_html)
            # No display font is referenced; the verdict is content-derived.
            self.assertNotIn("http://", report_html)
            self.assertNotIn("https://", report_html)


if __name__ == "__main__":
    unittest.main()
