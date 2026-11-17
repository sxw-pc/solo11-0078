from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.errors import ConfigError
from charorder.ingest import load_sources
from charorder.transforms import (
    analyze_visual_confusables,
    compare_visual_keys,
    escaped_text,
    key_visual_profile,
    load_confusable_map,
    visual_skeleton,
)

from tests.support import minimal_config, write_config


STRICT_LATIN = {
    "mode": "strict_script",
    "allowed_scripts": ["Latin"],
    "namespace": "crm_v2.customer.email_key",
    "reason": "该目标列声明只承载拉丁字母邮箱",
}

MIXED_LATIN_CYRILLIC = {
    "mode": "authorized_mixed",
    "allowed_scripts": ["Latin", "Cyrillic"],
    "namespace": "legacy.contact.email_key",
    "reason": "历史来源允许拉丁与西里尔字母混用",
}


class VisualMapTests(unittest.TestCase):
    def test_bundled_map_is_versioned_and_offline(self) -> None:
        confusables = load_confusable_map()
        self.assertTrue(confusables.map_version)
        self.assertTrue(confusables.skeleton_version)
        self.assertEqual(len(confusables.map_sha256), 64)
        self.assertFalse(confusables.provenance["network_access"])
        self.assertTrue(confusables.provenance["offline_only"])
        self.assertGreater(len(confusables.entries), 100)

    def test_map_sha256_matches_bundled_bytes(self) -> None:
        from charorder.transforms import CONFUSABLE_MAP_PATH

        expected = hashlib.sha256(CONFUSABLE_MAP_PATH.read_bytes()).hexdigest()
        self.assertEqual(load_confusable_map().map_sha256, expected)

    def test_latin_and_cyrillic_a_share_a_skeleton(self) -> None:
        latin = visual_skeleton("a")
        cyrillic = visual_skeleton("а")
        self.assertEqual(latin.skeleton, cyrillic.skeleton)
        self.assertEqual(cyrillic.scripts, ("Cyrillic",))
        chain = [step for step in cyrillic.chain if step["kind"] == "map"]
        self.assertEqual(chain[0]["from"], ["U+0430"])
        self.assertEqual(chain[0]["to"], ["U+0061"])

    def test_multicodepoint_and_combining_chain(self) -> None:
        # U+FB01 (ﬁ) expands through the bundled map, and U+00E9 decomposes.
        ligature = visual_skeleton("ﬁ")
        self.assertEqual(ligature.skeleton, "fi")
        self.assertEqual(
            [step["from"] for step in ligature.chain if step["kind"] == "map"][0],
            ["U+FB01"],
        )
        self.assertEqual(
            [step["to"] for step in ligature.chain if step["kind"] == "map"][0],
            ["U+0066", "U+0069"],
        )
        composed = visual_skeleton("é")
        decomposed = visual_skeleton("é")
        self.assertEqual(composed.skeleton, decomposed.skeleton)
        # The chain records the decomposition of U+00E9, not a silent claim.
        self.assertEqual(
            [step["to"] for step in composed.chain if step["kind"] == "map"][0],
            ["U+0065", "U+0301"],
        )

    def test_rn_sequence_maps_to_m(self) -> None:
        self.assertEqual(visual_skeleton("rn").skeleton, "m")

    def test_unmapped_script_is_never_claimed_covered(self) -> None:
        skeleton = visual_skeleton("李雷")
        self.assertEqual(skeleton.scripts, ("Han",))
        self.assertEqual(skeleton.coverage, "partial")
        self.assertIn(0x674E, skeleton.unknown_codepoints)
        # A known script with no bundled entry is specifically not "covered".
        self.assertNotEqual(skeleton.coverage, "covered")

    def test_unknown_codepoint_is_recorded(self) -> None:
        skeleton = visual_skeleton("\U0001F600")  # emoji, no bundled mapping
        self.assertTrue(skeleton.unknown_codepoints)
        self.assertNotEqual(skeleton.coverage, "covered")

    def test_compare_never_used_for_equal_keys_but_detects_cross_script(self) -> None:
        comparison = compare_visual_keys("a@example.com", "а@example.com")
        self.assertTrue(comparison["same_skeleton"])
        self.assertTrue(comparison["cross_script"])
        self.assertFalse(comparison["unknown_coverage"])
        self.assertEqual(comparison["skeleton_version"], load_confusable_map().skeleton_version)


class VisualAnalysisTests(unittest.TestCase):
    def test_script_not_authorized_uses_transformed_key(self) -> None:
        from charorder.models import ScriptPolicy

        policy = ScriptPolicy(
            mode="strict_script", allowed_scripts=("Latin",), namespace="n"
        )
        issues = analyze_visual_confusables("а@example.com", policy=policy)
        codes = {issue.code for issue in issues}
        self.assertIn("SCRIPT_NOT_AUTHORIZED", codes)
        issue = next(i for i in issues if i.code == "SCRIPT_NOT_AUTHORIZED")
        self.assertEqual(issue.details["unauthorized_scripts"], ["Cyrillic"])
        self.assertEqual(issue.details["allowed_scripts"], ["Latin"])

    def test_authorized_mixed_does_not_emit_script_block(self) -> None:
        from charorder.models import ScriptPolicy

        policy = ScriptPolicy(
            mode="authorized_mixed",
            allowed_scripts=("Latin", "Cyrillic"),
            namespace="n",
        )
        codes = {
            issue.code
            for issue in analyze_visual_confusables("а@example.com", policy=policy)
        }
        self.assertNotIn("SCRIPT_NOT_AUTHORIZED", codes)

    def test_unknown_coverage_issue_is_explicit(self) -> None:
        issues = analyze_visual_confusables("李雷")
        issue = next(i for i in issues if i.code == "VISUAL_COVERAGE_UNKNOWN")
        self.assertEqual(issue.details["coverage"], "partial")
        self.assertIn("U+674E", issue.details["unknown_codepoints"])

    def test_profile_separates_key_and_skeleton_hashes(self) -> None:
        # Use a key whose skeleton has actually changed, so the two hashes
        # describe different artifacts.
        profile = key_visual_profile("а@example.com")
        self.assertEqual(len(profile["target_key_sha256"]), 64)
        self.assertEqual(len(profile["skeleton_sha256"]), 64)
        self.assertNotEqual(profile["target_key_sha256"], profile["skeleton_sha256"])
        self.assertEqual(profile["codepoints"][0]["codepoint"], "U+0430")
        # A key that already equals its skeleton still carries both hashes.
        plain = key_visual_profile("a@example.com")
        self.assertEqual(len(plain["skeleton_sha256"]), 64)


class VisualEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scan(self, rows: list[str], policy: dict, *, extra: dict | None = None):
        path = self.root / "data.csv"
        path.write_text("id,email\n" + "\n".join(rows) + "\n", encoding="utf-8")
        key = {
            "id": "email",
            "label": "email",
            "source": "s1",
            "columns": ["email"],
            "destination": "target.email",
            "transform": {
                "normalization": "NFC",
                "case": "casefold",
                "width_fold": True,
                "trim": True,
                "collapse_whitespace": True,
                "invisible": "remove",
            },
            "unique": True,
            "required": True,
            "script_policy": policy,
        }
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[key],
        )
        if extra:
            config_data.update(extra)
        config = load_config(write_config(self.root / "config.json", config_data))
        return config, scan(config, load_sources(config))

    def test_byte_identical_keys_stay_normalization_collision(self) -> None:
        _, result = self._scan(
            ["1,Straße@example.com", "2,STRASSE@example.com"], STRICT_LATIN
        )
        self.assertEqual(len(result.collisions), 1)
        self.assertEqual(result.collisions[0].reason_code, "NORMALIZATION_COLLISION")
        # Exact byte equality must not be reported as a mere visual reminder.
        self.assertEqual(result.visual_candidates, [])
        codes = result.summary["findings_by_code"]
        self.assertNotIn("VISUAL_CONFUSABLE_CANDIDATE", codes)

    def test_identical_keys_with_same_raw_stay_duplicate_key(self) -> None:
        _, result = self._scan(
            ["1,a@example.com", "2,a@example.com"], STRICT_LATIN
        )
        self.assertEqual(len(result.collisions), 1)
        self.assertEqual(result.collisions[0].reason_code, "DUPLICATE_KEY")
        self.assertEqual(result.visual_candidates, [])

    def test_strict_script_blocks_cyrillic_without_fake_collision(self) -> None:
        _, result = self._scan(
            ["1,a@example.com", "2,а@example.com"], STRICT_LATIN
        )
        codes = result.summary["findings_by_code"]
        self.assertEqual(codes.get("SCRIPT_NOT_AUTHORIZED"), 1)
        self.assertIn("VISUAL_CONFUSABLE_CANDIDATE", codes)
        self.assertEqual(result.verdict, "blocked")
        # No fabricated database uniqueness collision.
        self.assertEqual(result.collisions, [])
        # Both binary keys are preserved untouched.
        self.assertEqual(
            sorted(item.target_key for item in result.key_results),
            ["a@example.com", "а@example.com"],
        )
        finding = next(
            item for item in result.findings if item.code == "SCRIPT_NOT_AUTHORIZED"
        )
        self.assertEqual(finding.record_ref, "row:3")
        self.assertEqual(finding.details["unauthorized_scripts"], ["Cyrillic"])
        self.assertEqual(result.plan["gate"]["collision_groups"], 0)
        self.assertFalse(result.plan["gate"]["passes"])

    def test_authorized_mixed_keeps_two_keys_and_requires_review(self) -> None:
        config, result = self._scan(
            ["1,a@example.com", "2,а@example.com"], MIXED_LATIN_CYRILLIC
        )
        self.assertNotIn("SCRIPT_NOT_AUTHORIZED", result.summary["findings_by_code"])
        self.assertEqual(result.collisions, [])
        self.assertEqual(
            sorted(item.target_key for item in result.key_results),
            ["a@example.com", "а@example.com"],
        )
        self.assertEqual(len(result.visual_candidates), 1)
        candidate = result.visual_candidates[0]
        self.assertEqual(candidate.status, "review_required")
        self.assertTrue(candidate.cross_script)
        self.assertTrue(candidate.requires_review)
        self.assertEqual(candidate.policy_mode, "authorized_mixed")
        self.assertEqual(len(candidate.members), 2)
        self.assertIn("Cyrillic", candidate.members[0]["scripts"] + candidate.members[1]["scripts"])
        # The two members keep distinct binary hashes.
        hashes = {member["target_key_sha256"] for member in candidate.members}
        self.assertEqual(len(hashes), 2)
        # Plan says review is pending; it is not "directly migratable".
        self.assertEqual(result.plan["gate"]["visual_pending_reviews"], 1)
        rule = next(r for r in result.plan["rules"] if r["rule_id"] == "email")
        self.assertEqual(rule["status"], "review")
        self.assertFalse(result.plan["gate"]["passes"])
        self.assertEqual(
            result.plan["visual_confusables"]["skeleton_sha256"]
            if "skeleton_sha256" in result.plan["visual_confusables"]
            else candidate.skeleton_sha256,
            candidate.skeleton_sha256,
        )
        self.assertEqual(
            result.plan["visual_confusables"]["map_version"], load_confusable_map().map_version
        )

    def test_review_conclusion_clears_pending_state_consistently(self) -> None:
        skeleton_sha = key_visual_profile("a@example.com")["skeleton_sha256"]
        review = {
            "rule_id": "email",
            "skeleton_sha256": skeleton_sha,
            "conclusion": "distinct_verified",
            "reviewer": "审阅人甲",
            "note": "确认这是两个不同客户的邮箱",
            "decided_at": "2026-01-01",
            "map_version": load_confusable_map().map_version,
            "skeleton_version": load_confusable_map().skeleton_version,
        }
        _, result = self._scan(
            ["1,a@example.com", "2,а@example.com"],
            MIXED_LATIN_CYRILLIC,
            extra={"visual_reviews": [review]},
        )
        self.assertEqual(len(result.visual_candidates), 1)
        candidate = result.visual_candidates[0]
        self.assertEqual(candidate.status, "reviewed")
        self.assertEqual(candidate.conclusion, "distinct_verified")
        self.assertEqual(candidate.reviewer, "审阅人甲")
        self.assertEqual(result.plan["gate"]["visual_pending_reviews"], 0)
        self.assertEqual(result.plan["visual_confusables"]["candidates"][0]["conclusion"], "distinct_verified")
        self.assertTrue(result.plan["gate"]["passes"])

    def test_stale_version_review_is_not_applied(self) -> None:
        skeleton_sha = key_visual_profile("a@example.com")["skeleton_sha256"]
        review = {
            "rule_id": "email",
            "skeleton_sha256": skeleton_sha,
            "conclusion": "distinct_verified",
            "reviewer": "审阅人乙",
            "map_version": "old-map-0",
            "skeleton_version": "old-skeleton-0",
        }
        _, result = self._scan(
            ["1,a@example.com", "2,а@example.com"],
            MIXED_LATIN_CYRILLIC,
            extra={"visual_reviews": [review]},
        )
        candidate = result.visual_candidates[0]
        self.assertEqual(candidate.status, "review_required")
        self.assertIsNone(candidate.conclusion)
        self.assertIn("已忽略旧版本复核", candidate.review_note)
        self.assertEqual(result.plan["gate"]["visual_pending_reviews"], 1)

    def test_unknown_coverage_never_certifies_absence_of_risk(self) -> None:
        han_policy = {
            "mode": "strict_script",
            "allowed_scripts": ["Han"],
            "namespace": "han-only",
        }
        _, result = self._scan(
            ["1,李@example.com", "2,李雷@example.com"], han_policy
        )
        codes = result.summary["findings_by_code"]
        self.assertIn("VISUAL_COVERAGE_UNKNOWN", codes)
        self.assertEqual(codes["SCRIPT_NOT_AUTHORIZED"], 2)
        self.assertEqual(result.plan["visual_confusables"]["certificate"], "none")
        self.assertEqual(
            result.plan["visual_confusables"]["unknown_coverage"],
            result.summary["visual_unknown_coverage"],
        )
        rule = next(r for r in result.plan["rules"] if r["rule_id"] == "email")
        self.assertEqual(rule["visual_unknown_coverage"], result.summary["visual_unknown_coverage"])
        # No candidate group can be formed from keys with different skeletons,
        # but the unknown coverage is still surfaced at rule level.
        for finding in result.findings:
            if finding.code == "VISUAL_COVERAGE_UNKNOWN":
                self.assertIn("不得据此宣称无视觉风险", finding.message)

    def test_no_policy_means_no_visual_evidence(self) -> None:
        path = self.root / "data.csv"
        path.write_text("id,email\n1,a@example.com\n2,а@example.com\n", encoding="utf-8")
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "email",
                    "label": "email",
                    "source": "s1",
                    "columns": ["email"],
                    "transform": {"case": "casefold"},
                    "unique": True,
                    "required": True,
                }
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result = scan(config, load_sources(config))
        self.assertEqual(result.visual_candidates, [])
        self.assertEqual(result.summary["visual_candidate_groups"], 0)

    def test_composite_and_multicodepoint_evidence_carries_chain(self) -> None:
        # Deliberately no casefold: Python's casefold() would fold the ligature
        # itself, and we want the *bundled map* to be the evidence source.
        path = self.root / "data.csv"
        path.write_text(
            "id,name,company\n1,ﬁle,Acme\n2,file,Acme\n", encoding="utf-8"
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "compound",
                    "label": "compound",
                    "source": "s1",
                    "columns": ["name", "company"],
                    "transform": {"normalization": "NFC", "case": "none"},
                    "unique": True,
                    "required": True,
                    "script_policy": MIXED_LATIN_CYRILLIC,
                }
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result = scan(config, load_sources(config))
        # U+FB01 and "fi" are different bytes (NFC does not fold ligatures).
        self.assertEqual(len(result.collisions), 0)
        self.assertEqual(len(result.visual_candidates), 1)
        candidate = result.visual_candidates[0]
        chain_text = json.dumps(candidate.members, ensure_ascii=False)
        self.assertIn("U+FB01", chain_text)
        self.assertEqual(
            {member["target_key"] for member in candidate.members},
            {"ﬁle\x1fAcme", "file\x1fAcme"},
        )


class VisualConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "data.csv").write_text("id,email\n1,a@example.com\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _base(self) -> dict:
        return minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "email",
                    "label": "email",
                    "source": "s1",
                    "columns": ["email"],
                    "transform": {"case": "casefold"},
                    "unique": True,
                    "script_policy": dict(MIXED_LATIN_CYRILLIC),
                }
            ],
        )

    def _expect(self, config: dict, pattern: str) -> None:
        config_path = write_config(self.root / "config.json", config)
        with self.assertRaisesRegex(ConfigError, pattern):
            load_config(config_path)

    def test_strict_script_requires_single_script(self) -> None:
        config = self._base()
        config["keys"][0]["script_policy"] = {
            "mode": "strict_script",
            "allowed_scripts": ["Latin", "Cyrillic"],
        }
        self._expect(config, "strict_script")

    def test_authorized_mixed_requires_two_scripts(self) -> None:
        config = self._base()
        config["keys"][0]["script_policy"] = {
            "mode": "authorized_mixed",
            "allowed_scripts": ["Latin"],
        }
        self._expect(config, "至少需要两个")

    def test_authorized_mixed_cannot_disable_visual_review(self) -> None:
        config = self._base()
        config["keys"][0]["script_policy"] = {
            "mode": "authorized_mixed",
            "allowed_scripts": ["Latin", "Cyrillic"],
            "visual_review_required": False,
        }
        self._expect(config, "不能关闭 visual_review_required")

    def test_unknown_script_name_is_rejected(self) -> None:
        config = self._base()
        config["keys"][0]["script_policy"] = {
            "mode": "strict_script",
            "allowed_scripts": ["Klingon"],
        }
        self._expect(config, "未收录")

    def test_review_requires_known_rule_and_hash(self) -> None:
        config = self._base()
        config["visual_reviews"] = [
            {
                "rule_id": "missing",
                "skeleton_sha256": "0" * 64,
                "conclusion": "distinct_verified",
                "reviewer": "r",
            }
        ]
        self._expect(config, "不存在的键规则")

    def test_review_conclusion_enum_and_note(self) -> None:
        config = self._base()
        config["visual_reviews"] = [
            {
                "rule_id": "email",
                "skeleton_sha256": "0" * 64,
                "conclusion": "looks-fine",
                "reviewer": "r",
            }
        ]
        self._expect(config, "conclusion 必须是")
        config["visual_reviews"][0]["conclusion"] = "merge_required"
        self._expect(config, "必须说明")

    def test_duplicate_reviews_rejected(self) -> None:
        config = self._base()
        review = {
            "rule_id": "email",
            "skeleton_sha256": "a" * 64,
            "conclusion": "distinct_verified",
            "reviewer": "r",
        }
        config["visual_reviews"] = [review, dict(review)]
        self._expect(config, "重复记录")


class VisualArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "data.csv").write_text(
            "id,email\n1,a@example.com\n2,а@example.com\n", encoding="utf-8"
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[
                {
                    "id": "email",
                    "label": "email",
                    "source": "s1",
                    "columns": ["email"],
                    "destination": "target.email",
                    "transform": {"normalization": "NFC", "case": "casefold"},
                    "unique": True,
                    "required": True,
                    "script_policy": dict(MIXED_LATIN_CYRILLIC),
                }
            ],
        )
        self.config = load_config(write_config(self.root / "config.json", config_data))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_visual_artifact_ledger_and_plan_agree(self) -> None:
        result, manifest, output = execute(self.config, self.root / "run")
        visual_path = output / "visual_confusables.json"
        self.assertTrue(visual_path.is_file())
        doc = json.loads(visual_path.read_text(encoding="utf-8"))
        self.assertEqual(doc["kind"], "charorder.visual_confusables")
        self.assertEqual(doc["counts"]["candidate_groups"], len(result.visual_candidates))
        self.assertTrue(doc["separate_from_byte_collisions"])
        self.assertEqual(doc["map"]["map_sha256"], load_confusable_map().map_sha256)
        self.assertEqual(doc["certificate"], "within_map_coverage_only")

        plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["gate"]["visual_pending_reviews"], 1)
        self.assertEqual(
            plan["visual_confusables"]["candidates"][0]["candidate_id"],
            result.visual_candidates[0].candidate_id,
        )
        self.assertEqual(plan["gate"]["collision_groups"], 0)

        connection = sqlite3.connect(
            (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        connection.row_factory = sqlite3.Row
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            member_count = connection.execute(
                "SELECT COUNT(*) FROM visual_candidate_members"
            ).fetchone()[0]
            self.assertEqual(member_count, result.summary["visual_candidate_records"])
            row = connection.execute("SELECT * FROM visual_candidates").fetchone()
            self.assertEqual(row["candidate_id"], result.visual_candidates[0].candidate_id)
            self.assertEqual(row["status"], "review_required")
            self.assertEqual(row["map_version"], load_confusable_map().map_version)
            meta = dict(
                connection.execute("SELECT key, value FROM meta").fetchall()
            )
            self.assertEqual(meta["visual_map_sha256"], load_confusable_map().map_sha256)
            # Byte-level collision tables stay empty; visual evidence lives apart.
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM collisions").fetchone()[0], 0
            )
        finally:
            connection.close()

        # keys.jsonl keeps the original bytes and carries the visual profile.
        key_rows = [
            json.loads(line)
            for line in (output / "keys.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        self.assertEqual(
            sorted(row["target_key"] for row in key_rows),
            ["a@example.com", "а@example.com"],
        )
        for row in key_rows:
            self.assertEqual(len(row["visual_profile"]["target_key_sha256"]), 64)
            self.assertEqual(len(row["visual_profile"]["skeleton_sha256"]), 64)
            self.assertTrue(row["visual_candidate_ids"])

        report_md = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn("视觉混淆候选", report_md)
        self.assertIn("不是数据库唯一碰撞", report_md)
        report_html = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("视觉混淆候选", report_html)
        self.assertIn("VISUAL CONFUSABLE", report_html)

    def test_strict_and_mixed_differ_only_in_gating(self) -> None:
        strict_key = {
            "id": "email",
            "label": "email",
            "source": "s1",
            "columns": ["email"],
            "destination": "target.email",
            "transform": {"normalization": "NFC", "case": "casefold"},
            "unique": True,
            "required": True,
            "script_policy": dict(STRICT_LATIN),
        }
        mixed_key = dict(strict_key, script_policy=dict(MIXED_LATIN_CYRILLIC))
        base = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "data.csv",
                "record_id_field": "id",
            },
            keys=[strict_key],
        )
        strict_config = load_config(
            write_config(self.root / "strict.json", base)
        )
        mixed_config = load_config(
            write_config(self.root / "mixed.json", dict(base, keys=[mixed_key]))
        )
        strict = scan(strict_config, load_sources(strict_config))
        mixed = scan(mixed_config, load_sources(mixed_config))
        # Same keys, same candidate group: only the authorization outcome differs.
        self.assertEqual(
            sorted(item.target_key for item in strict.key_results),
            sorted(item.target_key for item in mixed.key_results),
        )
        self.assertEqual(
            strict.visual_candidates[0].skeleton_sha256,
            mixed.visual_candidates[0].skeleton_sha256,
        )
        self.assertEqual(strict.verdict, "blocked")
        self.assertEqual(mixed.verdict, "review")
        self.assertEqual(strict.collisions, [])
        self.assertEqual(mixed.collisions, [])
        self.assertIn("SCRIPT_NOT_AUTHORIZED", strict.summary["findings_by_code"])
        self.assertNotIn("SCRIPT_NOT_AUTHORIZED", mixed.summary["findings_by_code"])


if __name__ == "__main__":
    unittest.main()
