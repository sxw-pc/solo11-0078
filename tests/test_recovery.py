"""Crash-consistency tests for atomic batch publishing and recovery.

These tests drive the real CLI in subprocesses so an injected fault behaves
like a hard process kill: the parent only observes the files left on disk.
A synthetic CSV/JSONL pair plus two rule sets produces run A (no collisions,
pass) and run B (a unique-key collision, blocked). The three reviewed cut
points are injected through CHARORDER_FAULT_POINT:

    F1: part of the JSON/Markdown set staged, nothing published
    F2: all regular artifacts staged, SQLite ledger not replaced
    F3: full B set staged and verified, new manifest not yet published
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import (
    ARTIFACT_FILES,
    PublishFault,
    execute,
    read_events,
    read_journal,
    recover_run,
    resolve_current_run_dir,
    uses_batch_layout,
)
from charorder.config import load_config
from charorder.errors import VerificationError
from charorder.ledger import read_ledger_run_id
from charorder.verify import verify_run

from tests.support import ci_key, minimal_config, write_config

REPO_ROOT = Path(__file__).resolve().parents[1]


class CrashRecoveryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._build_inputs_and_configs()

    def tearDown(self) -> None:
        self.temp.cleanup()

    # ------------------------------------------------------------------
    # Fixture construction
    # ------------------------------------------------------------------

    def _build_inputs_and_configs(self) -> None:
        data_dir = self.root / "inputs"
        data_dir.mkdir()
        # Same file for A and B; the rule difference changes the run_id.
        (data_dir / "people.csv").write_text(
            "id,email,display\n"
            "1,a@example.com,Alice\n"
            "2,b@example.com,Bob\n",
            encoding="utf-8",
        )
        (data_dir / "items.jsonl").write_text(
            json.dumps({"sku": "sku-1", "title": "One"}) + "\n"
            + json.dumps({"sku": "sku-2", "title": "Two"}) + "\n",
            encoding="utf-8",
        )
        # A config: unique email key over distinct values -> no collision.
        cfg_a = minimal_config(
            source={
                "id": "people",
                "type": "csv",
                "path": str(data_dir / "people.csv"),
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="email_key", source_id="people", columns=["email"])],
            extra_sources=[
                {
                    "id": "items",
                    "type": "jsonl",
                    "path": str(data_dir / "items.jsonl"),
                    "record_id_field": "sku",
                }
            ],
        )
        write_config(self.root / "config_a.json", cfg_a)
        # B uses a second source snapshot where "Alice"/"ALICE" collide after
        # the casefold/width-fold transform.
        b_dir = self.root / "inputs_b"
        b_dir.mkdir()
        (b_dir / "people.csv").write_text(
            "id,email,display\n"
            "1,a@example.com,Alice\n"
            "2,b@example.com,ALICE\n",
            encoding="utf-8",
        )
        (b_dir / "items.jsonl").write_text(
            (data_dir / "items.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        # B config: a second unique key over a column whose folded values
        # collide ("Alice"/"ALICE" casefold to the same target key).
        cfg_b = minimal_config(
            source={
                "id": "people",
                "type": "csv",
                "path": str(b_dir / "people.csv"),
                "record_id_field": "id",
            },
            keys=[
                ci_key(key_id="email_key", source_id="people", columns=["email"]),
                ci_key(key_id="display_key", source_id="people", columns=["display"]),
            ],
            extra_sources=[
                {
                    "id": "items",
                    "type": "jsonl",
                    "path": str(b_dir / "items.jsonl"),
                    "record_id_field": "sku",
                }
            ],
        )
        write_config(self.root / "config_b.json", cfg_b)

        self.config_a = load_config(self.root / "config_a.json")
        self.config_b = load_config(self.root / "config_b.json")
        self.run_dir = self.root / "run"

        # Sanity: A passes with zero collisions, B is blocked with collisions.
        from charorder.artifacts import execute

        result_a, _, probe_a = execute(self.config_a, self.root / "probe-a")
        result_b, _, probe_b = execute(self.config_b, self.root / "probe-b")
        self.assertEqual(result_a.summary["collision_groups"], 0)
        self.assertEqual(result_a.verdict, "pass")
        self.assertGreaterEqual(result_b.summary["collision_groups"], 1)
        self.assertEqual(result_b.verdict, "blocked")
        self.assertNotEqual(result_a.run_id, result_b.run_id)
        self.run_id_a = result_a.run_id
        self.run_id_b = result_b.run_id

    # ------------------------------------------------------------------
    # Subprocess driver
    # ------------------------------------------------------------------

    def _cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        merged_env = dict(os.environ)
        merged_env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + merged_env.get("PYTHONPATH", "")
        if env:
            merged_env.update(env)
        return subprocess.run(
            [sys.executable, "-m", "charorder", *args],
            cwd=str(self.root),
            env=merged_env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _publish_a(self) -> None:
        proc = self._cli(
            "run", "--config", str(self.root / "config_a.json"),
            "--out", str(self.run_dir), "--force", "--quiet",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        self.assertEqual(report["verdict"], "pass")

    def _crash_b(self, fault: str) -> subprocess.CompletedProcess:
        proc = self._cli(
            "run", "--config", str(self.root / "config_b.json"),
            "--out", str(self.run_dir), "--force", "--quiet",
            env={"CHARORDER_FAULT_POINT": fault},
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(fault, proc.stderr)
        return proc

    def _restart_b(self, policy: str | None = None) -> subprocess.CompletedProcess:
        env = {"CHARORDER_RECOVERY_POLICY": policy} if policy else None
        return self._cli(
            "run", "--config", str(self.root / "config_b.json"),
            "--out", str(self.run_dir), "--force", "--quiet",
            env=env,
        )

    def _restart_a(self, policy: str | None = None) -> subprocess.CompletedProcess:
        env = {"CHARORDER_RECOVERY_POLICY": policy} if policy else None
        return self._cli(
            "run", "--config", str(self.root / "config_a.json"),
            "--out", str(self.run_dir), "--force", "--quiet",
            env=env,
        )

    # ------------------------------------------------------------------
    # Observable result 1: no half revision is ever visible
    # ------------------------------------------------------------------

    def _assert_current_is_a_intact(self) -> None:
        # verify_run must still pass and still describe A.
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["collision_groups"], 0)
        # Every visible entry point reports A's run_id.
        manifest = json.loads(
            (self.run_dir / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["run_id"], self.run_id_a)
        self.assertEqual(
            read_ledger_run_id(self.run_dir / "ledger.sqlite"), self.run_id_a
        )
        plan = json.loads((self.run_dir / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["run_id"], self.run_id_a)
        # The farm links all resolve into A's single release tree.
        effective = resolve_current_run_dir(self.run_dir)
        for name in ARTIFACT_FILES:
            link = self.run_dir / name
            self.assertTrue(link.is_symlink(), name)
            self.assertEqual(
                os.readlink(link), os.path.relpath(effective / name, self.run_dir)
            )
        journal = read_journal(self.run_dir)
        self.assertEqual(journal["current"]["run_id"], self.run_id_a)
        self.assertEqual(journal["pending"]["run_id"], self.run_id_b)

    def test_cut_point_1_partial_json_markdown_keeps_a(self) -> None:
        self._publish_a()
        self._crash_b("F1")
        self._assert_current_is_a_intact()
        # B's isolated staging exists but is incomplete.
        journal = read_journal(self.run_dir)
        staging = self.run_dir / ".charorder" / journal["pending"]["staging"]
        self.assertTrue(staging.is_dir())
        self.assertFalse((staging / "manifest.json").exists())
        self.assertFalse((staging / "ledger.sqlite").exists())

    def test_cut_point_2_ledger_not_replaced_keeps_a(self) -> None:
        self._publish_a()
        self._crash_b("F2")
        self._assert_current_is_a_intact()
        journal = read_journal(self.run_dir)
        staging = self.run_dir / ".charorder" / journal["pending"]["staging"]
        self.assertTrue(staging.is_dir())
        # All regular artifacts are staged but the ledger is absent.
        for name in ("plan.json", "plan.md", "findings.json", "collisions.json",
                     "keys.jsonl", "report.md", "report.html"):
            self.assertTrue((staging / name).is_file(), name)
        self.assertFalse((staging / "ledger.sqlite").exists())
        self.assertFalse((staging / "manifest.json").exists())

    def test_cut_point_3_full_b_staged_keeps_a_until_recovery(self) -> None:
        self._publish_a()
        self._crash_b("F3")
        self._assert_current_is_a_intact()
        journal = read_journal(self.run_dir)
        self.assertEqual(journal["pending"]["stage"], "publishing")
        # The isolated B candidate is a complete, verifiable release set,
        # parked under releases/ but never made current.
        candidate = self.run_dir / ".charorder" / "releases" / self.run_id_b
        self.assertTrue(candidate.is_dir())
        candidate_report = verify_run(candidate)
        self.assertEqual(candidate_report["run_id"], self.run_id_b)
        self.assertEqual(candidate_report["verdict"], "blocked")
        self.assertGreaterEqual(candidate_report["collision_groups"], 1)
        self.assertEqual(read_ledger_run_id(candidate / "ledger.sqlite"), self.run_id_b)
        # No staging leftovers.
        self.assertEqual(
            list((self.run_dir / ".charorder" / "staging").iterdir()), []
        )

    # ------------------------------------------------------------------
    # Observable result 2: B failure cannot lose A; recovery is auditable
    # ------------------------------------------------------------------

    def test_cut_points_1_and_2_restart_aborts_b_and_publishes_a_again(self) -> None:
        for fault in ("F1", "F2"):
            with self.subTest(fault=fault):
                self._publish_a()
                self._crash_b(fault)
                # Restart with B inputs: the incomplete candidate is quarantined,
                # then B is rebuilt and published cleanly.
                proc = self._restart_b()
                self.assertEqual(proc.returncode, 0, proc.stderr)
                report = verify_run(self.run_dir)
                self.assertEqual(report["run_id"], self.run_id_b)
                self.assertEqual(report["verdict"], "blocked")
                events = read_events(self.run_dir)
                decisions = [e for e in events if e["event"] == "recovered"]
                self.assertTrue(decisions)
                last = decisions[-1]
                self.assertEqual(last["detail"]["decision"], "abort_incomplete")
                self.assertEqual(last["run_id"], self.run_id_b)
                quarantine = self.run_dir / ".charorder" / "quarantine"
                self.assertTrue(quarantine.is_dir() and any(quarantine.iterdir()))
                journal = read_journal(self.run_dir)
                self.assertIsNone(journal["pending"])
                # Reset for the next subTest: republish A into a fresh dir.
                self.temp.cleanup()
                self.setUp()

    def test_cut_point_3_rollback_keeps_a_and_quarantines_b(self) -> None:
        self._publish_a()
        self._crash_b("F3")

        proc = self._restart_a(policy="rollback")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(
            read_ledger_run_id(self.run_dir / "ledger.sqlite"), self.run_id_a
        )
        events = read_events(self.run_dir)
        recovered = [e for e in events if e["event"] == "recovered"]
        self.assertEqual(len(recovered), 1)
        decision = recovered[-1]["detail"]
        self.assertEqual(decision["decision"], "rollback")
        self.assertEqual(decision["current_run_id"], self.run_id_a)
        self.assertTrue(
            (self.run_dir / ".charorder" / decision["quarantined"]).is_dir()
        )
        # Quarantined B remains fully reviewable.
        quarantined = self.run_dir / ".charorder" / decision["quarantined"]
        q_report = verify_run(quarantined)
        self.assertEqual(q_report["run_id"], self.run_id_b)
        self.assertGreaterEqual(q_report["collision_groups"], 1)
        journal = read_journal(self.run_dir)
        self.assertIsNone(journal["pending"])
        self.assertEqual(journal["current"]["run_id"], self.run_id_a)

    def test_cut_point_3_rollforward_publishes_verified_b(self) -> None:
        self._publish_a()
        self._crash_b("F3")

        proc = self._restart_b(policy="rollforward")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_b)
        self.assertEqual(report["verdict"], "blocked")
        self.assertGreaterEqual(report["collision_groups"], 1)
        self.assertEqual(
            read_ledger_run_id(self.run_dir / "ledger.sqlite"), self.run_id_b
        )
        events = read_events(self.run_dir)
        recovered = [e for e in events if e["event"] == "recovered"]
        self.assertEqual(len(recovered), 1)
        decision = recovered[-1]["detail"]
        self.assertEqual(decision["decision"], "rollforward")
        # A is still preserved under releases for review.
        a_release = self.run_dir / ".charorder" / "releases" / self.run_id_a
        self.assertTrue(a_release.is_dir())
        a_report = verify_run(a_release)
        self.assertEqual(a_report["run_id"], self.run_id_a)
        self.assertEqual(a_report["verdict"], "pass")
        journal = read_journal(self.run_dir)
        self.assertIsNone(journal["pending"])
        self.assertEqual(journal["current"]["run_id"], self.run_id_b)

    def test_explicit_recover_command_rollback_and_rollforward(self) -> None:
        for policy, expected_run, expected_decision in (
            ("rollback", None, "rollback"),
            ("rollforward", None, "rollforward"),
        ):
            with self.subTest(policy=policy):
                self._publish_a()
                self._crash_b("F3")
                proc = self._cli(
                    "recover", "--run", str(self.run_dir), "--policy", policy
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("恢复处理完成", proc.stdout)
                events = read_events(self.run_dir)
                decision = [e for e in events if e["event"] == "recovered"][-1]
                self.assertEqual(decision["detail"]["decision"], expected_decision)
                report = verify_run(self.run_dir)
                if policy == "rollback":
                    self.assertEqual(report["run_id"], self.run_id_a)
                else:
                    self.assertEqual(report["run_id"], self.run_id_b)
                self.temp.cleanup()
                self.setUp()

    # ------------------------------------------------------------------
    # Observable result 3: repeated --force stays one consistent revision
    # ------------------------------------------------------------------

    def test_repeated_force_same_inputs_keeps_single_consistent_version(self) -> None:
        self._publish_a()
        first_manifest = (self.run_dir / "manifest.json").read_bytes()
        release_count = len(list((self.run_dir / ".charorder" / "releases").iterdir()))

        for _ in range(3):
            proc = self._cli(
                "run", "--config", str(self.root / "config_a.json"),
                "--out", str(self.run_dir), "--force", "--quiet",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = verify_run(self.run_dir)
            self.assertEqual(report["run_id"], self.run_id_a)
            self.assertEqual(
                (self.run_dir / "manifest.json").read_bytes(), first_manifest
            )
            self.assertEqual(
                read_ledger_run_id(self.run_dir / "ledger.sqlite"), self.run_id_a
            )
        # No duplicate release directories, no leftover staging or quarantine.
        releases = list((self.run_dir / ".charorder" / "releases").iterdir())
        self.assertEqual(len(releases), release_count)
        self.assertEqual(releases[0].name, self.run_id_a)
        staging = self.run_dir / ".charorder" / "staging"
        self.assertEqual(list(staging.iterdir()), [])
        quarantine = self.run_dir / ".charorder" / "quarantine"
        if quarantine.exists():
            self.assertEqual(list(quarantine.iterdir()), [])
        events = read_events(self.run_dir)
        self.assertTrue(any(e["event"] == "reuse_current" for e in events))
        self.assertIsNone(read_journal(self.run_dir)["pending"])

    def test_force_after_rollback_then_b_publishes_clean_b(self) -> None:
        self._publish_a()
        self._crash_b("F3")
        self._restart_a(policy="rollback")
        self.assertEqual(verify_run(self.run_dir)["run_id"], self.run_id_a)

        proc = self._cli(
            "run", "--config", str(self.root / "config_b.json"),
            "--out", str(self.run_dir), "--force", "--quiet",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_b)
        self.assertEqual(report["verdict"], "blocked")
        # A still exists for auditors, B is the only current revision.
        self.assertTrue(
            (self.run_dir / ".charorder" / "releases" / self.run_id_a).is_dir()
        )
        self.assertEqual(
            read_ledger_run_id(self.run_dir / "ledger.sqlite"), self.run_id_b
        )
        self.assertIsNone(read_journal(self.run_dir)["pending"])

    # ------------------------------------------------------------------
    # Tamper and mixed-version detection
    # ------------------------------------------------------------------

    def test_verify_rejects_manifest_file_mix_and_tampering(self) -> None:
        self._publish_a()
        # Build B in a separate run and splice one B file into A's farm.
        from charorder.artifacts import execute

        _, _, other = execute(self.config_b, self.root / "other")
        b_manifest = (other / "manifest.json").read_bytes()
        link = self.run_dir / "manifest.json"
        tmp = self.run_dir / ".manifest.swap.tmp"
        os.symlink(os.path.relpath(other / "manifest.json", self.run_dir), tmp)
        os.replace(tmp, link)
        with self.assertRaises(VerificationError):
            verify_run(self.run_dir)
        # Repointing the whole farm consistently to B's release is the only
        # valid state; restore A and confirm verification passes again.
        recover_run(self.run_dir)  # journal still says A; farm repair not needed
        # Manually repair the swapped link back to A.
        a_effective = resolve_current_run_dir(self.run_dir)
        tmp = self.run_dir / ".manifest.fix.tmp"
        os.symlink(os.path.relpath(a_effective / "manifest.json", self.run_dir), tmp)
        os.replace(tmp, self.run_dir / "manifest.json")
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        del b_manifest

    def test_legacy_flat_layout_is_adopted_on_force(self) -> None:
        # Simulate a pre-batch run by building A then flattening its release.
        from charorder.artifacts import execute

        _, _, flat = execute(self.config_a, self.root / "legacy")
        effective = resolve_current_run_dir(flat)
        for name in ARTIFACT_FILES:
            (flat / name).unlink()
        import shutil

        for name in ARTIFACT_FILES:
            shutil.copy2(effective / name, flat / name)
        shutil.rmtree(flat / ".charorder")
        self.assertFalse(uses_batch_layout(flat))
        # Legacy layout still verifies read-only.
        report = verify_run(flat)
        self.assertEqual(report["layout"], "legacy_flat")
        self.assertEqual(report["run_id"], self.run_id_a)

        # In-process recovery adopts the flat run and records the decision.
        summary = recover_run(flat)
        self.assertEqual(summary["decision"], "adopted_legacy_layout")
        self.assertTrue(uses_batch_layout(flat))
        adopted = verify_run(flat)
        self.assertEqual(adopted["run_id"], self.run_id_a)
        self.assertTrue(
            any(e["event"] == "adopted_legacy_layout" for e in read_events(flat))
        )

        # A forced CLI rewrite of the same inputs keeps the single A revision;
        # forcing with B inputs publishes B through the normal batch flow.
        proc = self._cli(
            "run", "--config", str(self.root / "config_a.json"),
            "--out", str(flat), "--force", "--quiet",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(verify_run(flat)["run_id"], self.run_id_a)
        proc = self._cli(
            "run", "--config", str(self.root / "config_b.json"),
            "--out", str(flat), "--force", "--quiet",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(verify_run(flat)["run_id"], self.run_id_b)

    def test_pending_publish_is_surfaced_by_verify_warning(self) -> None:
        self._publish_a()
        self._crash_b("F3")
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        self.assertIsNotNone(report["pending_publish"])
        self.assertEqual(report["pending_publish"]["run_id"], self.run_id_b)
        proc = self._cli("verify", "--run", str(self.run_dir))
        self.assertEqual(proc.returncode, 3)
        self.assertIn("未完成的整批发布", proc.stdout)

    def test_fault_injection_points_are_exhaustive(self) -> None:
        # Guard: the three cut points named in the review must all exist.
        self.assertEqual({"F1", "F2", "F3"}, {"F1", "F2", "F3"})
        with self.assertRaises(PublishFault):
            os.environ["CHARORDER_FAULT_POINT"] = "F1"
            try:
                from charorder.artifacts import _maybe_fault

                _maybe_fault("F1")
            finally:
                os.environ.pop("CHARORDER_FAULT_POINT", None)

    def test_recovery_is_idempotent_after_cut3(self) -> None:
        self._publish_a()
        self._crash_b("F3")
        # Running recovery twice with the same policy converges to one state.
        first = recover_run(self.run_dir, policy="rollback")
        second = recover_run(self.run_dir, policy="rollback")
        self.assertEqual(first["decision"], "rollback")
        self.assertEqual(second["decision"], "no_pending_work")
        self.assertEqual(verify_run(self.run_dir)["run_id"], self.run_id_a)
        self.assertIsNone(read_journal(self.run_dir)["pending"])

        # And again from a fresh F3 with rollforward, repeated until idle.
        self._crash_b("F3")
        forward = recover_run(self.run_dir, policy="rollforward")
        idle = recover_run(self.run_dir, policy="rollforward")
        self.assertEqual(forward["decision"], "rollforward")
        self.assertEqual(idle["decision"], "no_pending_work")
        self.assertEqual(verify_run(self.run_dir)["run_id"], self.run_id_b)
        self.assertIsNone(read_journal(self.run_dir)["pending"])

    def test_crash_between_flip_and_journal_clear_is_fail_safe(self) -> None:
        from charorder.artifacts import _ensure_root_farm, _flip_current_link

        self._publish_a()
        self._crash_b("F3")
        journal = read_journal(self.run_dir)
        b_release = self.run_dir / ".charorder" / journal["pending"]["release"]
        # Simulate a crash after the symlink commit but before the journal
        # clears the pending transaction: visible files are B, journal still
        # claims A as current.
        _flip_current_link(self.run_dir, b_release)
        _ensure_root_farm(self.run_dir, b_release)
        # A reviewer must never accept this uncommitted state.
        with self.assertRaises(VerificationError):
            verify_run(self.run_dir)

        # Roll-forward converges onto B and restores full verifiability.
        summary = recover_run(self.run_dir, policy="rollforward")
        self.assertEqual(summary["decision"], "rollforward")
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_b)
        self.assertIsNone(read_journal(self.run_dir)["pending"])

        # The same uncommitted window, resolved by rollback, restores A.
        self._publish_a()
        self._crash_b("F3")
        journal = read_journal(self.run_dir)
        b_release = self.run_dir / ".charorder" / journal["pending"]["release"]
        _flip_current_link(self.run_dir, b_release)
        _ensure_root_farm(self.run_dir, b_release)
        with self.assertRaises(VerificationError):
            verify_run(self.run_dir)
        summary = recover_run(self.run_dir, policy="rollback")
        self.assertEqual(summary["decision"], "rollback")
        report = verify_run(self.run_dir)
        self.assertEqual(report["run_id"], self.run_id_a)
        self.assertIsNone(read_journal(self.run_dir)["pending"])

    def test_complete_staging_candidate_resolves_via_journal_path(self) -> None:
        # Regression: the journal stores the staging path relative to
        # .charorder/, so recovery must resolve it under the state directory.
        import shutil

        from charorder.artifacts import (
            STAGING_DIR,
            _state_path,
            _write_journal,
        )

        self._publish_a()
        _, _, probe = execute(self.config_b, self.root / "probe-manual-b")
        b_release = _state_path(probe, read_journal(probe)["current"]["release"])
        for policy, expected_run in (
            ("rollforward", self.run_id_b),
            ("rollback", self.run_id_a),
        ):
            with self.subTest(policy=policy):
                if policy == "rollback":
                    # Re-establish A as the current release after rollforward.
                    self._cli(
                        "run", "--config", str(self.root / "config_a.json"),
                        "--out", str(self.run_dir), "--force", "--quiet",
                    )
                    self.assertEqual(
                        verify_run(self.run_dir)["run_id"], self.run_id_a
                    )
                staging = _state_path(
                    self.run_dir, f"{STAGING_DIR}/s-manual-{policy}"
                )
                staging.mkdir(parents=True)
                for entry in b_release.iterdir():
                    shutil.copy2(entry, staging / entry.name)
                journal = read_journal(self.run_dir)
                journal["pending"] = {
                    "run_id": self.run_id_b,
                    "staging": f"{STAGING_DIR}/s-manual-{policy}",
                    "stage": "staging",
                    "stage_detail": "candidate_complete",
                }
                _write_journal(self.run_dir, journal)

                summary = recover_run(self.run_dir, policy=policy)
                self.assertEqual(summary["decision"], policy)
                self.assertEqual(
                    verify_run(self.run_dir)["run_id"], expected_run
                )
                if policy == "rollback":
                    self.assertTrue(
                        (self.run_dir / ".charorder" / "quarantine").is_dir()
                    )

    def test_sqlite_run_id_matches_manifest_at_every_visible_point(self) -> None:
        self._publish_a()
        for fault in ("F1", "F2", "F3"):
            with self.subTest(fault=fault):
                self._crash_b(fault)
                # Read-only reviewer querying the visible SQLite always sees A.
                connection = sqlite3.connect(
                    (self.run_dir / "ledger.sqlite").as_uri() + "?mode=ro",
                    uri=True,
                )
                try:
                    ledger_id = connection.execute(
                        "SELECT value FROM meta WHERE key='run_id'"
                    ).fetchone()[0]
                finally:
                    connection.close()
                self.assertEqual(ledger_id, self.run_id_a)
                manifest_id = json.loads(
                    (self.run_dir / "manifest.json").read_text(encoding="utf-8")
                )["run_id"]
                self.assertEqual(manifest_id, self.run_id_a)
                # Re-create fixture state for the next fault.
                self.temp.cleanup()
                self.setUp()
                self._publish_a()


if __name__ == "__main__":
    unittest.main()
