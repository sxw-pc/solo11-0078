from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from charorder.artifacts import ARTIFACT_FILES, execute
from charorder.cli import main
from charorder.config import load_config
from charorder.errors import OutputError, VerificationError
from charorder.verify import verify_run

from tests.support import DEMO_CONFIG, DEMO_DIR, ci_key, minimal_config, write_config


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ArtifactIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = load_config(DEMO_CONFIG)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_all_artifacts_and_manifest_hashes(self) -> None:
        result, manifest, output = execute(self.config, self.root / "run")
        for name in ARTIFACT_FILES:
            self.assertTrue((output / name).is_file(), name)
        self.assertEqual(manifest["run_id"], result.run_id)
        self.assertEqual(manifest["verdict"], "blocked")
        self.assertTrue(manifest["read_only_sources"])
        self.assertFalse(manifest["network_access"])
        listed = {item["path"]: item for item in manifest["artifacts"]}
        for name, item in listed.items():
            data = (output / name).read_bytes()
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(item["bytes"], len(data))
        self.assertEqual(
            manifest["plan_sha256"],
            hashlib.sha256((output / "plan.json").read_bytes()).hexdigest(),
        )

    def test_verify_run_succeeds_and_detects_tampering(self) -> None:
        _, _, output = execute(self.config, self.root / "run")
        report = verify_run(output)
        self.assertEqual(report["run_id"], json.loads((output / "manifest.json").read_text("utf-8"))["run_id"])
        self.assertEqual(report["ledger_integrity"], "ok")
        self.assertTrue(report["html_self_contained"])

        with (output / "report.html").open("a", encoding="utf-8") as handle:
            handle.write("<!-- tampered -->")
        with self.assertRaisesRegex(VerificationError, "产物哈希不匹配"):
            verify_run(output)

    def test_plan_is_byte_identical_across_runs(self) -> None:
        result1, manifest1, output1 = execute(self.config, self.root / "run-a")
        result2, manifest2, output2 = execute(self.config, self.root / "run-b")
        self.assertEqual(result1.run_id, result2.run_id)
        self.assertEqual(
            (output1 / "plan.json").read_bytes(),
            (output2 / "plan.json").read_bytes(),
        )
        self.assertEqual(manifest1["plan_sha256"], manifest2["plan_sha256"])
        self.assertEqual(
            (output1 / "findings.json").read_bytes(),
            (output2 / "findings.json").read_bytes(),
        )
        self.assertEqual(
            (output1 / "keys.jsonl").read_bytes(),
            (output2 / "keys.jsonl").read_bytes(),
        )

    def test_source_files_are_not_modified(self) -> None:
        before = {
            path.name: _digest(path)
            for path in DEMO_DIR.iterdir()
            if path.is_file()
        }
        execute(self.config, self.root / "run")
        after = {
            path.name: _digest(path)
            for path in DEMO_DIR.iterdir()
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_ledger_tables_counts_and_views(self) -> None:
        result, _, output = execute(self.config, self.root / "run")
        connection = sqlite3.connect((output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(
                {
                    "meta",
                    "runs",
                    "sources",
                    "rules",
                    "records",
                    "key_results",
                    "findings",
                    "collisions",
                    "collision_members",
                }.issubset(tables)
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0], result.summary["findings_total"])
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM key_results").fetchone()[0],
                result.summary["keys_evaluated"],
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM collision_members").fetchone()[0],
                result.summary["collision_records"],
            )
            run = connection.execute("SELECT * FROM runs").fetchone()
            self.assertEqual(run["verdict"], result.verdict)
            self.assertEqual(run["run_id"], result.run_id)
            counts = connection.execute(
                "SELECT * FROM finding_counts ORDER BY finding_count DESC LIMIT 1"
            ).fetchone()
            self.assertGreater(counts["finding_count"], 0)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            connection.close()

    def test_output_conflict_and_force(self) -> None:
        output = self.root / "run"
        execute(self.config, output)
        with self.assertRaisesRegex(OutputError, "输出目录非空"):
            execute(self.config, output)
        _, manifest, _ = execute(self.config, output, force=True)
        self.assertEqual(manifest["verdict"], "blocked")

    def test_self_contained_html_and_escaping(self) -> None:
        csv_path = self.root / "inject.csv"
        payload = '<script>alert("x")</script>'
        csv_path.write_text(
            'id,email\n1,"' + payload + '"\n2,"' + payload + '"\n',
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "csv",
                "path": "inject.csv",
                "record_id_field": "id",
            },
            keys=[ci_key(key_id="email", source_id="s1", columns=["email"])],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        _, _, output = execute(config, self.root / "inject-run")
        report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;alert", report)
        self.assertNotIn('<script>alert("x")</script>', report)
        self.assertNotRegex(report, re.compile(r'<script\b[^>]*\bsrc\s*=', re.IGNORECASE))
        self.assertNotRegex(report, re.compile(r'<link\b[^>]*\bhref\s*=', re.IGNORECASE))
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)
        verify_run(output)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_run_default_exit_zero_and_fail_on_high_exit_one(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(
                [
                    "run",
                    "--config",
                    str(DEMO_CONFIG),
                    "--out",
                    str(self.root / "run-default"),
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("字序迁核台", out.getvalue())
        self.assertIn("风险：高", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(
                [
                    "run",
                    "--config",
                    str(DEMO_CONFIG),
                    "--out",
                    str(self.root / "run-gated"),
                    "--fail-on",
                    "high",
                ]
            )
        self.assertEqual(code, 1)

    def test_verify_command(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            main(
                [
                    "run",
                    "--config",
                    str(DEMO_CONFIG),
                    "--out",
                    str(self.root / "run"),
                ]
            )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["verify", "--run", str(self.root / "run")])
        self.assertEqual(code, 0)
        self.assertIn("完整性校验通过", output.getvalue())

    def test_demo_command(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["demo", "--out", str(self.root / "demo")])
        self.assertEqual(code, 0)
        self.assertIn("内置合成样例", out.getvalue())
        self.assertTrue((self.root / "demo" / "manifest.json").is_file())

    def test_config_error_returns_two(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(
                [
                    "run",
                    "--config",
                    str(self.root / "missing.json"),
                    "--out",
                    str(self.root / "out"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("配置文件不存在", err.getvalue())


if __name__ == "__main__":
    unittest.main()
