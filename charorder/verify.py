"""Integrity verification for generated run directories.

Verification always covers one *complete* release: every artifact is checked
against the manifest, the run_id and source fingerprints are cross-checked
across manifest, plan, findings, collisions, key results and the SQLite
ledger, and batch-published directories are additionally checked against the
durable publish journal so an old manifest can never be paired with new files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from .errors import VerificationError
from .ledger import read_ledger_run_id

_REQUIRED_ARTIFACTS = {
    "report.html",
    "report.md",
    "plan.json",
    "plan.md",
    "findings.json",
    "collisions.json",
    "keys.jsonl",
    "ledger.sqlite",
}
_EXTERNAL_ASSET_PATTERNS = (
    re.compile(r"<script\b[^>]*\bsrc\s*=", re.IGNORECASE),
    re.compile(r"<link\b[^>]*\bhref\s*=", re.IGNORECASE),
    re.compile(r"<img\b[^>]*\bsrc\s*=", re.IGNORECASE),
    re.compile(r"@import\b", re.IGNORECASE),
    re.compile(r"url\(\s*['\"]?https?://", re.IGNORECASE),
)


def verify_run(run_dir: str | Path) -> dict[str, Any]:
    try:
        root = Path(run_dir).expanduser().resolve()
    except OSError as exc:
        raise VerificationError(f"无法解析运行目录：{run_dir}（{exc}）") from exc
    if not root.exists():
        raise VerificationError(f"运行目录不存在：{root}")
    if not root.is_dir():
        raise VerificationError(f"运行路径不是目录：{root}")

    # Batch layouts expose the current release through the journal + symlink
    # indirection; legacy flat directories verify in place.
    journal_info = _journal_status(root)
    effective = _effective_release_dir(root)
    manifest_path = effective / "manifest.json"
    if not manifest_path.is_file():
        raise VerificationError(f"缺少 manifest.json：{manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"manifest.json 不可读或不是有效 JSON：{exc}") from exc
    if not isinstance(manifest, dict):
        raise VerificationError("manifest.json 顶层必须是对象。")

    errors: list[str] = []
    warnings: list[str] = []
    if manifest.get("kind") != "charorder.manifest" or manifest.get("schema_version") != 1:
        errors.append("manifest 类型或 schema_version 不正确。")
    if not manifest.get("run_id"):
        errors.append("manifest 缺少 run_id。")
    if manifest.get("read_only_sources") is not True:
        errors.append("manifest 未声明只读源文件。")
    if manifest.get("network_access") is not False:
        errors.append("manifest 未声明无网络访问。")

    artifact_records = manifest.get("artifacts")
    if not isinstance(artifact_records, list):
        errors.append("manifest.artifacts 必须是数组。")
        artifact_records = []
    listed = set()
    for record in artifact_records:
        if not isinstance(record, dict):
            errors.append("manifest.artifacts 含非对象条目。")
            continue
        name = record.get("path")
        if not isinstance(name, str) or not name:
            errors.append("artifact 缺少 path。")
            continue
        if Path(name).name != name:
            errors.append(f"artifact 路径必须是当前目录内的文件名：{name}")
            continue
        listed.add(name)
        path = effective / name
        if not path.is_file():
            errors.append(f"缺少产物：{name}")
            continue
        data = path.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        if record.get("sha256") != actual_hash:
            errors.append(f"产物哈希不匹配：{name}")
        if record.get("bytes") != len(data):
            errors.append(f"产物大小不匹配：{name}")
    missing = _REQUIRED_ARTIFACTS - listed
    if missing:
        errors.append(f"manifest 未登记必需产物：{', '.join(sorted(missing))}")

    plan = _verify_plan(effective, manifest, errors)
    _verify_named_docs(effective, manifest, errors)
    _verify_keys_jsonl(effective, manifest, errors)
    if isinstance(plan, dict):
        _verify_source_fingerprints(plan, manifest, errors)
    ledger_summary = _verify_ledger(effective, manifest, errors)
    _verify_html(effective, errors)
    if journal_info is not None:
        _verify_journal_consistency(root, effective, manifest, journal_info, errors, warnings)

    if errors:
        bullet = "\n".join(f"- {error}" for error in errors)
        raise VerificationError(f"运行完整性校验失败：\n{bullet}")

    return {
        "run_dir": str(effective.resolve()),
        "presented_run_dir": str(root.resolve()),
        "run_id": manifest.get("run_id"),
        "verdict": manifest.get("verdict"),
        "artifacts_verified": len(artifact_records),
        "findings": ledger_summary.get("findings"),
        "key_results": ledger_summary.get("key_results"),
        "collision_groups": ledger_summary.get("collision_groups"),
        "ledger_integrity": ledger_summary.get("integrity_check"),
        "html_self_contained": True,
        "layout": journal_info.get("layout") if journal_info else "legacy_flat",
        "pending_publish": journal_info.get("pending") if journal_info else None,
        "warnings": warnings,
    }


def _effective_release_dir(root: Path) -> Path:
    link = root / ".charorder" / "current"
    if link.is_symlink():
        try:
            target = os.readlink(link)
        except OSError:
            return root
        resolved = (link.parent / target).resolve()
        if resolved.is_dir():
            return resolved
    return root


def _journal_status(root: Path) -> dict[str, Any] | None:
    from .artifacts import read_journal

    journal = read_journal(root)
    if journal is None:
        return None
    status: dict[str, Any] = {"layout": "batch", "journal": journal, "pending": None}
    pending = journal.get("pending")
    if isinstance(pending, dict) and pending.get("run_id"):
        status["pending"] = {
            "run_id": pending.get("run_id"),
            "stage": pending.get("stage"),
        }
    return status


def _verify_plan(
    root: Path, manifest: dict[str, Any], errors: list[str]
) -> dict[str, Any] | None:
    plan_path = root / "plan.json"
    if not plan_path.is_file():
        errors.append("缺少产物：plan.json")
        return None
    plan_bytes = plan_path.read_bytes()
    if manifest.get("plan_sha256") != hashlib.sha256(plan_bytes).hexdigest():
        errors.append("plan.json 与 manifest.plan_sha256 不一致。")
    try:
        plan = json.loads(plan_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        errors.append("plan.json 不是有效 UTF-8 JSON。")
        return None
    if plan.get("run_id") != manifest.get("run_id"):
        errors.append("plan.json 的 run_id 与 manifest 不一致。")
    gate = plan.get("gate")
    if not isinstance(gate, dict):
        errors.append("plan.json 缺少 gate。")
    return plan


def _verify_named_docs(
    root: Path, manifest: dict[str, Any], errors: list[str]
) -> None:
    expected_run_id = manifest.get("run_id")
    for name, kind in (("findings.json", "charorder.findings"),
                       ("collisions.json", "charorder.collisions")):
        path = root / name
        if not path.is_file():
            errors.append(f"缺少产物：{name}")
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            errors.append(f"{name} 不是有效 UTF-8 JSON。")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{name} 顶层必须是对象。")
            continue
        if doc.get("kind") != kind:
            errors.append(f"{name} 的 kind 不正确。")
        if doc.get("run_id") != expected_run_id:
            errors.append(f"{name} 的 run_id 与 manifest 不一致。")


def _verify_keys_jsonl(
    root: Path, manifest: dict[str, Any], errors: list[str]
) -> None:
    path = root / "keys.jsonl"
    if not path.is_file():
        errors.append("缺少产物：keys.jsonl")
        return
    expected = manifest.get("summary", {}).get("keys_evaluated")
    rows = 0
    bad_lines = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows += 1
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            bad_lines += 1
            continue
        if not isinstance(item, dict) or not item.get("key_result_id"):
            bad_lines += 1
    if bad_lines:
        errors.append("keys.jsonl 含无法解析或缺少 key_result_id 的行。")
    if expected is not None and rows != expected:
        errors.append(
            f"keys.jsonl 键结果数与 manifest 不一致：{rows} != {expected}"
        )


def _verify_source_fingerprints(
    plan: dict[str, Any], manifest: dict[str, Any], errors: list[str]
) -> None:
    plan_fingerprints = plan.get("source_fingerprints")
    manifest_fingerprints = manifest.get("source_fingerprints")
    if not isinstance(plan_fingerprints, list):
        errors.append("plan.json 缺少 source_fingerprints。")
        return
    if plan_fingerprints != manifest_fingerprints:
        errors.append("manifest 与 plan.json 的来源摘要（source_fingerprints）不一致。")


def _verify_journal_consistency(
    root: Path,
    effective: Path,
    manifest: dict[str, Any],
    journal_info: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    journal = journal_info["journal"]
    current = journal.get("current")
    if not isinstance(current, dict):
        errors.append("发布日志未登记当前发布版本。")
        return
    current_release = (root / ".charorder" / str(current.get("release"))).resolve()
    if current_release != effective.resolve():
        errors.append(
            "当前可见产物与发布日志登记版本不一致，可能存在中断的整批发布；"
            "请先运行 charorder recover 完成恢复。"
        )
        return
    if current.get("run_id") != manifest.get("run_id"):
        errors.append("发布日志登记的 run_id 与 manifest 不一致。")
    recorded_hash = current.get("manifest_sha256")
    actual_hash = hashlib.sha256(
        (effective / "manifest.json").read_bytes()
    ).hexdigest()
    if recorded_hash != actual_hash:
        errors.append("发布日志登记的 manifest 哈希与当前 manifest 不一致。")

    # The root farm must present one release only: every link must point at
    # the same release tree as .charorder/current.
    for name in _REQUIRED_ARTIFACTS | {"manifest.json"}:
        link = root / name
        if not link.is_symlink():
            errors.append(f"产物 {name} 未通过整批发布链接呈现。")
            continue
        try:
            target = os.readlink(link)
        except OSError:
            errors.append(f"产物 {name} 的发布链接不可读。")
            continue
        wanted = os.path.relpath(effective / name, root)
        if target != wanted:
            errors.append(f"产物 {name} 的发布链接未指向当前版本（疑似新旧拼接）。")

    pending = journal_info.get("pending")
    if pending is not None:
        warnings.append(
            f"存在未完成的整批发布（run_id={pending['run_id']}，"
            f"阶段={pending['stage']}）；当前 verify 结果仍指向已发布版本，"
            "请运行 charorder recover 处理。"
        )


def _verify_ledger(
    root: Path, manifest: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    path = root / "ledger.sqlite"
    if not path.is_file():
        errors.append("缺少台账 ledger.sqlite。")
        return {}
    summary = manifest.get("summary") or {}
    try:
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    except sqlite3.Error as exc:
        errors.append(f"台账无法以只读方式打开：{exc}")
        return {}
    try:
        connection.execute("PRAGMA query_only = ON")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != 1:
            errors.append(f"台账 user_version 应为 1，实际为 {version}。")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            errors.append(f"SQLite integrity_check 未通过：{integrity}")

        run = connection.execute(
            "SELECT run_id, verdict, record_count, key_result_count, finding_count, collision_count "
            "FROM runs LIMIT 1"
        ).fetchone()
        if run is None:
            errors.append("台账 runs 表为空。")
            counts: dict[str, int] = {}
        else:
            if run[0] != manifest.get("run_id"):
                errors.append("台账 run_id 与 manifest 不一致。")
            if run[1] != manifest.get("verdict"):
                errors.append("台账 verdict 与 manifest 不一致。")
            counts = {
                "records": int(run[2]),
                "key_results": int(run[3]),
                "findings": int(run[4]),
                "collision_groups": int(run[5]),
            }
            expectations = {
                "records": summary.get("record_count"),
                "key_results": summary.get("keys_evaluated"),
                "findings": summary.get("findings_total"),
                "collision_groups": summary.get("collision_groups"),
            }
            for key, expected in expectations.items():
                if counts.get(key) != expected:
                    errors.append(
                        f"台账 {key} 计数与 manifest 不一致：{counts.get(key)} != {expected}"
                    )

        actual_findings = connection.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        actual_keys = connection.execute(
            "SELECT COUNT(*) FROM key_results"
        ).fetchone()[0]
        actual_collisions = connection.execute(
            "SELECT COUNT(*) FROM collisions"
        ).fetchone()[0]
        actual_members = connection.execute(
            "SELECT COUNT(*) FROM collision_members"
        ).fetchone()[0]
        if actual_findings != summary.get("findings_total"):
            errors.append("台账 findings 行数与 manifest 不一致。")
        if actual_keys != summary.get("keys_evaluated"):
            errors.append("台账 key_results 行数与 manifest 不一致。")
        if actual_collisions != summary.get("collision_groups"):
            errors.append("台账 collisions 行数与 manifest 不一致。")
        if actual_members != summary.get("collision_records"):
            errors.append("台账 collision_members 行数与 manifest 不一致。")
        distinct_runs = connection.execute("SELECT COUNT(DISTINCT run_id) FROM runs").fetchone()[0]
        if distinct_runs and distinct_runs != 1:
            errors.append("台账混入了多个 run_id 的记录，不是单一发布版本。")
        ledger_run_id = read_ledger_run_id(path)
        if ledger_run_id is not None and ledger_run_id != manifest.get("run_id"):
            errors.append("台账 meta.run_id 与 manifest 不一致。")
        return {
            "integrity_check": integrity,
            "findings": actual_findings,
            "key_results": actual_keys,
            "collision_groups": actual_collisions,
        }
    except sqlite3.Error as exc:
        errors.append(f"台账校验查询失败：{exc}")
        return {}
    finally:
        connection.close()


def _verify_html(root: Path, errors: list[str]) -> None:
    path = root / "report.html"
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"report.html 无法按 UTF-8 读取：{exc}")
        return
    if '<meta charset="utf-8">' not in text.lower():
        errors.append("report.html 未声明 UTF-8 charset。")
    for pattern in _EXTERNAL_ASSET_PATTERNS:
        if pattern.search(text):
            errors.append(
                f"report.html 含外部资源引用（{pattern.pattern}），不是自包含页面。"
            )
    if "只读" not in text and "READ-ONLY" not in text.upper():
        errors.append("report.html 未标明只读复核属性。")
