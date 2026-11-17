"""Integrity verification for generated run directories."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .errors import VerificationError

_REQUIRED_ARTIFACTS = {
    "report.html",
    "report.md",
    "plan.json",
    "plan.md",
    "findings.json",
    "collisions.json",
    "keys.jsonl",
    "composite_rehearsals.json",
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
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise VerificationError(f"缺少 manifest.json：{manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"manifest.json 不可读或不是有效 JSON：{exc}") from exc
    if not isinstance(manifest, dict):
        raise VerificationError("manifest.json 顶层必须是对象。")

    errors: list[str] = []
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
        path = root / name
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

    plan_path = root / "plan.json"
    if plan_path.is_file():
        plan_bytes = plan_path.read_bytes()
        if manifest.get("plan_sha256") != hashlib.sha256(plan_bytes).hexdigest():
            errors.append("plan.json 与 manifest.plan_sha256 不一致。")
        try:
            plan = json.loads(plan_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            errors.append("plan.json 不是有效 UTF-8 JSON。")
            plan = {}
        else:
            if plan.get("run_id") != manifest.get("run_id"):
                errors.append("plan.json 的 run_id 与 manifest 不一致。")
            gate = plan.get("gate")
            if not isinstance(gate, dict):
                errors.append("plan.json 缺少 gate。")
    else:
        plan = {}

    ledger_summary = _verify_ledger(root, manifest, errors)
    _verify_html(root, errors)

    if errors:
        bullet = "\n".join(f"- {error}" for error in errors)
        raise VerificationError(f"运行完整性校验失败：\n{bullet}")

    return {
        "run_dir": str(root.resolve()),
        "run_id": manifest.get("run_id"),
        "verdict": manifest.get("verdict"),
        "artifacts_verified": len(artifact_records),
        "findings": ledger_summary.get("findings"),
        "key_results": ledger_summary.get("key_results"),
        "collision_groups": ledger_summary.get("collision_groups"),
        "ledger_integrity": ledger_summary.get("integrity_check"),
        "html_self_contained": True,
    }


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
