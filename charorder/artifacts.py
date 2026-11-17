"""Run orchestration and deterministic artifact writing."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from . import APP_NAME, APP_SLUG, __version__
from .engine import scan
from .errors import OutputError
from .ingest import load_sources
from .ledger import write_ledger
from .models import ScanResult
from .report import render_html, render_markdown, render_plan_markdown

ARTIFACT_FILES = (
    "report.html",
    "report.md",
    "plan.json",
    "plan.md",
    "findings.json",
    "collisions.json",
    "keys.jsonl",
    "composite_rehearsals.json",
    "ledger.sqlite",
    "manifest.json",
)


def execute(
    config: Any,
    output_dir: str | Path | None = None,
    *,
    force: bool = False,
) -> tuple[ScanResult, dict[str, Any], Path]:
    """Load sources, scan, and write all artifacts. No source file is modified."""

    if output_dir is not None:
        target = Path(output_dir)
        _check_output_target(target, force=force)
    loads = load_sources(config)
    result = scan(config, loads)
    if output_dir is None:
        target = Path("charorder-runs") / result.run_id
    _check_output_target(target, force=force)
    manifest = write_artifacts(result, target, force=force)
    return result, manifest, target


def write_artifacts(
    result: ScanResult, output_dir: Path, *, force: bool = False
) -> dict[str, Any]:
    _check_output_target(output_dir, force=force)
    output_dir.mkdir(parents=True, exist_ok=True)

    plan_bytes = _json_bytes(result.plan)
    findings_doc = {
        "schema_version": 1,
        "kind": "charorder.findings",
        "run_id": result.run_id,
        "verdict": result.verdict,
        "counts": result.summary["findings_by_severity"],
        "by_code": result.summary["findings_by_code"],
        "findings": [finding.to_dict() for finding in result.findings],
    }
    collisions_doc = {
        "schema_version": 1,
        "kind": "charorder.collisions",
        "run_id": result.run_id,
        "counts": {
            "groups": len(result.collisions),
            "records": sum(len(group.participants) for group in result.collisions),
        },
        "collisions": [group.to_dict() for group in result.collisions],
    }
    rehearsal_doc = {
        "schema_version": 1,
        "kind": "charorder.composite_key_rehearsals",
        "run_id": result.run_id,
        "counts": {
            "rehearsals": len(result.rehearsals),
            "versioned_cutover_ready": sum(
                1
                for rehearsal in result.rehearsals
                if rehearsal.versioned_contract == "versioned_cutover"
            ),
            "legacy_blocked": sum(
                1
                for rehearsal in result.rehearsals
                if rehearsal.legacy_contract == "legacy_blocked"
            ),
        },
        "rehearsals": [rehearsal.to_dict() for rehearsal in result.rehearsals],
    }

    artifacts: dict[str, bytes] = {
        "plan.json": plan_bytes,
        "plan.md": render_plan_markdown(result).encode("utf-8"),
        "findings.json": _json_bytes(findings_doc),
        "collisions.json": _json_bytes(collisions_doc),
        "composite_rehearsals.json": _json_bytes(rehearsal_doc),
        "keys.jsonl": _jsonl_bytes(item.to_dict() for item in result.key_results),
        "report.md": render_markdown(result).encode("utf-8"),
        "report.html": render_html(result).encode("utf-8"),
    }
    for name, content in artifacts.items():
        _atomic_write_bytes(output_dir / name, content)

    ledger_path = output_dir / "ledger.sqlite"
    write_ledger(result, ledger_path)

    artifact_records: list[dict[str, Any]] = []
    for name in sorted([*artifacts, "ledger.sqlite"]):
        path = output_dir / name
        data = path.read_bytes()
        artifact_records.append(
            {
                "path": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    manifest = {
        "schema_version": 1,
        "kind": "charorder.manifest",
        "app": APP_NAME,
        "slug": APP_SLUG,
        "version": __version__,
        "generated_at": result.generated_at,
        "run_id": result.run_id,
        "project": result.config.project.name,
        "target": result.config.project.target,
        "verdict": result.verdict,
        "config": {
            "path": str(result.config.config_path),
            "sha256": result.config.config_sha256,
        },
        "summary": result.summary,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "source_fingerprints": result.plan["source_fingerprints"],
        "artifacts": artifact_records,
        "ledger": {
            "path": "ledger.sqlite",
            "sha256": next(
                item["sha256"] for item in artifact_records if item["path"] == "ledger.sqlite"
            ),
        },
        "reproduce_command": (
            f'python -m charorder run --config "{result.config.config_path}" '
            f'--out "<NEW_OUTPUT_DIR>" --fail-on high'
        ),
        "read_only_sources": True,
        "network_access": False,
    }
    _atomic_write_bytes(output_dir / "manifest.json", _json_bytes(manifest))
    return manifest


def _check_output_target(path: Path, *, force: bool) -> None:
    try:
        resolved = path.expanduser().resolve()
    except OSError as exc:
        raise OutputError(f"无法解析输出目录：{path}（{exc}）") from exc
    if resolved.exists():
        if not resolved.is_dir():
            raise OutputError(f"输出路径已存在且不是目录：{resolved}")
        try:
            has_entries = any(resolved.iterdir())
        except OSError as exc:
            raise OutputError(f"无法检查输出目录：{resolved}（{exc}）") from exc
        if has_entries and not force:
            raise OutputError(
                f"输出目录非空：{resolved}。请更换目录或显式使用 --force 覆盖已知产物。"
            )
    else:
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OutputError(f"无法创建输出目录：{resolved}（{exc}）") from exc


def _json_bytes(value: Any) -> bytes:
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        default=str,
    )
    # JSON files remain valid UTF-8 even when an input contained a lone surrogate.
    return (text + "\n").encode("utf-8", errors="replace")


def _jsonl_bytes(rows: Any) -> bytes:
    lines = []
    for row in rows:
        line = json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        lines.append(line)
    return ("\n".join(lines) + ("\n" if lines else "")).encode(
        "utf-8", errors="replace"
    )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = -1
    temp_path: str | None = None
    try:
        fd, temp_path = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    except OSError as exc:
        raise OutputError(f"无法写入产物 {path}：{exc}") from exc
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
