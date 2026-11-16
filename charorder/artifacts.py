"""Run orchestration and deterministic, all-or-nothing artifact publishing.

A run directory never exposes a half-written revision. Every new set of
artifacts is built in an isolated staging directory under ``.charorder/``,
verified as a complete set, and only then published in a single atomic
symlink flip. A durable journal plus an append-only event log make every
publish and recovery decision auditable.

On-disk layout (batch-published runs)::

    <run_dir>/
        report.html, report.md, plan.json, ..., manifest.json
            # immutable farm of symlinks, all pointing at the current release
        .charorder/
            journal.json          # durable publish state machine
            events.log            # append-only audit trail (JSON Lines)
            publish.lock          # flock serialising concurrent publishes
            current               # symlink -> ../releases/<run_id>
            releases/<run_id>/    # complete, verified, immutable releases
            staging/<s-id>/       # isolated, unpublished work in progress
            quarantine/<name>/    # aborted/unpublished evidence kept for review

Legacy flat directories (files written directly into the run root) are still
accepted read-only by the verification entry point and are adopted into the
batch layout on the first forced rewrite.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import APP_NAME, APP_SLUG, __version__
from .engine import now_iso, scan
from .errors import OutputError, VerificationError
from .ingest import load_sources
from .ledger import write_ledger
from .models import ScanResult
from .report import render_html, render_markdown, render_plan_markdown
from .verify import verify_run

ARTIFACT_FILES = (
    "report.html",
    "report.md",
    "plan.json",
    "plan.md",
    "findings.json",
    "collisions.json",
    "keys.jsonl",
    "ledger.sqlite",
    "manifest.json",
)

STATE_DIR = ".charorder"
JOURNAL_NAME = "journal.json"
EVENT_LOG_NAME = "events.log"
LOCK_NAME = "publish.lock"
CURRENT_LINK = "current"
RELEASES_DIR = "releases"
STAGING_DIR = "staging"
QUARANTINE_DIR = "quarantine"

JOURNAL_KIND = "charorder.publish_journal"
JOURNAL_SCHEMA = 1

# Test-only fault injection. Each point raises *after* the named durable step,
# simulating a hard crash at one of the three reviewed cut points:
#   F1: some JSON/Markdown artifacts staged, nothing published
#   F2: all regular artifacts staged, SQLite ledger not yet replaced
#   F3: full B set staged and verified, new manifest not yet published
_FAULT_ENV = "CHARORDER_FAULT_POINT"
_POLICY_ENV = "CHARORDER_RECOVERY_POLICY"
_ROLLFORWARD = "rollforward"
_ROLLBACK = "rollback"
_RECOVERY_POLICIES = (_ROLLFORWARD, _ROLLBACK)

# Reentrancy tokens for publish locks held by the current process.
_LOCK_HOLDERS: dict[Path, list[int]] = {}


class PublishFault(OutputError):
    """Raised by test-only fault injection to simulate a process crash."""


def execute(
    config: Any,
    output_dir: str | Path | None = None,
    *,
    force: bool = False,
    recovery_policy: str | None = None,
) -> tuple[ScanResult, dict[str, Any], Path]:
    """Load sources, scan, and publish all artifacts. No source file is modified."""

    if output_dir is not None:
        target = Path(output_dir)
        _check_output_target(target, force=force)
    loads = load_sources(config)
    result = scan(config, loads)
    if output_dir is None:
        target = Path("charorder-runs") / result.run_id
    _check_output_target(target, force=force)
    manifest = write_artifacts(result, target, force=force, recovery_policy=recovery_policy)
    return result, manifest, target


def write_artifacts(
    result: ScanResult,
    output_dir: Path,
    *,
    force: bool = False,
    recovery_policy: str | None = None,
) -> dict[str, Any]:
    """Build the full artifact set in isolation and publish it atomically."""

    _check_output_target(output_dir, force=force)
    output_dir.mkdir(parents=True, exist_ok=True)
    policy = _resolve_policy(recovery_policy)

    with _publish_lock(output_dir):
        # Finish or roll back any interrupted transaction before starting a new
        # one. Readers keep seeing the previous release throughout.
        recover_run(output_dir, policy=policy)

        journal = _read_journal(output_dir)
        current = journal.get("current")
        if (
            isinstance(current, dict)
            and current.get("run_id") == result.run_id
            and _current_release_verifies(output_dir, current)
        ):
            # Same inputs, same run_id: the verified release stays the current
            # revision byte-for-byte; no mixed or duplicate version is created.
            release_dir = _state_path(output_dir, current["release"])
            _ensure_root_farm(output_dir, release_dir)
            manifest = _load_manifest(release_dir)
            _append_event(
                output_dir,
                "reuse_current",
                result.run_id,
                {"reason": "identical_run_id", "release": current["release"]},
            )
            return manifest

        staging_dir = _prepare_staging(output_dir, result)
        try:
            manifest = _stage_all_artifacts(result, staging_dir)
            # The whole candidate set must verify before it may be published.
            verify_run(staging_dir)
            _publish_staging(output_dir, staging_dir, result, manifest)
        except BaseException:
            # On any failure the staging tree stays isolated (or is moved to
            # quarantine by the next recovery); the current release is untouched.
            _append_event(
                output_dir,
                "publish_failed",
                result.run_id,
                {"staging": str(staging_dir.relative_to(_state_dir(output_dir)))},
            )
            raise
        return manifest


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


def recover_run(run_dir: str | Path, *, policy: str | None = None) -> dict[str, Any]:
    """Resolve an interrupted publish transaction and adopt legacy layouts.

    Returns a summary of the decision. All decisions are persisted both in the
    journal state machine and the append-only event log.
    """

    root = Path(run_dir).expanduser().resolve()
    chosen_policy = _resolve_policy(policy)
    root.mkdir(parents=True, exist_ok=True)

    # Legacy flat runs are adopted before the batch state directory (and its
    # lock file) are created, so the two layouts can never be mixed.
    if not _state_dir(root).exists():
        legacy = _adopt_legacy_layout(root)
        if legacy is not None:
            return legacy

    with _publish_lock(root):
        state = _state_dir(root)
        state.mkdir(parents=True, exist_ok=True)
        journal = _read_journal(root)
        pending = journal.get("pending")
        if not pending:
            _ensure_journal(root, journal)
            return {
                "decision": "no_pending_work",
                "policy": chosen_policy,
                "current_run_id": (journal.get("current") or {}).get("run_id"),
            }

        run_id = str(pending.get("run_id") or "")
        stage = pending.get("stage")
        staging_rel = pending.get("staging")
        staging_dir = _state_path(root, staging_rel) if isinstance(staging_rel, str) else None
        release_rel = pending.get("release")
        if isinstance(release_rel, str):
            release_dir = _state_path(root, release_rel)
        elif run_id:
            release_dir = _release_dir(root, run_id)
        else:
            release_dir = None

        return _reconcile_pending(
            root,
            journal,
            pending=pending,
            stage=stage,
            staging_dir=staging_dir,
            release_dir=release_dir,
            run_id=run_id,
            policy=chosen_policy,
        )


def _reconcile_pending(
    root: Path,
    journal: dict[str, Any],
    *,
    pending: dict[str, Any],
    stage: Any,
    staging_dir: Path | None,
    release_dir: Path | None,
    run_id: str,
    policy: str,
) -> dict[str, Any]:
    # Cut points 1 and 2: the candidate set was never completed. It can never
    # be promoted; reviewers keep seeing the previous verified release.
    candidate: Path | None = None
    if stage == "publishing" and release_dir is not None and release_dir.is_dir():
        candidate = release_dir
    elif staging_dir is not None and staging_dir.is_dir():
        candidate = staging_dir

    candidate_ok = bool(candidate and _release_verifies(candidate))

    if stage == "staging" and not candidate_ok:
        return _abort_pending(
            root,
            journal,
            pending,
            candidate,
            run_id,
            reason="staging_incomplete",
            policy=policy,
        )

    if not candidate_ok:
        return _abort_pending(
            root,
            journal,
            pending,
            candidate,
            run_id,
            reason="candidate_verification_failed",
            policy=policy,
        )

    assert candidate is not None
    if policy == _ROLLFORWARD:
        # Cut point 3, option 1: re-verify the complete B set and promote it.
        return _roll_forward(root, journal, pending, candidate, run_id)

    # Cut point 3, option 2: keep A current and quarantine unpublished B.
    return _roll_back(root, journal, pending, candidate, run_id)


def _roll_forward(
    root: Path,
    journal: dict[str, Any],
    pending: dict[str, Any],
    candidate: Path,
    run_id: str,
) -> dict[str, Any]:
    if candidate.parent.name != RELEASES_DIR:
        release_dir = _release_dir(root, run_id)
        if release_dir.exists():
            # A release with this run_id already exists (e.g. a prior partial
            # roll-forward). Trust it only if it verifies; otherwise quarantine.
            if _release_verifies(release_dir):
                _quarantine(root, candidate, run_id)
            else:
                _quarantine(root, release_dir, run_id)
                _replace_tree(candidate, release_dir)
        else:
            _replace_tree(candidate, release_dir)
    else:
        release_dir = candidate
    verify_run(release_dir)
    manifest = _load_manifest(release_dir)
    current = {
        "release": str(release_dir.relative_to(_state_dir(root))),
        "run_id": run_id,
        "manifest_sha256": hashlib.sha256(
            (release_dir / "manifest.json").read_bytes()
        ).hexdigest(),
        "published_at": now_iso(),
    }
    # Flip the visible pointer first and make it durable; only then clear the
    # pending transaction in the journal. A crash in between simply repeats the
    # same roll-forward on the next restart.
    _flip_current_link(root, release_dir)
    _ensure_root_farm(root, release_dir)
    journal["current"] = current
    journal["pending"] = None
    _write_journal(root, journal)
    _append_event(
        root,
        "recovered",
        run_id,
        {
            "decision": _ROLLFORWARD,
            "previous_stage": pending.get("stage"),
            "release": current["release"],
            "verdict": manifest.get("verdict"),
        },
    )
    return {
        "decision": _ROLLFORWARD,
        "run_id": run_id,
        "current_run_id": run_id,
        "release": current["release"],
    }


def _roll_back(
    root: Path,
    journal: dict[str, Any],
    pending: dict[str, Any],
    candidate: Path,
    run_id: str,
) -> dict[str, Any]:
    quarantine = _quarantine(root, candidate, run_id)
    current = journal.get("current")
    current_run_id = current.get("run_id") if isinstance(current, dict) else None
    if isinstance(current, dict):
        release_dir = _state_path(root, current["release"])
        verify_run(release_dir)
        _flip_current_link(root, release_dir)
        _ensure_root_farm(root, release_dir)
    journal["pending"] = None
    _write_journal(root, journal)
    _append_event(
        root,
        "recovered",
        run_id,
        {
            "decision": _ROLLBACK,
            "previous_stage": pending.get("stage"),
            "quarantined": str(quarantine.relative_to(_state_dir(root))),
            "current_run_id": current_run_id,
        },
    )
    return {
        "decision": _ROLLBACK,
        "run_id": run_id,
        "current_run_id": current_run_id,
        "quarantined": str(quarantine),
    }


def _abort_pending(
    root: Path,
    journal: dict[str, Any],
    pending: dict[str, Any],
    candidate: Path | None,
    run_id: str,
    *,
    reason: str,
    policy: str,
) -> dict[str, Any]:
    quarantined: str | None = None
    if candidate is not None and candidate.exists():
        quarantined = str(
            _quarantine(root, candidate, run_id).relative_to(_state_dir(root))
        )
    current = journal.get("current")
    current_run_id = current.get("run_id") if isinstance(current, dict) else None
    if isinstance(current, dict):
        release_dir = _state_path(root, current["release"])
        verify_run(release_dir)
        _ensure_root_farm(root, release_dir)
    journal["pending"] = None
    _write_journal(root, journal)
    _append_event(
        root,
        "recovered",
        run_id,
        {
            "decision": "abort_incomplete",
            "reason": reason,
            "policy": policy,
            "quarantined": quarantined,
            "current_run_id": current_run_id,
        },
    )
    return {
        "decision": "abort_incomplete",
        "reason": reason,
        "run_id": run_id,
        "current_run_id": current_run_id,
        "quarantined": quarantined,
    }


def _adopt_legacy_layout(root: Path) -> dict[str, Any] | None:
    """Move a verified legacy flat run into the batch layout.

    Returns a recovery summary when adoption happened (or nothing to adopt was
    found); ``None`` means the directory already uses the batch layout.
    """

    state = _state_dir(root)
    if state.exists():
        return None
    legacy_manifest = root / "manifest.json"
    if not legacy_manifest.is_file():
        state.mkdir(parents=True, exist_ok=True)
        _write_journal(root, _empty_journal(root))
        return {"decision": "initialised", "policy": _resolve_policy(None), "current_run_id": None}

    # Only a fully verifiable flat run may become the current release.
    verify_run(root)
    manifest = _load_manifest(root)
    run_id = str(manifest["run_id"])
    release_dir = _release_dir(root, run_id)
    release_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_tmp = _state_path(root, f"{STAGING_DIR}/legacy-{uuid.uuid4().hex}")
    staging_tmp.mkdir(parents=True, exist_ok=False)
    for name in ARTIFACT_FILES:
        legacy = root / name
        if legacy.exists() and not legacy.is_symlink():
            os.replace(legacy, staging_tmp / name)
    verify_run(staging_tmp)
    os.replace(staging_tmp, release_dir)
    current = {
        "release": str(release_dir.relative_to(state)),
        "run_id": run_id,
        "manifest_sha256": hashlib.sha256(
            (release_dir / "manifest.json").read_bytes()
        ).hexdigest(),
        "published_at": now_iso(),
    }
    journal = _empty_journal(root)
    journal["current"] = current
    _write_journal(root, journal)
    _flip_current_link(root, release_dir)
    _ensure_root_farm(root, release_dir)
    _append_event(
        root,
        "adopted_legacy_layout",
        run_id,
        {"release": current["release"]},
    )
    return {
        "decision": "adopted_legacy_layout",
        "policy": _resolve_policy(None),
        "current_run_id": run_id,
        "release": current["release"],
    }


# ---------------------------------------------------------------------------
# Staging and publishing
# ---------------------------------------------------------------------------


def _prepare_staging(root: Path, result: ScanResult) -> Path:
    # Any staging tree left on disk by a crashed process is evidence. Recover
    # it before registering a new pending transaction so it cannot be overwritten.
    staging_root = _state_path(root, STAGING_DIR)
    if staging_root.is_dir():
        for leftover in staging_root.iterdir():
            if leftover.is_dir() and not leftover.name.startswith("."):
                quarantine_dir = _quarantine(root, leftover, f"staging-{result.run_id}")
                _append_event(
                    root,
                    "recovered",
                    result.run_id,
                    {
                        "decision": "abort_incomplete",
                        "reason": "orphan_staging_directory",
                        "quarantined": str(
                            quarantine_dir.relative_to(_state_dir(root))
                        ),
                        "current_run_id": (
                            (read_journal(root) or {}).get("current", {}) or {}
                        ).get("run_id"),
                    },
                )
    staging_dir = _state_path(root, f"{STAGING_DIR}/s-{uuid.uuid4().hex}")
    staging_dir.mkdir(parents=True, exist_ok=False)
    journal = _read_journal(root)
    journal["pending"] = {
        "run_id": result.run_id,
        "staging": str(staging_dir.relative_to(_state_dir(root))),
        "stage": "staging",
        "stage_detail": "staging_created",
        "manifest_sha256": None,
        "created_at": now_iso(),
        "config_sha256": result.config.config_sha256,
        "verdict": result.verdict,
        "source_fingerprints": result.plan["source_fingerprints"],
    }
    _write_journal(root, journal)
    _append_event(
        root,
        "staging_started",
        result.run_id,
        {"staging": journal["pending"]["staging"]},
    )
    return staging_dir


def _stage_all_artifacts(
    result: ScanResult, staging_dir: Path
) -> dict[str, Any]:
    root = _run_root_from_state(staging_dir)
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

    artifacts: dict[str, bytes] = {
        "plan.json": plan_bytes,
        "plan.md": render_plan_markdown(result).encode("utf-8"),
        "findings.json": _json_bytes(findings_doc),
        "collisions.json": _json_bytes(collisions_doc),
        "keys.jsonl": _jsonl_bytes(item.to_dict() for item in result.key_results),
        "report.md": render_markdown(result).encode("utf-8"),
        "report.html": render_html(result).encode("utf-8"),
    }
    for index, (name, content) in enumerate(artifacts.items()):
        _atomic_write_bytes(staging_dir / name, content)
        if index == 0:
            # Cut point 1: part of the JSON/Markdown set exists in isolation.
            _maybe_fault("F1")

    # Cut point 2: every regular artifact is staged but the SQLite ledger has
    # not been replaced yet.
    _maybe_fault("F2")
    write_ledger(result, staging_dir / "ledger.sqlite")

    artifact_records: list[dict[str, Any]] = []
    for name in sorted([*artifacts, "ledger.sqlite"]):
        data = (staging_dir / name).read_bytes()
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
    _atomic_write_bytes(staging_dir / "manifest.json", _json_bytes(manifest))

    journal = _read_journal(root)
    pending = journal.get("pending")
    if isinstance(pending, dict):
        pending["stage"] = "staging"
        pending["stage_detail"] = "candidate_complete"
        pending["manifest_sha256"] = hashlib.sha256(
            (staging_dir / "manifest.json").read_bytes()
        ).hexdigest()
        _write_journal(root, journal)
    _append_event(
        root,
        "staging_completed",
        result.run_id,
        {"staging": str(staging_dir.relative_to(_state_dir(root)))},
    )
    return manifest


def _publish_staging(
    root: Path,
    staging_dir: Path,
    result: ScanResult,
    manifest: dict[str, Any],
) -> None:
    journal = _read_journal(root)
    pending = journal.get("pending")
    if not isinstance(pending, dict) or pending.get("run_id") != result.run_id:
        raise OutputError("发布状态与暂存产物不一致，已中止整批发布。")
    release_dir = _release_dir(root, result.run_id)
    pending["stage"] = "publishing"
    pending["stage_detail"] = "parking_candidate"
    _write_journal(root, journal)
    _append_event(root, "publish_started", result.run_id, {"stage": "publishing"})

    if release_dir.exists():
        # A previous release with this run_id was superseded; keep its evidence
        # in quarantine instead of deleting it.
        _quarantine(root, release_dir, result.run_id)
    release_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging_dir, release_dir)
    _fsync_dir(release_dir.parent)

    # The candidate is now durably parked; record its exact location so a
    # restart can roll it forward or back without rescanning.
    pending["release"] = str(release_dir.relative_to(_state_dir(root)))
    pending["stage_detail"] = "awaiting_current_flip"
    _write_journal(root, journal)

    # Cut point 3: the complete, verified B set exists as a release candidate
    # and the journal durably records "publishing", but the current symlink
    # (and therefore the new manifest) has not been published yet.
    _maybe_fault("F3")

    current = {
        "release": str(release_dir.relative_to(_state_dir(root))),
        "run_id": result.run_id,
        "manifest_sha256": hashlib.sha256(
            (release_dir / "manifest.json").read_bytes()
        ).hexdigest(),
        "published_at": now_iso(),
    }
    # The symlink flip is the single commit point: make it durable before the
    # journal clears the pending transaction. A crash here is recoverable by
    # repeating the same flip (idempotent) on the next run.
    _flip_current_link(root, release_dir)
    _ensure_root_farm(root, release_dir)

    journal["current"] = current
    journal["pending"] = None
    _write_journal(root, journal)
    _append_event(
        root,
        "published",
        result.run_id,
        {
            "release": current["release"],
            "verdict": manifest.get("verdict"),
            "manifest_sha256": current["manifest_sha256"],
        },
    )


# ---------------------------------------------------------------------------
# Read-side helpers
# ---------------------------------------------------------------------------


def uses_batch_layout(run_dir: str | Path) -> bool:
    root = Path(run_dir).expanduser().resolve()
    return (_state_dir(root) / JOURNAL_NAME).is_file()


def resolve_current_run_dir(run_dir: str | Path) -> Path:
    """Resolve the directory that actually holds the current published files.

    Batch layouts redirect through ``.charorder/current``; legacy flat
    directories resolve to themselves.
    """

    root = Path(run_dir).expanduser().resolve()
    current_link = _state_dir(root) / CURRENT_LINK
    if current_link.is_symlink():
        try:
            target = os.readlink(current_link)
        except OSError:
            target = None
        if target:
            resolved = (current_link.parent / target).resolve()
            if resolved.is_dir():
                return resolved
    return root


def read_journal(run_dir: str | Path) -> dict[str, Any] | None:
    path = _state_dir(Path(run_dir).expanduser().resolve()) / JOURNAL_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_events(run_dir: str | Path) -> list[dict[str, Any]]:
    path = _state_dir(Path(run_dir).expanduser().resolve()) / EVENT_LOG_NAME
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


# ---------------------------------------------------------------------------
# Journal, events, links and low-level durable IO
# ---------------------------------------------------------------------------


def _empty_journal(root: Path) -> dict[str, Any]:
    return {
        "schema_version": JOURNAL_SCHEMA,
        "kind": JOURNAL_KIND,
        "output_dir": str(root),
        "created_at": now_iso(),
        "current": None,
        "pending": None,
    }


def _ensure_journal(root: Path, journal: dict[str, Any]) -> None:
    path = _state_dir(root) / JOURNAL_NAME
    if not path.is_file():
        _write_journal(root, journal)


def _read_journal(root: Path) -> dict[str, Any]:
    state = _state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    path = state / JOURNAL_NAME
    if not path.is_file():
        journal = _empty_journal(root)
        _write_journal(root, journal)
        return journal
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OutputError(f"发布状态日志不可读：{path}（{exc}）") from exc
    if not isinstance(journal, dict) or journal.get("kind") != JOURNAL_KIND:
        raise OutputError(f"发布状态日志格式不正确：{path}")
    return journal


def _write_journal(root: Path, journal: dict[str, Any]) -> None:
    state = _state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(state / JOURNAL_NAME, _json_bytes(journal))
    _fsync_dir(state)


def _append_event(
    root: Path, event: str, run_id: str, detail: dict[str, Any] | None = None
) -> None:
    state = _state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    entry = {
        "at": now_iso(),
        "event": event,
        "run_id": run_id,
        "detail": detail or {},
    }
    line = (
        json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str) + "\n"
    ).encode("utf-8")
    path = state / EVENT_LOG_NAME
    try:
        with open(path, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(state)
    except OSError as exc:
        raise OutputError(f"无法追加审计事件日志：{path}（{exc}）") from exc


def _flip_current_link(root: Path, release_dir: Path) -> None:
    state = _state_dir(root)
    link = state / CURRENT_LINK
    # Relative target so the whole run directory stays relocatable.
    target = os.path.relpath(release_dir, state)
    tmp = state / f".{CURRENT_LINK}.{uuid.uuid4().hex}.tmp"
    os.symlink(target, tmp)
    os.replace(tmp, link)
    _fsync_dir(state)


def _ensure_root_farm(root: Path, release_dir: Path) -> None:
    """Make every root-level artifact name a symlink into the current release.

    Each link is replaced atomically, and the farm always points at a single
    release, so an old manifest can never be paired with new files.
    """

    for name in ARTIFACT_FILES:
        link = root / name
        wanted_target = os.path.relpath(release_dir / name, root)
        if link.is_symlink():
            try:
                if os.readlink(link) == wanted_target:
                    continue
            except OSError:
                pass
        elif link.exists() and not link.is_symlink():
            # A leftover regular file (legacy or stray) is preserved, not
            # overwritten: quarantine it before exposing the farm link.
            _quarantine(root, link, f"loose-{name}")
        tmp = root / f".{name}.{uuid.uuid4().hex}.tmp"
        os.symlink(wanted_target, tmp)
        os.replace(tmp, link)
    _fsync_dir(root)


def _quarantine(root: Path, tree: Path, label: str) -> Path:
    quarantine_root = _state_path(root, QUARANTINE_DIR)
    quarantine_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    base = f"{tree.name}-{label}-{stamp}"
    destination = quarantine_root / base
    counter = 1
    while destination.exists():
        destination = quarantine_root / f"{base}-{counter}"
        counter += 1
    os.replace(tree, destination)
    _fsync_dir(quarantine_root)
    return destination


def _replace_tree(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise OutputError(f"目标发布版本已存在：{destination}")
    os.replace(source, destination)
    _fsync_dir(destination.parent)


@contextlib.contextmanager
def _publish_lock(root: Path) -> Iterator[None]:
    """Serialise publishes across processes and re-entrantly within one.

    fcntl.flock is associated with the open file description and blocks a
    second acquisition in the same thread, so nested calls within one process
    reuse the outer lock instead of deadlocking.
    """

    state = _state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    lock_path = state / LOCK_NAME
    holder = _LOCK_HOLDERS.get(lock_path)
    if holder is not None:
        holder[0] += 1
        try:
            yield
        finally:
            holder[0] -= 1
        return

    handle = open(lock_path, "a+b")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise OutputError(f"无法获取发布锁：{lock_path}（{exc}）") from exc
        token = [1]
        _LOCK_HOLDERS[lock_path] = token
        try:
            yield
        finally:
            token[0] -= 1
            if token[0] == 0:
                _LOCK_HOLDERS.pop(lock_path, None)
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _state_dir(root: Path) -> Path:
    return root / STATE_DIR


def _state_path(root: Path, relative: str) -> Path:
    return _state_dir(root) / relative


def _release_dir(root: Path, run_id: str) -> Path:
    return _state_path(root, f"{RELEASES_DIR}/{run_id}")


def _run_root_from_state(staging_dir: Path) -> Path:
    # .charorder/staging/<s-id> -> run root is two parents up.
    if staging_dir.parent.name != STAGING_DIR:
        raise OutputError(f"暂存目录位置不正确：{staging_dir}")
    return staging_dir.parents[2]


def _load_manifest(directory: Path) -> dict[str, Any]:
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OutputError(f"发布清单不可读：{directory / 'manifest.json'}（{exc}）") from exc
    if not isinstance(manifest, dict):
        raise OutputError(f"发布清单顶层必须是对象：{directory}")
    return manifest


def _release_verifies(directory: Path) -> bool:
    try:
        verify_run(directory)
    except VerificationError:
        return False
    return (directory / "manifest.json").is_file()


def _current_release_verifies(root: Path, current: dict[str, Any]) -> bool:
    release = current.get("release")
    if not isinstance(release, str):
        return False
    return _release_verifies(_state_path(root, release))


def _fsync_dir(directory: Path) -> None:
    try:
        handle = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def _resolve_policy(policy: str | None) -> str:
    chosen = policy or os.environ.get(_POLICY_ENV) or _ROLLBACK
    if chosen not in _RECOVERY_POLICIES:
        raise OutputError(
            f"恢复策略必须是 {_ROLLFORWARD} 或 {_ROLLBACK}：{chosen}"
        )
    return chosen


def _maybe_fault(point: str) -> None:
    if os.environ.get(_FAULT_ENV) == point:
        raise PublishFault(
            f"模拟进程中断（{point}）：当前发布版本保持不变，未完成产物已隔离。"
        )


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
        _fsync_dir(path.parent)
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
