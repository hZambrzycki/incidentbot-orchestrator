"""
Runbook: Cleanup Disk
Safely cleans up disk space by removing old logs, temp files, and cache.
"""

from __future__ import annotations

import asyncio
import glob
import os
import re
import sys
from dataclasses import dataclass, field

from src.core.logging_config import get_logger
from src.core.models import Severity
from src.runbooks.registry import runbook

logger = get_logger("runbook.cleanup_disk")

# -----------------------------
# Config (safe defaults)
# -----------------------------

# Safe directories where cleanup is allowed
SAFE_CLEANUP_PATHS: list[str] = [
    "/var/log",
    "/tmp",
    "/var/tmp",
    "/var/cache/apt/archives",
    "/root/.cache",
    "/home/*/.cache",
]

# File patterns to clean (age in days)
# Note: log retention is overridden by log_retention_days parameter.
CLEANUP_PATTERNS: dict[str, int] = {
    "/var/log/*.gz": 7,
    "/var/log/*.log.*": 7,
    "/var/log/**/*.gz": 7,
    "/tmp/*": 1,
    "/var/tmp/*": 3,
}

DEFAULT_MAX_FILES_PER_PATTERN = 200


# -----------------------------
# Types
# -----------------------------


@dataclass
class CleanupResult:
    """Result of cleanup operation."""

    success: bool
    status: str  # "ok", "failed", "skipped", "degraded"
    message: str
    space_freed_mb: float = 0.0
    items_removed: int = 0
    errors: list[str] = field(default_factory=list)


# -----------------------------
# Helpers (pure-ish)
# -----------------------------


def _status_from_errors(items_removed: int, errors: list[str]) -> tuple[str, bool]:
    """
    Returns (status, success).
    - degraded if we removed something but had errors
    - failed if we removed nothing and had errors
    - ok otherwise
    """
    if errors and items_removed > 0:
        return "degraded", True
    if errors and items_removed == 0:
        return "failed", False
    return "ok", True


def _split_pattern(pattern: str) -> tuple[str, str]:
    """
    "/var/log/**/*.gz" -> ("/var/log", "*.gz") with recurse=True detected in caller
    "/var/tmp/*"      -> ("/var/tmp", "*")
    """
    base = os.path.dirname(pattern)
    name = os.path.basename(pattern)
    return base, name


def _expand_allowed_roots(allowed_roots: list[str]) -> list[str]:
    expanded: list[str] = []
    for root in allowed_roots:
        if any(ch in root for ch in ("*", "?", "[")):
            expanded.extend(glob.glob(root))
        else:
            expanded.append(root)
    return expanded


def _is_under_any_allowed(path: str, allowed_roots: list[str]) -> bool:
    """
    allowed_roots may include glob (e.g. /home/*/.cache).
    Resolves to real paths and validates by prefix.
    """
    try:
        rp = os.path.realpath(path)
    except Exception:
        return False

    for root in _expand_allowed_roots(allowed_roots):
        try:
            rr = os.path.realpath(root)
            if rp == rr or rp.startswith(rr.rstrip("/") + "/"):
                return True
        except Exception:
            continue

    return False


# -----------------------------
# Helpers (I/O)
# -----------------------------


async def _run_cmd(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout = stdout_b.decode(errors="ignore")
        stderr = stderr_b.decode(errors="ignore")
        return proc.returncode, stdout, stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"


async def _get_disk_usage() -> dict:
    """Get current disk usage for /."""
    try:
        rc, stdout, stderr = await _run_cmd("df", "-P", "/", timeout=10)
        if rc != 0:
            logger.warning("df_failed", rc=rc, stderr=(stderr or "").strip())
            return {}

        lines = stdout.strip().split("\n")
        if len(lines) < 2:
            return {}

        parts = lines[1].split()
        if len(parts) < 5:
            return {}

        return {
            "filesystem": parts[0],
            "size": parts[1],
            "used": parts[2],
            "available": parts[3],
            "use_percent": int(parts[4].rstrip("%")),
        }
    except Exception as e:
        logger.warning("disk_usage_error", error=str(e))
        return {}


# -----------------------------
# Actions
# -----------------------------


async def _clean_by_patterns(
    patterns: dict[str, int],
    allowed_paths: list[str],
    max_files_per_pattern: int = DEFAULT_MAX_FILES_PER_PATTERN,
) -> CleanupResult:
    """
    Clean files by patterns {glob_pattern: days}.
    - Uses 'find' for mtime + name (and ** for recurse).
    - Validates paths against allowed_paths.
    """
    errors: list[str] = []
    total_freed = 0.0
    total_removed = 0

    if not patterns:
        return CleanupResult(
            success=False,
            status="skipped",
            message="No cleanup patterns configured (skipped)",
        )

    for pattern, days in patterns.items():
        base, name = _split_pattern(pattern)
        recurse = "**" in pattern

        # Normalize base for recursive patterns
        base_norm = base.replace("/**", "")

        # Safety: base must be under allowed paths (expanded globs)
        if not _is_under_any_allowed(base_norm, allowed_paths):
            errors.append(f"Pattern base not allowed: {pattern}")
            continue

        # Build find:
        # - if recurse: search from base_norm without depth limit
        # - else: limit to maxdepth 1 so "/tmp/*" won't traverse deeper
        find_args: list[str] = ["find", base_norm]

        if not recurse:
            find_args += ["-maxdepth", "1"]

        find_args += [
            "-type",
            "f",
            "-name",
            name,
            "-mtime",
            f"+{int(days)}",
        ]

        rc, stdout, stderr = await _run_cmd(*find_args, timeout=45)

        # 'find' may warn about permissions. Keep as "soft" errors.
        if (stderr or "").strip():
            errors.append(f"find stderr ({pattern}): {stderr.strip()}")

        files = [f for f in (stdout or "").splitlines() if f.strip()]

        removed_this_pattern = 0
        for filepath in files[:max_files_per_pattern]:
            try:
                if not _is_under_any_allowed(filepath, allowed_paths):
                    errors.append(f"Refused (outside allowed paths): {filepath}")
                    continue

                size = os.path.getsize(filepath) / (1024 * 1024)
                os.remove(filepath)
                total_freed += size
                total_removed += 1
                removed_this_pattern += 1
            except PermissionError:
                errors.append(f"Permission denied: {filepath}")
            except FileNotFoundError:
                # If file disappeared between find and remove, ignore.
                continue
            except Exception as e:
                errors.append(f"Error removing {filepath}: {str(e)}")

        # If find failed hard AND we removed nothing, count it as a serious error.
        if rc != 0 and removed_this_pattern == 0:
            errors.append(f"find returncode {rc} for pattern {pattern}")

    status, success = _status_from_errors(total_removed, errors)

    if total_removed == 0 and not errors:
        return CleanupResult(
            success=False,
            status="skipped",
            message="Nothing to clean (skipped)",
            space_freed_mb=0.0,
            items_removed=0,
            errors=[],
        )

    return CleanupResult(
        success=success,
        status=status,
        message=f"Cleaned {total_removed} items by patterns",
        space_freed_mb=total_freed,
        items_removed=total_removed,
        errors=errors,
    )


async def _clean_apt_cache() -> CleanupResult:
    """Clean apt cache (Debian/Ubuntu)."""
    rc, stdout, stderr = await _run_cmd("apt-get", "clean", timeout=60)
    if rc == 0:
        return CleanupResult(success=True, status="ok", message="APT cache cleaned")

    err = (stderr or "").strip()
    if rc == 127 or "command not found" in err.lower():
        return CleanupResult(
            success=False, status="skipped", message="apt-get not available (skipped)"
        )

    return CleanupResult(
        success=False,
        status="failed",
        message=f"apt-get clean failed: {err or 'unknown error'}",
        errors=[err] if err else [],
    )


async def _clean_journal_logs(days: int = 7) -> CleanupResult:
    """Clean old journald logs."""
    rc, stdout, stderr = await _run_cmd(
        "journalctl", "--vacuum-time", f"{days}d", timeout=60
    )

    if rc == 127:
        return CleanupResult(
            success=False,
            status="skipped",
            message="journalctl not available (skipped)",
        )

    output = (stdout or "") + "\n" + (stderr or "")

    if rc != 0:
        err = (stderr or "").strip()
        return CleanupResult(
            success=False,
            status="failed",
            message=f"journalctl vacuum failed: {err or 'unknown error'}",
            errors=[err] if err else [],
        )

    match = re.search(r"freed\s+([\d.]+)\s*([BKMG]?)", output, re.IGNORECASE)
    space_freed = 0.0
    if match:
        value = float(match.group(1))
        unit = (match.group(2) or "").upper()
        if unit == "G":
            space_freed = value * 1024
        elif unit == "M":
            space_freed = value
        elif unit == "K":
            space_freed = value / 1024
        else:
            space_freed = value / (1024 * 1024)

    return CleanupResult(
        success=True,
        status="ok",
        message=f"Journal logs cleaned (kept last {days} days)",
        space_freed_mb=space_freed,
    )


async def _clean_docker_system() -> CleanupResult:
    """Clean unused Docker resources."""
    rc, stdout, stderr = await _run_cmd("docker", "system", "prune", "-f", timeout=120)

    if rc == 127:
        return CleanupResult(
            success=False, status="skipped", message="Docker not available (skipped)"
        )

    if rc != 0:
        err = (stderr or "").strip()
        err_l = err.lower()
        socket_markers = (
            "cannot connect to the docker daemon",
            "is the docker daemon running",
            "error during connect",
            "permission denied",
            "connect: no such file or directory",
        )
        if any(m in err_l for m in socket_markers):
            return CleanupResult(
                success=False,
                status="skipped",
                message=f"Docker not accessible (skipped): {err}",
                errors=[err] if err else [],
            )
        return CleanupResult(
            success=False,
            status="failed",
            message=f"Docker prune failed: {err or 'unknown error'}",
            errors=[err] if err else [],
        )

    output = stdout or ""
    match = re.search(r"reclaimed\s+([\d.]+)\s*([KMG]?B)", output, re.IGNORECASE)
    space_freed = 0.0
    if match:
        value = float(match.group(1))
        unit = match.group(2).upper()
        if "G" in unit:
            space_freed = value * 1024
        elif "M" in unit:
            space_freed = value
        elif "K" in unit:
            space_freed = value / 1024
        else:
            space_freed = value / (1024 * 1024)

    return CleanupResult(
        success=True,
        status="ok",
        message="Docker system pruned",
        space_freed_mb=space_freed,
    )


# -----------------------------
# Runbook
# -----------------------------


@runbook(
    name="cleanup_disk",
    description="Clean up disk space by removing old logs, temp files, and cache",
    category="disk",
    severity_threshold=Severity.WARNING,
    auto_execute=True,
    requires_confirmation=False,
    timeout=300,
    allowed_services=["*"],
    allowed_parameters=[
        "clean_logs",
        "clean_tmp",
        "clean_apt",
        "clean_journal",
        "clean_docker",
        "log_retention_days",
        "max_files_per_pattern",
    ],
    dangerous=False,
)
async def cleanup_disk(
    clean_logs: bool = True,
    clean_tmp: bool = True,
    clean_apt: bool = True,
    clean_journal: bool = True,
    clean_docker: bool = False,  # Off by default, can remove important images
    log_retention_days: int = 7,
    max_files_per_pattern: int = DEFAULT_MAX_FILES_PER_PATTERN,
    **kwargs,
) -> dict:
    if sys.platform.startswith("win"):
        return {
            "success": False,
            "status": "skipped",
            "message": (
                "cleanup_disk is not supported on Windows. "
                "Run it inside WSL2/Docker/Linux to enable disk cleanup."
            ),
            "overall_status": "skipped",
        }

    logger.info(
        "starting_disk_cleanup",
        clean_logs=clean_logs,
        clean_tmp=clean_tmp,
        clean_apt=clean_apt,
        clean_journal=clean_journal,
        clean_docker=clean_docker,
        log_retention_days=log_retention_days,
        max_files_per_pattern=max_files_per_pattern,
    )

    initial_usage = await _get_disk_usage()

    results: list[tuple[str, CleanupResult]] = []
    total_freed = 0.0
    total_items = 0
    all_errors: list[str] = []

    # --- Pattern-based cleanup ---
    pattern_subset: dict[str, int] = {}

    if clean_logs:
        for p in ("/var/log/*.gz", "/var/log/*.log.*", "/var/log/**/*.gz"):
            if p in CLEANUP_PATTERNS:
                pattern_subset[p] = log_retention_days  # respect user input

    if clean_tmp:
        for p in ("/tmp/*", "/var/tmp/*"):
            if p in CLEANUP_PATTERNS:
                pattern_subset[p] = CLEANUP_PATTERNS[p]

    if pattern_subset:
        r = await _clean_by_patterns(
            patterns=pattern_subset,
            allowed_paths=SAFE_CLEANUP_PATHS,
            max_files_per_pattern=max_files_per_pattern,
        )
        results.append(("patterns", r))
        total_freed += r.space_freed_mb
        total_items += r.items_removed
        all_errors.extend(r.errors)

    if clean_apt:
        r = await _clean_apt_cache()
        results.append(("apt_cache", r))
        total_freed += r.space_freed_mb
        all_errors.extend(r.errors)

    if clean_journal:
        r = await _clean_journal_logs(days=log_retention_days)
        results.append(("journal", r))
        total_freed += r.space_freed_mb
        all_errors.extend(r.errors)

    if clean_docker:
        r = await _clean_docker_system()
        results.append(("docker", r))
        total_freed += r.space_freed_mb
        all_errors.extend(r.errors)

    final_usage = await _get_disk_usage()

    statuses = [r.status for _, r in results]
    effective = [s for s in statuses if s != "skipped"]

    if not effective:
        overall_status = "skipped"
    elif "failed" in effective:
        overall_status = "failed"
    elif "degraded" in effective:
        overall_status = "degraded"
    else:
        overall_status = "ok"

    success = overall_status != "failed"

    logger.info(
        "disk_cleanup_complete",
        total_freed_mb=total_freed,
        total_items=total_items,
        success=success,
        initial_usage=initial_usage.get("use_percent"),
        final_usage=final_usage.get("use_percent"),
        overall_status=overall_status,
    )

    return {
        "success": success,
        "overall_status": overall_status,
        "message": (
            f"Cleanup {overall_status}: freed ~{total_freed:.1f} MB, "
            f"removed {total_items} items"
        ),
        "space_freed_mb": total_freed,
        "items_removed": total_items,
        "initial_disk_usage": initial_usage,
        "final_disk_usage": final_usage,
        "details": {
            name: {"success": r.success, "status": r.status, "message": r.message}
            for name, r in results
        },
        "errors": all_errors[:10] if all_errors else None,
    }
