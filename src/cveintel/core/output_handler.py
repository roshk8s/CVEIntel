"""CVEIntel output rendering and destination handling."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any

from .exceptions import OutputError
from .models import (
    BusinessReport,
    ConsolidatedReport,
    DeveloperReport,
)

# ANSI color codes
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_STATUS_COLORS: dict[str, str] = {
    "patched": _GREEN,
    "not_patched": _RED,
    "partially_patched": _RED,
    "undetermined": _YELLOW,
}

_ALAS_BASE = "https://alas.aws.amazon.com"


def _ensure_alas_url(value: str) -> str:
    """Turn an ALAS ID or partial path into a full URL if needed."""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    # Normalize: remove stray hyphen between "ALAS" and year digits
    # e.g. "ALAS-2023-2026-1532" -> "ALAS2023-2026-1532"
    normalized = re.sub(r"^ALAS-(\d)", r"ALAS\1", value)
    if normalized.startswith("ALAS"):
        if "ALAS2023" in normalized:
            return f"{_ALAS_BASE}/AL2023/{normalized}.html"
        if "ALAS2" in normalized:
            return f"{_ALAS_BASE}/AL2/{normalized}.html"
        return f"{_ALAS_BASE}/{normalized}.html"
    return value


def _colorize(text: str, status: str) -> str:
    color = _STATUS_COLORS.get(status, _RESET)
    return f"{color}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

def _render_developer_terminal(report: DeveloperReport) -> str:
    lines: list[str] = [f"{_BOLD}=== Developer Report ==={_RESET}", ""]
    for entry in report.entries:
        ps = entry.patch_status
        status_label = _colorize(ps.status.replace("_", " ").title(), ps.status)
        lines.append(f"{_BOLD}{ps.cve_id}{_RESET}  Status: {status_label}")
        if ps.reason:
            lines.append(f"  Reason: {ps.reason}")
        for rname, rs in ps.releases.items():
            patched_str = "Yes" if rs.patched else ("No" if rs.patched is False else "Unknown")
            patched_color = _GREEN if rs.patched else (_RED if rs.patched is False else _YELLOW)
            lines.append(f"  {rname}: {patched_color}{patched_str}{_RESET}")
            for pkg in rs.affected_packages:
                ver = f" ({pkg.affected_version} -> {pkg.fixed_version})" if pkg.affected_version or pkg.fixed_version else ""
                lines.append(f"    - {pkg.name}{ver}")
            if rs.resolution_commands:
                lines.append(f"    Run the following to remediate:")
                for cmd in rs.resolution_commands:
                    lines.append(f"      $ {cmd}")
            if rs.alas_url:
                lines.append(f"    Link: {_ensure_alas_url(rs.alas_url)}")
        if entry.alas_links:
            full_links = [_ensure_alas_url(link) for link in entry.alas_links]
            lines.append(f"  Advisory links: {', '.join(full_links)}")
        lines.append("")
    return "\n".join(lines)


def _render_business_terminal(report: BusinessReport) -> str:
    lines: list[str] = [f"{_BOLD}=== Business Report ==={_RESET}", ""]
    for entry in report.entries:
        status_key = entry.remediation_status.lower().replace(" ", "_")
        colored_status = _colorize(entry.remediation_status, status_key)
        lines.append(f"{_BOLD}{entry.cve_id}{_RESET}  {colored_status}")
        lines.append(f"  {entry.description}")
        lines.append(f"  Severity: {entry.severity}")
        if entry.impacted_components:
            lines.append(f"  Impacted: {', '.join(entry.impacted_components)}")
        if entry.advisory_links:
            lines.append(f"  Advisory: {', '.join(entry.advisory_links)}")
        lines.append("")
    s = report.summary
    lines.append(f"{_BOLD}Summary{_RESET}")
    lines.append(f"  Total: {s.total}  "
                 f"{_GREEN}Patched: {s.patched}{_RESET}  "
                 f"{_RED}Unpatched: {s.unpatched}{_RESET}  "
                 f"{_YELLOW}Undetermined: {s.undetermined}{_RESET}")
    lines.append("")
    return "\n".join(lines)


def render_terminal(report: DeveloperReport | BusinessReport | ConsolidatedReport) -> str:
    """Render report as colored terminal output."""
    if isinstance(report, ConsolidatedReport):
        dev = _render_developer_terminal(report.developer_section)
        sep = f"\n{_BOLD}{'=' * 60}{_RESET}\n\n"
        biz = _render_business_terminal(report.business_section)
        return dev + sep + biz
    if isinstance(report, DeveloperReport):
        return _render_developer_terminal(report)
    if isinstance(report, BusinessReport):
        return _render_business_terminal(report)
    raise TypeError(f"Unsupported report type: {type(report).__name__}")


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------

class _ReportEncoder(json.JSONEncoder):
    """Custom encoder that handles dataclass-converted dicts with None values."""

    def default(self, o: Any) -> Any:
        # Fallback for any non-serializable types
        return str(o)


def render_json(report: DeveloperReport | BusinessReport | ConsolidatedReport) -> str:
    """Render report as a JSON string."""
    return json.dumps(asdict(report), cls=_ReportEncoder, indent=2)


# ---------------------------------------------------------------------------
# Plain-text rendering
# ---------------------------------------------------------------------------

def _plain_developer(report: DeveloperReport) -> str:
    lines: list[str] = ["=== Developer Report ===", ""]
    for entry in report.entries:
        ps = entry.patch_status
        lines.append(f"{ps.cve_id}  Status: {ps.status.replace('_', ' ').title()}")
        if ps.reason:
            lines.append(f"  Reason: {ps.reason}")
        for rname, rs in ps.releases.items():
            patched_str = "Yes" if rs.patched else ("No" if rs.patched is False else "Unknown")
            lines.append(f"  {rname}: {patched_str}")
            for pkg in rs.affected_packages:
                ver = f" ({pkg.affected_version} -> {pkg.fixed_version})" if pkg.affected_version or pkg.fixed_version else ""
                lines.append(f"    - {pkg.name}{ver}")
            if rs.resolution_commands:
                lines.append(f"    Run the following to remediate:")
                for cmd in rs.resolution_commands:
                    lines.append(f"      $ {cmd}")
            if rs.alas_url:
                lines.append(f"    Link: {_ensure_alas_url(rs.alas_url)}")
        if entry.alas_links:
            full_links = [_ensure_alas_url(link) for link in entry.alas_links]
            lines.append(f"  Advisory links: {', '.join(full_links)}")
        lines.append("")
    return "\n".join(lines)


def _plain_business(report: BusinessReport) -> str:
    lines: list[str] = ["=== Business Report ===", ""]
    for entry in report.entries:
        lines.append(f"{entry.cve_id}  {entry.remediation_status}")
        lines.append(f"  {entry.description}")
        lines.append(f"  Severity: {entry.severity}")
        if entry.impacted_components:
            lines.append(f"  Impacted: {', '.join(entry.impacted_components)}")
        if entry.advisory_links:
            lines.append(f"  Advisory: {', '.join(entry.advisory_links)}")
        lines.append("")
    s = report.summary
    lines.append("Summary")
    lines.append(f"  Total: {s.total}  Patched: {s.patched}  Unpatched: {s.unpatched}  Undetermined: {s.undetermined}")
    lines.append("")
    return "\n".join(lines)


def render_plain_text(report: DeveloperReport | BusinessReport | ConsolidatedReport) -> str:
    """Render report as plain text (no ANSI codes)."""
    if isinstance(report, ConsolidatedReport):
        dev = _plain_developer(report.developer_section)
        sep = "\n" + "=" * 60 + "\n\n"
        biz = _plain_business(report.business_section)
        return dev + sep + biz
    if isinstance(report, DeveloperReport):
        return _plain_developer(report)
    if isinstance(report, BusinessReport):
        return _plain_business(report)
    raise TypeError(f"Unsupported report type: {type(report).__name__}")


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def write_to_file(content: str, path: str) -> None:
    """Write rendered report content to a file path.

    Raises OutputError on write failure.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as exc:
        raise OutputError(f"Failed to write to {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# S3 output
# ---------------------------------------------------------------------------

async def upload_to_s3(content: str, bucket: str, key: str) -> None:
    """Upload rendered report to S3.

    Falls back to printing to terminal on failure.
    """
    try:
        import boto3  # type: ignore[import-untyped]

        s3 = boto3.client("s3")
        s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
    except Exception as exc:
        # Fallback: print to terminal so the user still sees the report
        print(f"S3 upload failed ({exc}). Displaying report on terminal:\n")
        print(content)
