"""CVEIntel report generation for developer and business audiences."""

from __future__ import annotations

from .models import (
    BusinessEntry,
    BusinessReport,
    BusinessSummary,
    ConsolidatedReport,
    DeveloperEntry,
    DeveloperReport,
    PatchStatus,
)

_STATUS_DESCRIPTIONS: dict[str, str] = {
    "patched": "Patched",
    "not_patched": "Not patched",
    "partially_patched": "Partially patched",
    "undetermined": "Undetermined",
}

_STATUS_SEVERITY: dict[str, str] = {
    "patched": "Low",
    "not_patched": "High",
    "partially_patched": "Medium",
    "undetermined": "Unknown",
}


def generate_developer_report(statuses: list[PatchStatus]) -> DeveloperReport:
    """Build a developer-focused report from patch statuses.

    Each entry contains CVE ID, patch status per release, affected packages
    with versions, resolution commands, and ALAS advisory links.
    Entries are grouped by CVE identifier (one entry per CVE).
    """
    entries: list[DeveloperEntry] = []
    for ps in statuses:
        alas_links: list[str] = []
        for rs in ps.releases.values():
            if rs.alas_url and rs.alas_url not in alas_links:
                alas_links.append(rs.alas_url)
        entries.append(
            DeveloperEntry(cve_id=ps.cve_id, patch_status=ps, alas_links=alas_links)
        )
    return DeveloperReport(entries=entries)


def generate_business_report(statuses: list[PatchStatus]) -> BusinessReport:
    """Build a business-stakeholder report from patch statuses.

    Each entry contains CVE ID, plain-language description, severity, and
    remediation status. No commands or package version details are included.
    Includes a summary with total, patched, unpatched, and undetermined counts.
    """
    entries: list[BusinessEntry] = []
    patched = 0
    unpatched = 0
    undetermined = 0

    for ps in statuses:
        remediation = _STATUS_DESCRIPTIONS.get(ps.status, "Unknown")
        severity = _STATUS_SEVERITY.get(ps.status, "Unknown")
        description = ps.description or f"Vulnerability {ps.cve_id}"
        if ps.reason and not ps.description:
            description = f"Vulnerability {ps.cve_id} — {ps.reason}"

        # Collect advisory links from releases
        advisory_links: list[str] = []
        for rs in ps.releases.values():
            if rs.alas_url and rs.alas_url not in advisory_links:
                advisory_links.append(rs.alas_url)

        entries.append(
            BusinessEntry(
                cve_id=ps.cve_id,
                description=description,
                severity=severity,
                remediation_status=remediation,
                impacted_components=list(ps.impacted_components),
                advisory_links=advisory_links,
            )
        )

        if ps.status == "patched":
            patched += 1
        elif ps.status in ("not_patched", "partially_patched"):
            unpatched += 1
        else:
            undetermined += 1

    summary = BusinessSummary(
        total=len(statuses),
        patched=patched,
        unpatched=unpatched,
        undetermined=undetermined,
    )
    return BusinessReport(entries=entries, summary=summary)


def generate_consolidated_report(
    statuses: list[PatchStatus],
) -> ConsolidatedReport:
    """Build a consolidated report combining developer and business sections.

    Composes by calling generate_developer_report and generate_business_report
    internally. The rendered output should include a clear section separator
    between the two sections.
    """
    return ConsolidatedReport(
        developer_section=generate_developer_report(statuses),
        business_section=generate_business_report(statuses),
    )
