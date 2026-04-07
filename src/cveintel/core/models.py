"""CVEIntel data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class PackageInfo:
    """Information about an affected package."""

    name: str
    affected_version: str | None = None
    fixed_version: str | None = None


@dataclass
class ReleaseStatus:
    """Patch status for a specific Amazon Linux release."""

    release_name: str
    patched: bool | None = None
    affected_packages: list[PackageInfo] = field(default_factory=list)
    resolution_commands: list[str] = field(default_factory=list)
    alas_url: str | None = None


@dataclass
class PatchStatus:
    """Overall patch status for a CVE across releases."""

    cve_id: str
    status: Literal["patched", "not_patched", "partially_patched", "undetermined"]
    releases: dict[str, ReleaseStatus] = field(default_factory=dict)
    reason: str | None = None
    description: str | None = None
    impacted_components: list[str] = field(default_factory=list)


@dataclass
class AdvisoryResult:
    """Result of fetching an ALAS advisory for a CVE."""

    cve_id: str
    found: bool
    alas_id: str | None = None
    advisory_url: str | None = None
    advisory_html: str | None = None
    error: str | None = None


@dataclass
class ECRScanResult:
    """Result of fetching ECR image scan findings."""

    image_arn: str
    cve_ids: list[str] = field(default_factory=list)
    severities: dict[str, str] = field(default_factory=dict)
    error: str | None = None


@dataclass
class DeveloperEntry:
    """A single entry in the developer report."""

    cve_id: str
    patch_status: PatchStatus
    alas_links: list[str] = field(default_factory=list)


@dataclass
class DeveloperReport:
    """Technical report for developers."""

    entries: list[DeveloperEntry] = field(default_factory=list)


@dataclass
class BusinessEntry:
    """A single entry in the business report."""

    cve_id: str
    description: str
    severity: str
    remediation_status: str
    impacted_components: list[str] = field(default_factory=list)
    advisory_links: list[str] = field(default_factory=list)


@dataclass
class BusinessSummary:
    """Summary counts for the business report."""

    total: int = 0
    patched: int = 0
    unpatched: int = 0
    undetermined: int = 0


@dataclass
class BusinessReport:
    """Non-technical report for business stakeholders."""

    entries: list[BusinessEntry] = field(default_factory=list)
    summary: BusinessSummary = field(default_factory=BusinessSummary)


@dataclass
class ConsolidatedReport:
    """Combined developer and business report."""

    developer_section: DeveloperReport = field(default_factory=DeveloperReport)
    business_section: BusinessReport = field(default_factory=BusinessReport)


@dataclass
class AppConfig:
    """Application configuration loaded from environment."""

    ai_provider: Literal["openai", "bedrock", "local"]
    api_key: str | None = None
    model: str | None = None
    bedrock_model_id: str | None = None
    local_endpoint: str | None = None
    aws_region: str = "us-east-1"
