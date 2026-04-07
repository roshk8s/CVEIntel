"""CVEIntel ECR image scan findings retrieval."""

from __future__ import annotations

import re

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cveintel.core.exceptions import InputError
from cveintel.core.models import ECRScanResult

ECR_ARN_PATTERN = re.compile(
    r"^arn:aws:ecr:[a-z0-9-]+:\d{12}:repository/[\w./-]+"
)

# ECR image URI: <account>.dkr.ecr.<region>.amazonaws.com/<repo>[:<tag>|@<digest>]
ECR_URI_PATTERN = re.compile(
    r"^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/(.+)$"
)


def validate_ecr_arn(arn: str) -> bool:
    """Return True if *arn* matches a valid ECR image ARN format."""
    return bool(ECR_ARN_PATTERN.match(arn))


def validate_ecr_uri(uri: str) -> bool:
    """Return True if *uri* matches a valid ECR image URI format."""
    return bool(ECR_URI_PATTERN.match(uri))


def _parse_ecr_input(image_ref: str) -> tuple[str, str, str]:
    """Extract region, registry_id, and repository/tag from an ECR ARN or image URI.

    Accepts both formats:
      - ARN: arn:aws:ecr:<region>:<account>:repository/<repo>[:<tag>|@<digest>]
      - URI: <account>.dkr.ecr.<region>.amazonaws.com/<repo>[:<tag>|@<digest>]

    Raises InputError when neither format matches.
    """
    # Try URI format first (more common user input)
    uri_match = ECR_URI_PATTERN.match(image_ref)
    if uri_match:
        registry_id = uri_match.group(1)
        region = uri_match.group(2)
        repo_path = uri_match.group(3)
        return region, registry_id, repo_path

    # Try ARN format
    if validate_ecr_arn(image_ref):
        parts = image_ref.split(":")
        region = parts[3]
        registry_id = parts[4]
        repo_and_rest = ":".join(parts[5:])
        repo_path = repo_and_rest.split("/", 1)[1] if "/" in repo_and_rest else repo_and_rest
        return region, registry_id, repo_path

    raise InputError(
        f"Invalid ECR image reference '{image_ref}'. Expected either:\n"
        "  URI: <account-id>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>\n"
        "  ARN: arn:aws:ecr:<region>:<account-id>:repository/<repo-name>"
    )


async def fetch_ecr_scan_findings(
    image_ref: str,
    region: str | None = None,
) -> ECRScanResult:
    """Call ECR DescribeImageScanFindings and extract CVE IDs.

    Uses configured AWS credentials.  Returns an ``ECRScanResult`` with
    ``error`` populated on API failure (permissions, image not found, scan
    not available).  Returns empty ``cve_ids`` when no findings exist.

    Args:
        image_ref: ECR image URI or ARN (may include tag or digest).
        region: Optional AWS region override.  Derived from the input when
            not supplied.

    Returns:
        ECRScanResult with extracted CVE identifiers and severities.
    """
    try:
        arn_region, registry_id, repo_path = _parse_ecr_input(image_ref)
    except InputError as exc:
        return ECRScanResult(image_arn=image_ref, error=str(exc))

    effective_region = region or arn_region

    # Separate repository name from image identifier (tag or digest)
    image_id: dict[str, str] = {}
    if "@" in repo_path:
        repo_name, digest = repo_path.split("@", 1)
        image_id["imageDigest"] = digest
    elif ":" in repo_path:
        repo_name, tag = repo_path.rsplit(":", 1)
        image_id["imageTag"] = tag
    else:
        repo_name = repo_path
        image_id["imageTag"] = "latest"

    try:
        client = boto3.client("ecr", region_name=effective_region)
        paginator = client.get_paginator("describe_image_scan_findings")

        cve_ids: list[str] = []
        severities: dict[str, str] = {}

        for page in paginator.paginate(
            registryId=registry_id,
            repositoryName=repo_name,
            imageId=image_id,
        ):
            scan_findings = page.get("imageScanFindings", {})

            # Basic scanning: findings are under "findings"
            for finding in scan_findings.get("findings", []):
                cve_name = finding.get("name", "")
                severity = finding.get("severity", "UNDEFINED")
                if cve_name.startswith("CVE-"):
                    cve_ids.append(cve_name)
                    severities[cve_name] = severity

            # Enhanced scanning (Inspector): findings under "enhancedFindings"
            for finding in scan_findings.get("enhancedFindings", []):
                pkg_vuln = finding.get("packageVulnerabilityDetails", {})
                # The CVE ID is in vulnerabilityId
                cve_name = pkg_vuln.get("vulnerabilityId", "") or finding.get("title", "")
                severity = finding.get("severity", "UNDEFINED")
                if cve_name.startswith("CVE-") and cve_name not in severities:
                    cve_ids.append(cve_name)
                    severities[cve_name] = severity

        return ECRScanResult(
            image_arn=image_ref,
            cve_ids=cve_ids,
            severities=severities,
        )

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        error_msg = exc.response.get("Error", {}).get("Message", str(exc))

        if error_code == "RepositoryNotFoundException":
            detail = f"Repository not found for '{image_ref}': {error_msg}"
        elif error_code == "ImageNotFoundException":
            detail = f"Image not found for '{image_ref}': {error_msg}"
        elif error_code == "ScanNotFoundException":
            detail = (
                f"No scan results available for '{image_ref}'. "
                "Ensure an image scan has been run."
            )
        elif error_code in ("AccessDeniedException", "UnauthorizedAccess"):
            detail = (
                f"Permission denied when accessing ECR scan findings for "
                f"'{image_ref}': {error_msg}"
            )
        else:
            detail = f"ECR API error for '{image_ref}' ({error_code}): {error_msg}"

        return ECRScanResult(image_arn=image_ref, error=detail)

    except BotoCoreError as exc:
        return ECRScanResult(
            image_arn=image_ref,
            error=f"AWS SDK error for '{image_ref}': {exc}",
        )
