"""LLM Analyzer — uses an AI provider to extract structured patch status from advisory HTML."""

from __future__ import annotations

import json
import logging

from cveintel.core.ai_provider import AIProvider
from cveintel.core.models import (
    AdvisoryResult,
    PackageInfo,
    PatchStatus,
    ReleaseStatus,
)

logger = logging.getLogger(__name__)

_ANALYSIS_PROMPT = """\
You are a security analyst. Analyze the following Amazon Linux Security Advisory HTML \
and extract structured patch information for CVE {cve_id}.

Return ONLY a JSON object (no markdown fences, no commentary) with this exact schema:

{{
  "status": "patched" | "not_patched" | "partially_patched" | "undetermined",
  "reason": null or string explaining why status is undetermined,
  "description": "A plain-language summary of what this vulnerability is and its potential impact (1-2 sentences)",
  "impacted_components": ["list", "of", "affected", "software", "components"],
  "releases": {{
    "<release_name>": {{
      "patched": true | false | null,
      "affected_packages": [
        {{
          "name": "package-name",
          "affected_version": "version or null",
          "fixed_version": "version or null"
        }}
      ],
      "resolution_commands": ["yum update ..."],
      "alas_url": "url or null"
    }}
  }}
}}

Rules:
- Use release names like "AL2023", "AL2", "AL1".
- "status" should be "patched" if all releases are patched, "not_patched" if none are, \
"partially_patched" if some are, and "undetermined" if you cannot determine.
- "description" should be a concise, non-technical summary suitable for business stakeholders.
- "impacted_components" should list the software packages or services affected.
- Include resolution commands (e.g. yum/dnf update commands) when available.
- If you cannot determine the status, set status to "undetermined" and provide a reason.

Advisory HTML:
{advisory_html}
"""

_MAX_RETRIES = 1


async def analyze_advisory(
    advisory: AdvisoryResult,
    provider: AIProvider,
) -> PatchStatus:
    """Use the AI provider to extract structured patch status from advisory HTML.

    Retries once on timeout, then returns undetermined.
    """
    if not advisory.found or not advisory.advisory_html:
        return PatchStatus(
            cve_id=advisory.cve_id,
            status="undetermined",
            reason=advisory.error or "No advisory content available for analysis",
        )

    prompt = _ANALYSIS_PROMPT.format(
        cve_id=advisory.cve_id,
        advisory_html=advisory.advisory_html,
    )

    raw_response: str | None = None
    last_error: Exception | None = None

    for attempt in range(_MAX_RETRIES + 1):
        try:
            raw_response = await provider.analyze(prompt)
            break
        except TimeoutError as exc:
            last_error = exc
            logger.warning(
                "LLM timeout for %s (attempt %d/%d)",
                advisory.cve_id,
                attempt + 1,
                _MAX_RETRIES + 1,
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            logger.warning(
                "LLM error for %s (attempt %d/%d): %s",
                advisory.cve_id,
                attempt + 1,
                _MAX_RETRIES + 1,
                exc,
            )

    if raw_response is None:
        return PatchStatus(
            cve_id=advisory.cve_id,
            status="undetermined",
            reason=f"LLM API failure after {_MAX_RETRIES + 1} attempts: {last_error}",
        )

    return _parse_llm_response(advisory.cve_id, raw_response, advisory.advisory_url)


def _parse_llm_response(cve_id: str, raw: str, advisory_url: str | None = None) -> PatchStatus:
    """Parse the raw LLM JSON response into a PatchStatus."""
    cleaned = _strip_markdown_fences(raw).strip()

    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as exc:
        return PatchStatus(
            cve_id=cve_id,
            status="undetermined",
            reason=f"Unparseable LLM response: {exc}",
        )

    if not isinstance(data, dict):
        return PatchStatus(
            cve_id=cve_id,
            status="undetermined",
            reason="LLM response is not a JSON object",
        )

    status = data.get("status", "undetermined")
    valid_statuses = {"patched", "not_patched", "partially_patched", "undetermined"}
    if status not in valid_statuses:
        status = "undetermined"

    reason = data.get("reason")
    releases: dict[str, ReleaseStatus] = {}

    raw_releases = data.get("releases", {})
    if isinstance(raw_releases, dict):
        for release_name, release_data in raw_releases.items():
            if not isinstance(release_data, dict):
                continue
            releases[release_name] = _parse_release_status(
                release_name, release_data
            )

    # Override LLM-provided alas_url with the known-good URL from the fetcher
    if advisory_url:
        for rs in releases.values():
            rs.alas_url = advisory_url

    return PatchStatus(
        cve_id=cve_id,
        status=status,
        releases=releases,
        reason=reason,
        description=data.get("description"),
        impacted_components=[
            c for c in data.get("impacted_components", []) if isinstance(c, str)
        ],
    )


def _parse_release_status(name: str, data: dict) -> ReleaseStatus:
    """Parse a single release entry from the LLM response."""
    patched = data.get("patched")
    if not isinstance(patched, bool):
        patched = None

    packages: list[PackageInfo] = []
    for pkg in data.get("affected_packages", []):
        if isinstance(pkg, dict):
            packages.append(
                PackageInfo(
                    name=pkg.get("name", "unknown"),
                    affected_version=pkg.get("affected_version"),
                    fixed_version=pkg.get("fixed_version"),
                )
            )

    commands = [
        cmd for cmd in data.get("resolution_commands", []) if isinstance(cmd, str)
    ]

    alas_url = data.get("alas_url")
    if not isinstance(alas_url, str):
        alas_url = None

    return ReleaseStatus(
        release_name=name,
        patched=patched,
        affected_packages=packages,
        resolution_commands=commands,
        alas_url=alas_url,
    )


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences if the LLM wrapped its JSON in them."""
    stripped = text.strip()
    if stripped.startswith("```"):
        # Remove opening fence (possibly with language tag like ```json)
        first_newline = stripped.find("\n")
        if first_newline != -1:
            stripped = stripped[first_newline + 1 :]
    if stripped.endswith("```"):
        stripped = stripped[:-3]
    return stripped.strip()
