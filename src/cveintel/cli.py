"""CVEIntel CLI — click-based command-line interface.

Usage examples::

    cveintel check CVE-2023-12345
    cveintel check CVE-2023-12345 CVE-2024-9999
    cveintel check CVE-2023-12345,CVE-2024-9999
    cveintel check --file cves.csv
    cveintel check --ecr arn:aws:ecr:us-east-1:123456789012:repository/myapp:latest
    cveintel check CVE-2023-12345 --audience business --format json --output report.json
    cveintel check CVE-2023-12345 --s3 s3://my-bucket/reports/report.json
"""

from __future__ import annotations

import asyncio
import sys

import click

import cveintel
from cveintel.core.ai_provider import get_provider
from cveintel.core.analyzer import analyze_advisory
from cveintel.core.config import load_config
from cveintel.core.ecr_scanner import fetch_ecr_scan_findings
from cveintel.core.exceptions import CVEIntelError
from cveintel.core.fetcher import fetch_advisories
from cveintel.core.input_parser import parse_cve_args, parse_cve_file
from cveintel.core.models import PatchStatus
from cveintel.core.output_handler import (
    render_json,
    render_plain_text,
    render_terminal,
    upload_to_s3,
    write_to_file,
)
from cveintel.core.report_generator import (
    generate_business_report,
    generate_consolidated_report,
    generate_developer_report,
)


@click.group()
@click.version_option(version=cveintel.__version__, prog_name="cveintel")
def main() -> None:
    """CVEIntel — determine CVE patch status across Amazon Linux releases."""


@main.command()
@click.argument("cves", nargs=-1)
@click.option(
    "--file", "-f", "file_path", type=click.Path(), default=None,
    help="Path to a file containing CVE identifiers (CSV or one-per-line).",
)
@click.option(
    "--ecr", "ecr_arn", default=None,
    help="ECR image URI or ARN to fetch scan findings from.",
)
@click.option(
    "--audience", type=click.Choice(["developer", "business", "both"]),
    default="developer", show_default=True,
    help="Target audience for the report.",
)
@click.option(
    "--output", "-o", "output_path", type=click.Path(), default=None,
    help="Write report to a file instead of the terminal.",
)
@click.option(
    "--format", "fmt", type=click.Choice(["json", "text"]),
    default="text", show_default=True,
    help="Output format when writing to a file or S3.",
)
@click.option(
    "--s3", "s3_uri", default=None,
    help="S3 destination URI (s3://bucket/key).",
)
@click.option(
    "--provider", type=click.Choice(["openai", "bedrock", "local"]),
    default=None,
    help="Override the AI provider (default: from CVEINTEL_PROVIDER env var).",
)
def check(
    cves: tuple[str, ...],
    file_path: str | None,
    ecr_arn: str | None,
    audience: str,
    output_path: str | None,
    fmt: str,
    s3_uri: str | None,
    provider: str | None,
) -> None:
    """Check CVE patch status across Amazon Linux releases.

    \b
    Examples:
      cveintel check CVE-2023-12345
      cveintel check CVE-2023-12345 CVE-2024-9999
      cveintel check --file cves.csv --audience both
      cveintel check --ecr 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
      cveintel check CVE-2023-12345 --format json -o report.json
      cveintel check CVE-2023-12345 --s3 s3://bucket/report.json
    """
    try:
        asyncio.run(_run_check(
            cves=cves,
            file_path=file_path,
            ecr_arn=ecr_arn,
            audience=audience,
            output_path=output_path,
            fmt=fmt,
            s3_uri=s3_uri,
            provider=provider,
        ))
    except CVEIntelError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


async def _run_check(
    *,
    cves: tuple[str, ...],
    file_path: str | None,
    ecr_arn: str | None,
    audience: str,
    output_path: str | None,
    fmt: str,
    s3_uri: str | None,
    provider: str | None,
) -> None:
    """Core async pipeline: parse → fetch → analyze → report → output."""

    # ── 1. Collect CVE identifiers ──────────────────────────────────
    cve_ids: list[str] = []
    warnings: list[str] = []

    if cves:
        cve_ids.extend(parse_cve_args(list(cves)))

    if file_path:
        file_cves, file_warnings = parse_cve_file(file_path)
        cve_ids.extend(file_cves)
        warnings.extend(file_warnings)

    if ecr_arn:
        ecr_result = await fetch_ecr_scan_findings(ecr_arn)
        if ecr_result.error:
            click.echo(f"ECR scan error: {ecr_result.error}", err=True)
        if ecr_result.cve_ids:
            cve_ids.extend(ecr_result.cve_ids)
        elif not ecr_result.error:
            click.echo("No CVEs found in ECR scan results.", err=True)

    if not cve_ids:
        raise CVEIntelError(
            "No CVE identifiers provided. Supply CVEs as arguments, "
            "via --file, or via --ecr."
        )

    # Print file-parsing warnings
    for w in warnings:
        click.echo(f"Warning: skipping invalid entry '{w}'", err=True)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_cves: list[str] = []
    for cid in cve_ids:
        if cid not in seen:
            seen.add(cid)
            unique_cves.append(cid)

    click.echo(f"Processing {len(unique_cves)} CVE(s)...", err=True)

    # ── 2. Load config and AI provider ──────────────────────────────
    config = load_config(provider_override=provider)
    ai_provider = get_provider(config)

    # ── 3. Fetch advisories ─────────────────────────────────────────
    advisories = await fetch_advisories(unique_cves)

    # ── 4. Analyze each advisory ────────────────────────────────────
    statuses: list[PatchStatus] = []
    for adv in advisories:
        status = await analyze_advisory(adv, ai_provider)
        statuses.append(status)

    # ── 5. Generate report ──────────────────────────────────────────
    if audience == "business":
        report = generate_business_report(statuses)
    elif audience == "both":
        report = generate_consolidated_report(statuses)
    else:
        report = generate_developer_report(statuses)

    # ── 6. Render and output ────────────────────────────────────────
    if output_path or s3_uri:
        rendered = render_json(report) if fmt == "json" else render_plain_text(report)
    else:
        rendered = render_terminal(report)

    if output_path:
        write_to_file(rendered, output_path)
        click.echo(f"Report written to {output_path}", err=True)

    if s3_uri:
        bucket, key = _parse_s3_uri(s3_uri)
        await upload_to_s3(rendered, bucket, key)
        click.echo(f"Report uploaded to {s3_uri}", err=True)

    if not output_path and not s3_uri:
        click.echo(rendered)


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    """Parse an s3://bucket/key URI into (bucket, key)."""
    if not uri.startswith("s3://"):
        raise CVEIntelError(f"Invalid S3 URI '{uri}'. Expected format: s3://bucket/key")
    path = uri[5:]
    if "/" not in path:
        raise CVEIntelError(
            f"Invalid S3 URI '{uri}'. Must include a key: s3://bucket/key"
        )
    bucket, key = path.split("/", 1)
    if not bucket or not key:
        raise CVEIntelError(
            f"Invalid S3 URI '{uri}'. Bucket and key must not be empty."
        )
    return bucket, key
