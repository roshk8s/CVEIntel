"""Security Data Fetcher — retrieves ALAS advisory data for CVEs.

Strategy:
1. Search the ALAS index pages (AL2023, AL2, AL1) for the target CVE ID.
2. Extract the advisory link from the matching table row.
3. Fetch the full advisory page HTML for downstream LLM analysis.

URL layout (as of 2026):
- Index pages:  https://alas.aws.amazon.com/alas2023.html
                https://alas.aws.amazon.com/alas2.html
                https://alas.aws.amazon.com/alas.html
- Advisory:     https://alas.aws.amazon.com/AL2023/ALAS2023-2026-1532.html
                https://alas.aws.amazon.com/AL2/ALAS2ECS-2026-100.html
- CVE explore:  https://explore.alas.aws.amazon.com/CVE-2026-26308.html
"""

from __future__ import annotations

import asyncio
import re

import httpx

from cveintel.core.models import AdvisoryResult

ALAS_BASE_URL = "https://alas.aws.amazon.com"

# Index pages to search, in order.  Each tuple is (index_url, label).
ALAS_INDEX_PAGES: list[tuple[str, str]] = [
    (f"{ALAS_BASE_URL}/alas2023.html", "Amazon Linux 2023"),
    (f"{ALAS_BASE_URL}/alas2.html", "Amazon Linux 2"),
    (f"{ALAS_BASE_URL}/alas.html", "Amazon Linux 1"),
]

# Regex to find advisory links in an index page table row.
# Captures the relative href, e.g. "AL2023/ALAS2023-2026-1532.html"
_ADVISORY_HREF_RE = re.compile(
    r"""href=['"]([^'"]*?ALAS[^'"]*?\.html)['"]"""
)

# Extract the ALAS ID from a path like AL2023/ALAS2023-2026-1532.html
_ALAS_ID_RE = re.compile(r"(ALAS\S*-\d{4}-\d+)")

_DEFAULT_TIMEOUT = 30.0
_MAX_CONCURRENCY = 10


async def fetch_advisory(
    cve_id: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> AdvisoryResult:
    """Query the Amazon Linux Security Center for a single CVE.

    Searches each ALAS index page for the CVE, fetches the first matching
    advisory page, and returns its HTML.  Returns ``found=False`` when no
    advisory exists.  HTTP/connectivity errors are captured in ``error``.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT)

    try:
        return await _fetch_single(client, cve_id)
    finally:
        if own_client:
            await client.aclose()


async def fetch_advisories(
    cve_ids: list[str],
    *,
    client: httpx.AsyncClient | None = None,
) -> list[AdvisoryResult]:
    """Fetch advisories for multiple CVEs concurrently.

    Limits concurrency to ``_MAX_CONCURRENCY`` parallel requests.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT)

    semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)

    async def _bounded(cve_id: str) -> AdvisoryResult:
        async with semaphore:
            return await _fetch_single(client, cve_id)

    try:
        return list(await asyncio.gather(*[_bounded(cid) for cid in cve_ids]))
    finally:
        if own_client:
            await client.aclose()


# ── internal helpers ────────────────────────────────────────────────


async def _fetch_single(
    client: httpx.AsyncClient,
    cve_id: str,
) -> AdvisoryResult:
    """Search ALAS index pages for *cve_id*, then fetch the advisory page."""

    errors: list[str] = []

    for index_url, _label in ALAS_INDEX_PAGES:
        result = await _search_index(client, index_url, cve_id)
        if result is None:
            # CVE not mentioned on this index — try the next one.
            continue
        if result.found:
            return result
        if result.error:
            # Index page had an error; record it but keep trying others.
            errors.append(result.error)
            continue
        # result.found is False with no error — shouldn't happen from
        # _search_index, but treat as "not found on this page".
        continue

    # No advisory found on any accessible index page.
    if errors:
        return AdvisoryResult(
            cve_id=cve_id,
            found=False,
            error="; ".join(errors),
        )
    return AdvisoryResult(cve_id=cve_id, found=False)


async def _search_index(
    client: httpx.AsyncClient,
    index_url: str,
    cve_id: str,
) -> AdvisoryResult | None:
    """Search a single ALAS index page for *cve_id*.

    Returns ``None`` if the CVE is not mentioned on this index page so the
    caller can try the next one.  Returns an ``AdvisoryResult`` (possibly
    with ``error``) if the CVE was found or a network error occurred.
    """
    try:
        resp = await client.get(index_url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return AdvisoryResult(
            cve_id=cve_id,
            found=False,
            error=f"HTTP error fetching index {index_url}: {exc}",
        )

    if resp.status_code != 200:
        return AdvisoryResult(
            cve_id=cve_id,
            found=False,
            error=f"Unexpected status {resp.status_code} from {index_url}",
        )

    advisory_href = _find_advisory_href(resp.text, cve_id)
    if advisory_href is None:
        return None  # CVE not on this index page

    # Build the full advisory URL.
    advisory_url = f"{ALAS_BASE_URL}/{advisory_href}"
    alas_id_match = _ALAS_ID_RE.search(advisory_href)
    alas_id = alas_id_match.group(1) if alas_id_match else None

    return await _fetch_advisory_page(client, cve_id, advisory_url, alas_id)


def _find_advisory_href(index_html: str, cve_id: str) -> str | None:
    """Find the advisory href in the index HTML that is associated with *cve_id*.

    The index page is a large HTML table.  Each ``<tr>`` contains an advisory
    link and one or more CVE references.  We locate the ``<tr>`` that mentions
    the CVE and extract the advisory href from it.
    """
    # Split into table rows and find the one containing our CVE.
    rows = re.split(r"<tr\b", index_html, flags=re.IGNORECASE)
    for row in rows:
        if cve_id not in row:
            continue
        href_match = _ADVISORY_HREF_RE.search(row)
        if href_match:
            return href_match.group(1)
    return None


async def _fetch_advisory_page(
    client: httpx.AsyncClient,
    cve_id: str,
    advisory_url: str,
    alas_id: str | None,
) -> AdvisoryResult:
    """Fetch the full advisory page and return the result."""
    try:
        resp = await client.get(advisory_url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return AdvisoryResult(
            cve_id=cve_id,
            found=False,
            error=f"HTTP error fetching advisory {advisory_url}: {exc}",
        )

    if resp.status_code != 200:
        return AdvisoryResult(
            cve_id=cve_id,
            found=False,
            error=f"Unexpected status {resp.status_code} from {advisory_url}",
        )

    return AdvisoryResult(
        cve_id=cve_id,
        found=True,
        alas_id=alas_id,
        advisory_url=advisory_url,
        advisory_html=resp.text,
    )
