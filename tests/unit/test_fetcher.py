"""Unit tests for the Security Data Fetcher module.

Covers:
- Successful advisory retrieval (mocked HTTP)
- HTTP error handling and connectivity failure
- CVE with no advisory found
Requirements: 3.1, 3.2, 3.3, 3.4
"""

from __future__ import annotations

import httpx

from cveintel.core.fetcher import (
    ALAS_BASE_URL,
    fetch_advisories,
    fetch_advisory,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _index_html_with_cve(cve_id: str, alas_id: str = "ALAS2023-2026-999") -> str:
    """Return minimal ALAS index HTML containing a row for *cve_id*."""
    href = f"AL2023/{alas_id}.html"
    return (
        "<html><body><table>"
        f'<tr><td><a href="{href}">{alas_id}</a></td>'
        f"<td>{cve_id}</td></tr>"
        "</table></body></html>"
    )


ADVISORY_PAGE_HTML = "<html><body><h1>Advisory Details</h1><p>Patch info here</p></body></html>"

EMPTY_INDEX_HTML = "<html><body><table><tr><td>No advisories</td></tr></table></body></html>"


# ── Successful retrieval ─────────────────────────────────────────────

async def test_fetch_advisory_found():
    """Req 3.1, 3.2: Advisory found on first index page and detail page fetched."""
    cve_id = "CVE-2026-12345"
    alas_id = "ALAS2023-2026-999"

    index_html = _index_html_with_cve(cve_id, alas_id)
    advisory_url = f"{ALAS_BASE_URL}/AL2023/{alas_id}.html"

    async def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "alas2023.html" in url:
            return httpx.Response(200, text=index_html)
        if alas_id in url:
            return httpx.Response(200, text=ADVISORY_PAGE_HTML)
        # Other index pages — empty
        return httpx.Response(200, text=EMPTY_INDEX_HTML)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is True
    assert result.cve_id == cve_id
    assert result.alas_id == alas_id
    assert result.advisory_url == advisory_url
    assert result.advisory_html == ADVISORY_PAGE_HTML
    assert result.error is None


async def test_fetch_advisory_found_on_second_index():
    """Req 3.1, 3.2: CVE not on first index but found on AL2 index."""
    cve_id = "CVE-2025-99999"
    alas_id = "ALAS2-2025-1234"
    al2_index_html = (
        "<html><body><table>"
        f'<tr><td><a href="AL2/{alas_id}.html">{alas_id}</a></td>'
        f"<td>{cve_id}</td></tr>"
        "</table></body></html>"
    )

    async def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "alas2023.html" in url:
            return httpx.Response(200, text=EMPTY_INDEX_HTML)
        if "alas2.html" in url:
            return httpx.Response(200, text=al2_index_html)
        if alas_id in url:
            return httpx.Response(200, text=ADVISORY_PAGE_HTML)
        return httpx.Response(200, text=EMPTY_INDEX_HTML)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is True
    assert result.cve_id == cve_id
    assert result.alas_id == alas_id
    assert result.advisory_html == ADVISORY_PAGE_HTML


# ── No advisory found ────────────────────────────────────────────────

async def test_fetch_advisory_not_found():
    """Req 3.4: No advisory exists for the CVE on any index page."""
    cve_id = "CVE-2026-00001"

    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=EMPTY_INDEX_HTML)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is False
    assert result.cve_id == cve_id
    assert result.error is None
    assert result.advisory_html is None


# ── HTTP error handling ──────────────────────────────────────────────

async def test_fetch_advisory_index_http_error():
    """Req 3.3: All index pages return HTTP errors."""
    cve_id = "CVE-2026-55555"

    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is False
    assert result.cve_id == cve_id
    assert result.error is not None
    assert "500" in result.error


async def test_fetch_advisory_connectivity_failure():
    """Req 3.3: Network connectivity failure raises an HTTP error."""
    cve_id = "CVE-2026-77777"

    async def _handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is False
    assert result.cve_id == cve_id
    assert result.error is not None
    assert "HTTP error" in result.error


async def test_fetch_advisory_advisory_page_error():
    """Req 3.3: Index page works but advisory detail page returns 404."""
    cve_id = "CVE-2026-44444"
    alas_id = "ALAS2023-2026-500"
    index_html = _index_html_with_cve(cve_id, alas_id)

    async def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "alas2023.html" in url:
            return httpx.Response(200, text=index_html)
        if alas_id in url:
            return httpx.Response(404, text="Not Found")
        return httpx.Response(200, text=EMPTY_INDEX_HTML)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_advisory(cve_id, client=client)

    assert result.found is False
    assert result.cve_id == cve_id
    assert result.error is not None
    assert "404" in result.error


# ── Concurrent fetching ──────────────────────────────────────────────

async def test_fetch_advisories_multiple():
    """Req 3.1: Concurrent fetching returns results for all CVEs."""
    cve_found = "CVE-2026-11111"
    cve_missing = "CVE-2026-22222"
    alas_id = "ALAS2023-2026-100"
    index_html = _index_html_with_cve(cve_found, alas_id)

    async def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "alas2023.html" in url:
            return httpx.Response(200, text=index_html)
        if alas_id in url:
            return httpx.Response(200, text=ADVISORY_PAGE_HTML)
        return httpx.Response(200, text=EMPTY_INDEX_HTML)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await fetch_advisories([cve_found, cve_missing], client=client)

    assert len(results) == 2
    found_result = next(r for r in results if r.cve_id == cve_found)
    missing_result = next(r for r in results if r.cve_id == cve_missing)

    assert found_result.found is True
    assert found_result.alas_id == alas_id

    assert missing_result.found is False
    assert missing_result.error is None
