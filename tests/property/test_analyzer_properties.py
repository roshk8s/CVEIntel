# Feature: cveintel, Property 5: LLM response parsing extracts all structured fields
"""Property test: _parse_llm_response produces a PatchStatus with all structured fields
from any well-formed LLM JSON response.

Validates: Requirements 4.1, 4.2, 4.3
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from cveintel.core.analyzer import _parse_llm_response
from cveintel.core.models import PatchStatus

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_valid_statuses = st.sampled_from(["patched", "not_patched", "partially_patched", "undetermined"])

_package_strategy = st.fixed_dictionaries(
    {
        "name": st.from_regex(r"[a-z][a-z0-9\-]{0,20}", fullmatch=True),
        "affected_version": st.one_of(st.none(), st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True)),
        "fixed_version": st.one_of(st.none(), st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True)),
    }
)

_release_name = st.sampled_from(["AL2023", "AL2", "AL1"])

_resolution_cmd = st.from_regex(r"yum update [a-z][a-z0-9\-]{0,15}", fullmatch=True)

_release_strategy = st.fixed_dictionaries(
    {
        "patched": st.one_of(st.just(True), st.just(False)),
        "affected_packages": st.lists(_package_strategy, min_size=1, max_size=4),
        "resolution_commands": st.lists(_resolution_cmd, min_size=0, max_size=3),
        "alas_url": st.one_of(st.none(), st.just("https://alas.aws.amazon.com/ALAS-2024-001.html")),
    }
)

_releases_strategy = st.dictionaries(
    keys=_release_name,
    values=_release_strategy,
    min_size=1,
    max_size=3,
)


def _build_llm_json(status, reason, releases):
    """Build a well-formed LLM JSON response dict."""
    return {
        "status": status,
        "reason": reason,
        "description": "A test vulnerability description.",
        "impacted_components": ["openssl"],
        "releases": releases,
    }


_well_formed_response = st.builds(
    _build_llm_json,
    status=_valid_statuses,
    reason=st.one_of(st.none(), st.text(min_size=1, max_size=30, alphabet="abcdefghijklmnopqrstuvwxyz ")),
    releases=_releases_strategy,
)

_cve_id_strategy = st.from_regex(r"CVE-\d{4}-\d{4,7}", fullmatch=True)


# ---------------------------------------------------------------------------
# Property 5-a: For any well-formed LLM response, _parse_llm_response
# produces a PatchStatus with a valid status enum value.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cve_id=_cve_id_strategy, response_data=_well_formed_response)
def test_llm_parsing_produces_valid_status(cve_id: str, response_data: dict) -> None:
    raw_json = json.dumps(response_data)
    result = _parse_llm_response(cve_id, raw_json)

    assert isinstance(result, PatchStatus)
    assert result.cve_id == cve_id
    assert result.status in {"patched", "not_patched", "partially_patched", "undetermined"}
    assert result.status == response_data["status"]


# ---------------------------------------------------------------------------
# Property 5-b: Every release in the LLM response appears in the PatchStatus
# with affected_packages containing name and version info.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cve_id=_cve_id_strategy, response_data=_well_formed_response)
def test_llm_parsing_extracts_all_releases_and_packages(cve_id: str, response_data: dict) -> None:
    raw_json = json.dumps(response_data)
    result = _parse_llm_response(cve_id, raw_json)

    expected_releases = response_data["releases"]
    assert set(result.releases.keys()) == set(expected_releases.keys()), (
        f"Expected releases {set(expected_releases.keys())}, got {set(result.releases.keys())}"
    )

    for release_name, expected in expected_releases.items():
        rs = result.releases[release_name]
        assert rs.release_name == release_name
        assert isinstance(rs.patched, bool)
        assert len(rs.affected_packages) == len(expected["affected_packages"])
        for pkg in rs.affected_packages:
            assert pkg.name, "Package name must be non-empty"


# ---------------------------------------------------------------------------
# Property 5-c: Resolution commands are preserved from the LLM response.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cve_id=_cve_id_strategy, response_data=_well_formed_response)
def test_llm_parsing_preserves_resolution_commands(cve_id: str, response_data: dict) -> None:
    raw_json = json.dumps(response_data)
    result = _parse_llm_response(cve_id, raw_json)

    for release_name, expected in response_data["releases"].items():
        rs = result.releases[release_name]
        assert rs.resolution_commands == expected["resolution_commands"], (
            f"Resolution commands mismatch for {release_name}"
        )
