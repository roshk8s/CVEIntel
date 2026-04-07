# Feature: cveintel, Property 1: CVE validation accepts exactly valid formats
"""Property test: validate_cve accepts exactly strings matching CVE-YYYY-NNNNN+.

Validates: Requirements 1.1, 1.2
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from cveintel.core.input_parser import validate_cve, parse_cve_args

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ---------------------------------------------------------------------------
# Strategy: generate strings that ARE valid CVE identifiers
# ---------------------------------------------------------------------------
_valid_cve_strategy = st.from_regex(CVE_REGEX, fullmatch=True)


# ---------------------------------------------------------------------------
# Strategy: generate arbitrary text (overwhelmingly unlikely to be valid)
# ---------------------------------------------------------------------------
_arbitrary_text = st.text(
    min_size=0,
    max_size=40,
    alphabet=st.characters(exclude_categories=("Cs",)),
)


# ---------------------------------------------------------------------------
# Property 1-a: validate_cve returns True for every valid CVE string.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cve=_valid_cve_strategy)
def test_validate_cve_accepts_valid_format(cve: str) -> None:
    assert validate_cve(cve) is True, f"validate_cve should accept '{cve}'"


# ---------------------------------------------------------------------------
# Property 1-b: validate_cve returns False for every string that does NOT
# match the CVE regex.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(s=_arbitrary_text.filter(lambda s: not CVE_REGEX.match(s)))
def test_validate_cve_rejects_invalid_format(s: str) -> None:
    assert validate_cve(s) is False, f"validate_cve should reject '{s}'"


# ---------------------------------------------------------------------------
# Property 1-c: parse_cve_args returns exactly the valid CVE identifiers
# from a list of valid inputs.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cves=st.lists(_valid_cve_strategy, min_size=1, max_size=10))
def test_parse_cve_args_returns_all_valid(cves: list[str]) -> None:
    result = parse_cve_args(cves)
    assert result == cves, (
        f"parse_cve_args should return all valid CVEs unchanged; "
        f"expected {cves}, got {result}"
    )


# ---------------------------------------------------------------------------
# Property 1-d: parse_cve_args also works when valid CVEs are
# comma-separated within a single argument string.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(cves=st.lists(_valid_cve_strategy, min_size=2, max_size=6))
def test_parse_cve_args_handles_comma_separated(cves: list[str]) -> None:
    combined = ",".join(cves)
    result = parse_cve_args([combined])
    assert result == cves, (
        f"parse_cve_args should split comma-separated CVEs; "
        f"expected {cves}, got {result}"
    )
