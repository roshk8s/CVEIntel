# Feature: cveintel, Property 16: ECR ARN validation accepts exactly valid formats
"""Property test: validate_ecr_arn accepts exactly strings matching the ECR ARN pattern.

Validates: Requirements 15.4
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from cveintel.core.ecr_scanner import validate_ecr_arn

ECR_ARN_REGEX = re.compile(
    r"^arn:aws:ecr:[a-z0-9-]+:\d{12}:repository/[\w./-]+"
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Build valid ECR ARNs from components
_region = st.from_regex(r"[a-z][a-z0-9-]{2,20}", fullmatch=True)
_account_id = st.from_regex(r"\d{12}", fullmatch=True)
_repo_name = st.from_regex(r"[\w][\w./-]{0,30}", fullmatch=True)

_valid_ecr_arn = st.builds(
    lambda r, a, repo: f"arn:aws:ecr:{r}:{a}:repository/{repo}",
    r=_region,
    a=_account_id,
    repo=_repo_name,
)

_arbitrary_text = st.text(
    min_size=0,
    max_size=80,
    alphabet=st.characters(exclude_categories=("Cs",)),
)


# ---------------------------------------------------------------------------
# Property 16-a: validate_ecr_arn returns True for every valid ECR ARN.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(arn=_valid_ecr_arn)
def test_validate_ecr_arn_accepts_valid_format(arn: str) -> None:
    assert validate_ecr_arn(arn) is True, f"validate_ecr_arn should accept '{arn}'"


# ---------------------------------------------------------------------------
# Property 16-b: validate_ecr_arn returns False for every string that does
# NOT match the ECR ARN regex.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(s=_arbitrary_text.filter(lambda s: not ECR_ARN_REGEX.match(s)))
def test_validate_ecr_arn_rejects_invalid_format(s: str) -> None:
    assert validate_ecr_arn(s) is False, f"validate_ecr_arn should reject '{s}'"


# ---------------------------------------------------------------------------
# Property 16-c: validate_ecr_arn agrees with the reference regex for all
# generated strings (both valid and arbitrary).
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(s=st.one_of(_valid_ecr_arn, _arbitrary_text))
def test_validate_ecr_arn_matches_reference_regex(s: str) -> None:
    expected = bool(ECR_ARN_REGEX.match(s))
    actual = validate_ecr_arn(s)
    assert actual == expected, (
        f"validate_ecr_arn('{s}') returned {actual}, "
        f"but reference regex says {expected}"
    )
