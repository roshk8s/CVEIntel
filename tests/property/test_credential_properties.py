# Feature: cveintel, Property 14: Missing credential error identifies the missing variable
"""Property test: missing credential errors name the specific missing variable.

Validates: Requirements 12.4
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cveintel.core.config import load_config
from cveintel.core.exceptions import ConfigError

# Env vars that load_config may read
_ALL_VARS = (
    "CVEINTEL_PROVIDER",
    "CVEINTEL_API_KEY",
    "CVEINTEL_MODEL",
    "CVEINTEL_LOCAL_ENDPOINT",
    "AWS_DEFAULT_REGION",
)

# Provider -> (env var that must be set, substring expected in error)
PROVIDER_REQUIRED_VARS: dict[str, tuple[str, str]] = {
    "openai": ("CVEINTEL_API_KEY", "CVEINTEL_API_KEY"),
    "local": ("CVEINTEL_LOCAL_ENDPOINT", "CVEINTEL_LOCAL_ENDPOINT"),
}


@contextmanager
def _clean_env() -> Iterator[None]:
    """Temporarily remove all CVEIntel env vars, restoring them on exit.

    Also patches ``load_dotenv`` so the .env file does not interfere.
    """
    saved = {k: os.environ.pop(k) for k in _ALL_VARS if k in os.environ}
    try:
        from unittest.mock import patch
        with patch("cveintel.core.config.load_dotenv"):
            yield
    finally:
        # Remove anything the test may have set
        for k in _ALL_VARS:
            os.environ.pop(k, None)
        # Restore originals
        os.environ.update(saved)


# ---------------------------------------------------------------------------
# Property 14-a: When no provider is configured, the error names
# CVEINTEL_PROVIDER.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(extra_key=st.text(min_size=0, max_size=20, alphabet=st.characters(exclude_characters="\x00", exclude_categories=("Cs",))))
def test_missing_provider_error_names_variable(extra_key: str) -> None:
    with _clean_env():
        os.environ["CVEINTEL_MODEL"] = extra_key  # noise

        with pytest.raises(ConfigError) as exc_info:
            load_config()

        error_msg = str(exc_info.value)
        assert "CVEINTEL_PROVIDER" in error_msg, (
            f"Error should name CVEINTEL_PROVIDER but got: {error_msg}"
        )


# ---------------------------------------------------------------------------
# Property 14-b: For each provider that requires a specific credential,
# omitting that credential produces an error naming the missing variable.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(provider=st.sampled_from(list(PROVIDER_REQUIRED_VARS.keys())))
def test_missing_credential_error_names_variable(provider: str) -> None:
    with _clean_env():
        os.environ["CVEINTEL_PROVIDER"] = provider
        # Deliberately do NOT set the required credential

        env_var, expected_substring = PROVIDER_REQUIRED_VARS[provider]

        with pytest.raises(ConfigError) as exc_info:
            load_config()

        error_msg = str(exc_info.value)
        assert expected_substring in error_msg, (
            f"Error for provider '{provider}' should mention "
            f"'{expected_substring}' but got: {error_msg}"
        )
