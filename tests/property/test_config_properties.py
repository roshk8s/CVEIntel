# Feature: cveintel, Property 6: AI provider configuration selects the correct provider
"""Property test: get_provider returns the correct provider class for each config.

Validates: Requirements 5.1
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from cveintel.core.ai_provider import (
    APIKeyProvider,
    BedrockProvider,
    LocalLLMProvider,
    get_provider,
)
from cveintel.core.models import AppConfig

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_non_empty_text = st.text(
    min_size=1,
    max_size=50,
    alphabet=st.characters(
        categories=("L", "N", "P"),
        exclude_characters="\x00",
    ),
)

_http_endpoint = st.builds(
    lambda host, port: f"http://{host}:{port}",
    host=st.just("localhost"),
    port=st.integers(min_value=1024, max_value=65535),
)

_aws_region = st.sampled_from(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"])


def _openai_config() -> st.SearchStrategy[AppConfig]:
    return st.builds(
        AppConfig,
        ai_provider=st.just("openai"),
        api_key=_non_empty_text,
        model=st.one_of(st.none(), _non_empty_text),
        aws_region=_aws_region,
    )


def _bedrock_config() -> st.SearchStrategy[AppConfig]:
    return st.builds(
        AppConfig,
        ai_provider=st.just("bedrock"),
        bedrock_model_id=st.one_of(st.none(), _non_empty_text),
        aws_region=_aws_region,
    )


def _local_config() -> st.SearchStrategy[AppConfig]:
    return st.builds(
        AppConfig,
        ai_provider=st.just("local"),
        local_endpoint=_http_endpoint,
        model=st.one_of(st.none(), _non_empty_text),
        aws_region=_aws_region,
    )


_valid_config = st.one_of(_openai_config(), _bedrock_config(), _local_config())

# Mapping from provider name to expected class
_EXPECTED_CLASS = {
    "openai": APIKeyProvider,
    "bedrock": BedrockProvider,
    "local": LocalLLMProvider,
}


# ---------------------------------------------------------------------------
# Property 6: For any valid config, get_provider returns the matching class.
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(config=_valid_config)
def test_provider_config_selects_correct_class(config: AppConfig) -> None:
    provider = get_provider(config)
    expected_cls = _EXPECTED_CLASS[config.ai_provider]
    assert isinstance(provider, expected_cls), (
        f"Expected {expected_cls.__name__} for provider '{config.ai_provider}', "
        f"got {type(provider).__name__}"
    )
