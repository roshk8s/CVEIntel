"""Configuration loader for CVEIntel."""

from __future__ import annotations

import os

from dotenv import load_dotenv

from cveintel.core.exceptions import ConfigError
from cveintel.core.models import AppConfig

SUPPORTED_PROVIDERS = ("openai", "bedrock", "local")


def load_config(provider_override: str | None = None) -> AppConfig:
    """Load AppConfig from environment variables with .env fallback.

    Args:
        provider_override: Optional provider name from CLI flag.

    Returns:
        Populated AppConfig instance.

    Raises:
        ConfigError: When required configuration is missing.
    """
    load_dotenv()

    provider = provider_override or os.getenv("CVEINTEL_PROVIDER")
    if not provider:
        raise ConfigError(
            "No AI provider configured. Set CVEINTEL_PROVIDER to one of: "
            + ", ".join(SUPPORTED_PROVIDERS)
        )

    provider = provider.lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise ConfigError(
            f"Unsupported AI provider '{provider}'. "
            f"Supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
        )

    api_key = os.getenv("CVEINTEL_API_KEY")
    model = os.getenv("CVEINTEL_MODEL")
    local_endpoint = os.getenv("CVEINTEL_LOCAL_ENDPOINT")
    aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    if provider == "openai" and not api_key:
        raise ConfigError(
            "Missing CVEINTEL_API_KEY. An API key is required for the OpenAI provider."
        )

    if provider == "local" and not local_endpoint:
        raise ConfigError(
            "Missing CVEINTEL_LOCAL_ENDPOINT. A local endpoint URL is required "
            "for the local LLM provider."
        )

    return AppConfig(
        ai_provider=provider,  # type: ignore[arg-type]
        api_key=api_key,
        model=model,
        bedrock_model_id=model if provider == "bedrock" else None,
        local_endpoint=local_endpoint,
        aws_region=aws_region,
    )
