"""AI provider registry and implementations."""

from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

import boto3
import httpx
from openai import AsyncOpenAI

from cveintel.core.exceptions import ConfigError
from cveintel.core.models import AppConfig

SUPPORTED_PROVIDERS = ("openai", "bedrock", "local")


@runtime_checkable
class AIProvider(Protocol):
    """Protocol for AI analysis backends."""

    async def analyze(self, prompt: str) -> str:
        """Send a prompt and return the LLM response text."""
        ...


class APIKeyProvider:
    """OpenAI-compatible API provider using a user-supplied key."""

    def __init__(self, api_key: str, model: str | None = None) -> None:
        self._client = AsyncOpenAI(api_key=api_key)
        self._model = model or "openai.gpt-oss-120b-1:0"

    async def analyze(self, prompt: str) -> str:
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""


class BedrockProvider:
    """AWS Bedrock provider using configured AWS credentials."""

    def __init__(self, model_id: str | None = None, region: str = "us-east-1") -> None:
        self._model_id = model_id or "anthropic.claude-sonnet-4-6"
        self._client = boto3.client("bedrock-runtime", region_name=region)

    async def analyze(self, prompt: str) -> str:
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            }
        )
        response = self._client.invoke_model(
            modelId=self._model_id,
            contentType="application/json",
            accept="application/json",
            body=body,
        )
        result = json.loads(response["body"].read())
        return result.get("content", [{}])[0].get("text", "")


class LocalLLMProvider:
    """Local LLM provider connecting to a user-specified HTTP endpoint."""

    def __init__(self, endpoint: str, model: str | None = None) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._model = model

    async def analyze(self, prompt: str) -> str:
        payload: dict = {"prompt": prompt}
        if self._model:
            payload["model"] = self._model
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self._endpoint}/v1/completions",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        # Support both OpenAI-compatible and simple {text: ...} responses
        if "choices" in data:
            return data["choices"][0].get("text", "")
        return data.get("text", data.get("response", ""))


def get_provider(config: AppConfig) -> AIProvider:
    """Return the configured AI provider instance.

    Raises:
        ConfigError: When no provider is configured or required credentials are missing.
    """
    provider = config.ai_provider

    if provider == "openai":
        if not config.api_key:
            raise ConfigError(
                "Missing CVEINTEL_API_KEY. An API key is required for the OpenAI provider."
            )
        return APIKeyProvider(api_key=config.api_key, model=config.model)

    if provider == "bedrock":
        return BedrockProvider(
            model_id=config.bedrock_model_id, region=config.aws_region
        )

    if provider == "local":
        if not config.local_endpoint:
            raise ConfigError(
                "Missing CVEINTEL_LOCAL_ENDPOINT. A local endpoint URL is required "
                "for the local LLM provider."
            )
        return LocalLLMProvider(endpoint=config.local_endpoint, model=config.model)

    raise ConfigError(
        f"Unsupported AI provider '{provider}'. "
        f"Supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
    )
