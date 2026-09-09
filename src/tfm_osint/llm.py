"""Fábrica de LLM intercambiable: Claude (API directa o vía Bedrock) u Ollama (local).

Los tres proveedores devuelven un ``BaseChatModel`` de LangChain que soporta ``bind_tools``,
de modo que el resto del sistema (grafo, nodos) no depende del proveedor concreto.
"""

from __future__ import annotations

import os

from langchain_core.language_models import BaseChatModel

from tfm_osint.config import get_settings

# Precios de referencia (USD por millón de tokens) para estimar coste en la evaluación.
# Bedrock (Claude Haiku 4.5, Amazon Nova Pro): tarifa "Geo and in-region cross-region
# inference" de eu-north-1, la región donde corren estos modelos en este proyecto.
PRICING = {
    "claude-opus-4-8": {"input": 5.0, "output": 25.0},
    "claude-sonnet-5": {"input": 3.0, "output": 15.0},
    "eu.anthropic.claude-haiku-4-5-20251001-v1:0": {"input": 1.10, "output": 5.50},
    "eu.amazon.nova-pro-v1:0": {"input": 0.87, "output": 3.48},
    "deepseek.v3.2": {"input": 0.62, "output": 1.85},
    # Corre en us-east-1 (ver _BEDROCK_MODEL_REGION_OVERRIDES); precio aproximado a falta de
    # tarifa publicada para esa combinación región/modelo.
    "qwen.qwen3-next-80b-a3b": {"input": 0.23, "output": 1.86},
}

# Fallback por subcadena: un mismo modelo de Bedrock puede llegar como ARN completo de
# inference profile o como id corto con prefijo regional, sin coincidir con una clave exacta
# de PRICING.
_PRICING_SUBSTRING_FALLBACK = {
    "claude-haiku-4-5": PRICING["eu.anthropic.claude-haiku-4-5-20251001-v1:0"],
    "nova-pro": PRICING["eu.amazon.nova-pro-v1:0"],
}

# Proveedores de modelo que Bedrock aloja, usado para deducir el `provider` que exige
# ChatBedrockConverse cuando el id de modelo es un ARN completo.
_BEDROCK_MODEL_PROVIDERS = (
    "anthropic",
    "amazon",
    "meta",
    "cohere",
    "ai21",
    "mistral",
    "deepseek",
    "stability",
)

# Algunos modelos de Bedrock solo están disponibles en regiones concretas, distintas de
# `settings.aws_region`.
_BEDROCK_MODEL_REGION_OVERRIDES = {
    "qwen.qwen3-next-80b-a3b": "us-east-1",
}


def _bedrock_region_for(model: str, default_region: str) -> str:
    """Región a usar para este modelo concreto, `default_region` salvo excepción conocida."""
    return _BEDROCK_MODEL_REGION_OVERRIDES.get(model, default_region)


def _bedrock_provider_from_arn(arn: str) -> str | None:
    """Extrae el proveedor del modelo (anthropic/amazon/...) de un ARN de Bedrock."""
    lowered = arn.lower()
    for name in _BEDROCK_MODEL_PROVIDERS:
        if name in lowered:
            return name
    return None


def get_llm(
    provider: str | None = None, model: str | None = None, *, temperature: float = 0.0
) -> BaseChatModel:
    """Devuelve el chat model del proveedor indicado ('claude' | 'ollama' | 'bedrock').

    ``model``, si se da, sustituye al modelo por defecto del proveedor (``settings.*_model``),
    necesario para "bedrock", donde un mismo proveedor sirve varios motores distintos.
    """
    settings = get_settings()
    provider = (provider or settings.llm_provider).lower()

    if provider == "claude":
        from langchain_anthropic import ChatAnthropic

        if not settings.anthropic_api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY no está configurada. Rellena .env o usa --provider ollama."
            )
        return ChatAnthropic(
            model=model or settings.claude_model,
            api_key=settings.anthropic_api_key,
            max_tokens=8000,
            temperature=temperature,
        )

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=model or settings.ollama_model,
            base_url=settings.ollama_base_url,
            temperature=temperature,
            # Sin timeout HTTP explícito, una petición que Ollama nunca responde bloquea el
            # hilo de lectura del socket indefinidamente (asyncio.wait_for no lo rescata).
            client_kwargs={"timeout": settings.ollama_http_timeout_s},
        )

    if provider == "bedrock":
        from langchain_aws import ChatBedrockConverse

        if not settings.bedrock_api_key:
            raise RuntimeError(
                "AWS_BEARER_TOKEN_BEDROCK no está configurada. Rellena .env o usa otro proveedor."
            )
        if not model:
            raise RuntimeError(
                "Falta indicar qué modelo de Bedrock usar (p. ej. TFM_BEDROCK_CLAUDE_MODEL o "
                "TFM_BEDROCK_NOVA_MODEL en .env)."
            )
        # botocore recoge la clave de la variable de entorno real AWS_BEARER_TOKEN_BEDROCK;
        # pydantic-settings no la vuelca al os.environ del proceso, así que hay que hacerlo aquí.
        os.environ.setdefault("AWS_BEARER_TOKEN_BEDROCK", settings.bedrock_api_key)
        kwargs: dict = {
            "model": model,
            "region_name": _bedrock_region_for(model, settings.aws_region),
            "temperature": temperature,
            "max_tokens": 8000,
        }
        # Con un id de modelo "pelado", ChatBedrockConverse deduce el proveedor del propio id.
        # Con un ARN completo no puede, y exige el parámetro `provider` explícito.
        if model.startswith("arn:"):
            provider_hint = _bedrock_provider_from_arn(model)
            if provider_hint:
                kwargs["provider"] = provider_hint
        return ChatBedrockConverse(**kwargs)

    raise ValueError(f"Proveedor LLM desconocido: {provider!r}. Usa 'claude', 'ollama' o 'bedrock'.")


def cost_estimate(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimación de coste en USD (0 para modelos locales o sin precio de referencia)."""
    price = PRICING.get(model)
    if not price:
        lowered = model.lower()
        for key, candidate in _PRICING_SUBSTRING_FALLBACK.items():
            if key in lowered:
                price = candidate
                break
    if not price:
        return 0.0
    return (input_tokens * price["input"] + output_tokens * price["output"]) / 1_000_000
