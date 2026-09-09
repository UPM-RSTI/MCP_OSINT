"""Utilidades compartidas por los nodos: salida estructurada robusta y conteo de uso."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from pydantic import BaseModel

from tfm_osint.state import Usage

T = TypeVar("T", bound=BaseModel)

_JSON_BLOCK = re.compile(r"\{.*\}|\[.*\]", re.DOTALL)


def _normalize_top_level_keys(data: object, schema: type[BaseModel]) -> object:
    """Corrige mayúsculas/minúsculas de las claves de nivel superior si no coinciden con el
    esquema tal cual, pero sí sin distinguir mayúsculas de minúsculas.

    Solo se aplica al camino de reserva (JSON en texto libre, sin la disciplina que impone el
    tool-calling nativo): un modelo puede devolver una clave mal capitalizada (p. ej. "ioCs"
    en vez de "iocs"), y `model_validate` la rechazaría entera por un campo obligatorio
    "ausente" que en realidad estaba ahí, mal escrito. No toca valores ni estructuras
    anidadas, solo el nombre de los campos del nivel superior.
    """
    if not isinstance(data, dict):
        return data
    valid = {name.lower(): name for name in schema.model_fields}
    return {valid.get(k.lower(), k): v for k, v in data.items()}


def structured(
    llm: BaseChatModel, schema: type[T], prompt: str, usage: Usage | None = None
) -> T:
    """Obtiene salida estructurada del LLM de forma robusta entre proveedores.

    Intenta ``with_structured_output`` (soportado por Claude y por Ollama reciente); si el
    proveedor local no lo soporta o devuelve algo inválido, cae a un parseo tolerante de JSON.
    Si se pasa ``usage``, acumula en él los tokens de la llamada (para el conteo de coste).
    """
    try:
        # include_raw=True expone el AIMessage crudo para poder contar sus tokens.
        result = llm.with_structured_output(schema, include_raw=True).invoke(prompt)
        raw = result.get("raw") if isinstance(result, dict) else None
        parsed = result.get("parsed") if isinstance(result, dict) else result
        if usage is not None and isinstance(raw, AIMessage):
            accumulate_usage(usage, raw)
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema.model_validate(parsed)
    except Exception:  # noqa: BLE001, S110, fallback deliberado para modelos locales
        pass

    # Fallback: pedir JSON y parsear el primer bloque válido.
    raw = llm.invoke(
        prompt + "\n\nResponde ÚNICAMENTE con JSON válido conforme al esquema, sin texto extra."
    )
    if usage is not None and isinstance(raw, AIMessage):
        accumulate_usage(usage, raw)
    text = raw.content if isinstance(raw, AIMessage) else str(raw)
    match = _JSON_BLOCK.search(text if isinstance(text, str) else str(text))
    if not match:
        raise ValueError(f"El LLM no devolvió JSON parseable:\n{text}")
    parsed_json = _normalize_top_level_keys(json.loads(match.group(0)), schema)
    return schema.model_validate(parsed_json)


def accumulate_usage(usage: Usage, message: AIMessage) -> Usage:
    """Suma los tokens de un mensaje del LLM a las métricas acumuladas."""
    meta = getattr(message, "usage_metadata", None) or {}
    usage.input_tokens += int(meta.get("input_tokens", 0) or 0)
    usage.output_tokens += int(meta.get("output_tokens", 0) or 0)
    return usage
