"""Nodo Planner: descompone la consulta en subtareas de recolección OSINT."""

from __future__ import annotations

from pydantic import BaseModel, Field

from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import structured
from tfm_osint.state import OSINTState

_PROMPT = """Eres un analista de inteligencia de amenazas (threat intelligence).
Objetivo de la investigación: {target}
Petición del usuario: {query}

Diseña un plan de recolección OSINT: entre 3 y 6 subtareas concretas, cada una orientada a
un tipo de fuente pública (DNS, certificate transparency, Wayback, Shodan/InternetDB,
reputación/OTX, filtraciones/HIBP, etc.). Ordena de lo más informativo a lo más específico.
Solo fuentes públicas; nada de intrusión ni escaneo activo agresivo."""


class Plan(BaseModel):
    subtasks: list[str] = Field(description="Lista de subtareas de recolección.")


_FALLBACK_SUBTASK = (
    "Recolectar evidencia OSINT general sobre '{target}' (DNS, WHOIS, certificados, "
    "reputación) — el planificador no devolvió un plan válido, se usa este plan por defecto."
)


def planner_node(state: OSINTState) -> dict:
    usage = state["usage"]
    llm = get_llm(usage.provider, usage.model)
    prompt = _PROMPT.format(target=state["target"], query=state.get("query", ""))
    try:
        plan = structured(llm, Plan, prompt, usage=usage)
        subtasks = plan.subtasks
    except Exception:  # noqa: BLE001, sin plan válido, seguir con uno por defecto en vez de
        # tumbar el pipeline entero.
        subtasks = [_FALLBACK_SUBTASK.format(target=state["target"])]
    return {"plan": subtasks, "usage": usage}
