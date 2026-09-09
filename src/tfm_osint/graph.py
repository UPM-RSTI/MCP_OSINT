"""Construcción y ejecución del grafo LangGraph del pipeline OSINT."""

from __future__ import annotations

import re
import time
from contextlib import AsyncExitStack

from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph

from tfm_osint.llm import cost_estimate
from tfm_osint.mcp_client import mcp_tools_session
from tfm_osint.nodes import (
    analyst_node,
    make_collector_node,
    planner_node,
    reporter_node,
    verifier_node,
)
from tfm_osint.state import OSINTState, Usage

# Mismo patrón que chat_intent.py::_HASH_RE, pero como fullmatch: aquí 'target' es el valor
# completo del campo, no una frase libre en la que buscar un hash.
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _has_hash_capable_tool(tools: list[BaseTool]) -> bool:
    return any("hash" in f"{t.name} {t.description or ''}".lower() for t in tools)


def build_graph(tools: list[BaseTool]):
    """Ensambla el StateGraph:  planner → collector → analyst → reporter → verifier."""
    g = StateGraph(OSINTState)

    g.add_node("planner", planner_node)
    g.add_node("collector", make_collector_node(tools))
    g.add_node("analyst", analyst_node)
    g.add_node("reporter", reporter_node)
    g.add_node("verifier", verifier_node)

    g.add_edge(START, "planner")
    g.add_edge("planner", "collector")
    g.add_edge("collector", "analyst")
    g.add_edge("analyst", "reporter")
    g.add_edge("reporter", "verifier")
    g.add_edge("verifier", END)

    # Sin checkpointer: cada run_pipeline() es una ejecución aislada y nada en el repo lee
    # historial de estados entre ejecuciones, así que compilar con uno (como se hacía antes,
    # con MemorySaver + thread_id) no aportaba trazabilidad real, solo la aparentaba.
    return g.compile()


async def run_pipeline(
    target: str,
    provider: str,
    model: str,
    query: str = "",
) -> OSINTState:
    """Ejecuta el pipeline completo y devuelve el estado final (con informe y métricas)."""
    target = (target or "").strip()
    if not target:
        raise ValueError("El objetivo ('target') no puede estar vacío.")

    # mcp_tools_session(), no load_tools(): abre UNA sesión persistente (un solo proceso
    # `npx`) para todas las llamadas a herramienta del colector, en vez de una por llamada.
    async with AsyncExitStack() as stack:
        try:
            tools = await stack.enter_async_context(mcp_tools_session())
        except Exception as exc:  # mensaje claro en vez de una traza cruda de npx/MCP
            raise RuntimeError(
                "No se pudieron cargar las herramientas MCP. Comprueba que Node.js está "
                f"instalado y que 'npx' funciona ({exc})."
            ) from exc

        # Ninguna herramienta del servidor MCP acepta un hash como entrada (ni siquiera las
        # de pago): sin este bloqueo, el colector no tiene nada real que hacer y el modelo
        # puede sustituir el objetivo por otro inventado. Se comprueba contra las tools ya
        # cargadas, no de forma fija, para dejar de bloquear solo si se añade una herramienta
        # capaz de consultar hashes.
        if _HASH_RE.match(target) and not _has_hash_capable_tool(tools):
            raise ValueError(
                f"'{target}' parece un hash, pero ninguna herramienta OSINT disponible admite "
                "hashes como objetivo — el sistema no puede investigarlo todavía. Prueba con un "
                "dominio o una dirección IP."
            )

        app = build_graph(tools)

        initial: OSINTState = {
            "target": target,
            "query": query or f"Investiga el objetivo '{target}' y elabora un informe OSINT.",
            "evidence": [],
            "usage": Usage(provider=provider, model=model),
        }

        t0 = time.perf_counter()
        final: OSINTState = await app.ainvoke(initial)
        elapsed = time.perf_counter() - t0

    usage = final.get("usage") or Usage(provider=provider, model=model)
    usage.latency_s = round(elapsed, 2)
    usage.cost_usd = round(cost_estimate(model, usage.input_tokens, usage.output_tokens), 6)
    final["usage"] = usage
    return final
