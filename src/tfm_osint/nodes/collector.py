"""Nodo Recolector: agente con herramientas MCP que reúne evidencia OSINT.

Usa el agente ReAct prefabricado de LangGraph (``create_react_agent``) sobre las
herramientas MCP. Cada resultado de herramienta se guarda como una ``Evidence``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Callable

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import create_react_agent

from tfm_osint.config import get_settings
from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import accumulate_usage
from tfm_osint.state import Evidence, OSINTState, Usage

_SYSTEM = """Eres un recolector OSINT. Dispones de herramientas para consultar fuentes
públicas de ciberseguridad. Ejecuta las consultas necesarias para cubrir el plan sobre el
objetivo indicado. Usa herramientas; no inventes datos. Cuando hayas recolectado suficiente,
detente. Solo fuentes públicas; nada de intrusión."""

# Fuentes de Evidence que este nodo genera él mismo cuando el colector falla (timeout o
# límite de recursión), no son datos OSINT reales, solo el aviso del corte. `analyst.py` las
# excluye de lo que ve el LLM.
SYNTHETIC_EVIDENCE_SOURCES = {"collector_timeout", "collector_recursion_limit"}

# Límite de iteraciones del agente, para acotar coste/latencia sin cortar prematuramente una
# recolección legítima de varias herramientas encadenadas.
_RECURSION_LIMIT = 30

# Límite de caracteres por resultado de herramienta. Se aplica dos veces: aquí, antes de que
# el resultado reentre en el historial de mensajes del bucle ReAct; y de nuevo al construir el
# registro Evidence, por defensa en profundidad, sin el primero, un objetivo con mucha
# evidencia asociada hace crecer el contexto sin límite en cada paso del bucle.
_MAX_TOOL_CHARS = 4000


def _truncate(text: str, limit: int = _MAX_TOOL_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[...truncado, {len(text)} caracteres originales]"


# Nombre del argumento que usan de forma consistente las herramientas de reconocimiento de
# dominio del servidor MCP conectado (dns_lookup, whois_domain, crtsh_search,
# osint_domain_recon...). Solo se valida este argumento (el dominio que el colector elige
# consultar), nunca el contenido que la herramienta devuelve.
_DOMAIN_ARG_KEY = "domain"


def _target_is_domain(target: str) -> bool:
    """True si el objetivo es un dominio (no una IP ni un hash), el único caso en que tiene
    sentido comprobar el argumento `domain` de una tool contra él."""
    try:
        ipaddress.ip_address(target)
        return False
    except ValueError:
        pass
    return not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", target)


def _is_related_domain(candidate: str, target: str) -> bool:
    """True si ``candidate`` es el propio objetivo, un subdominio suyo, o un dominio padre
    suyo (p. ej. `nmap.org` es un padre legítimo de `scanme.nmap.org`)."""
    candidate = candidate.strip().lower().rstrip(".")
    target = target.strip().lower().rstrip(".")
    if not candidate or not target:
        return False
    return (
        candidate == target
        or candidate.endswith("." + target)
        or target.endswith("." + candidate)
    )


def _extract_tool_text(content: object) -> str:
    """Extrae el texto legible de la salida de una tool MCP.

    Las tools MCP suelen devolver una lista de bloques ``[{'type': 'text', 'text': '...'}]``,
    no una cadena plana, aquí se extrae el texto real de cada bloque en vez de volcar la
    estructura tal cual.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list) and content:
        parts = [
            block.get("text", "") if isinstance(block, dict) else str(block) for block in content
        ]
        parts = [p for p in parts if p]
        if parts:
            return "\n".join(parts)
    return str(content)


def _cap_tool_output(tool: BaseTool, target: str, check_domain: bool) -> BaseTool:
    """Envuelve una tool MCP para truncar su salida antes de que el agente ReAct la vea, y
    para rechazar consultas a un dominio distinto del objetivo (ver ``_DOMAIN_ARG_KEY``).

    ``target``/``check_domain`` vienen de la ejecución concreta, así que las tools se envuelven
    en cada ejecución de ``collector_node``, no una sola vez al arrancar.
    """

    async def _capped(*args: object, **kwargs: object) -> str:
        domain_arg = kwargs.get(_DOMAIN_ARG_KEY)
        if (
            check_domain
            and isinstance(domain_arg, str)
            and domain_arg.strip()
            and not _is_related_domain(domain_arg, target)
        ):
            # No se ejecuta la tool real: se rechaza en origen, antes de que entre en el
            # historial del bucle como si fuera evidencia legítima.
            return (
                f"Bloqueado: se pidió consultar el dominio '{domain_arg}', pero el "
                f"objetivo de esta investigación es '{target}' — no son el mismo dominio "
                "ni están relacionados (subdominio/dominio padre). Resultado descartado "
                "para no mezclar información de un objetivo distinto en este informe."
            )
        result = await tool.ainvoke(kwargs)
        return _truncate(_extract_tool_text(result))

    # response_format="content" a propósito: _capped siempre devuelve una cadena de texto
    # (nunca la tupla (content, artifact) que exige "content_and_artifact"), aunque la tool
    # original la use.
    return tool.model_copy(update={"coroutine": _capped, "response_format": "content"})


async def _run_agent_streaming(agent, user: str) -> tuple[list, bool]:
    """Ejecuta el agente con ``astream(..., stream_mode="values")`` en vez de ``ainvoke()``.

    Con ``ainvoke()``, si salta ``GraphRecursionError`` no hay forma de recuperar los mensajes
    ya generados en las iteraciones previas. Con ``astream(stream_mode="values")``, cada
    elemento del generador es el estado completo acumulado hasta ese punto, basta con
    quedarse con el último antes de que salte la excepción para conservar toda la evidencia
    real recolectada hasta el corte. Devuelve ``(mensajes, alcanzó_límite_recursión)``.
    """
    messages: list = []
    hit_limit = False
    try:
        async for chunk in agent.astream(
            {"messages": [HumanMessage(content=user)]},
            config={"recursion_limit": _RECURSION_LIMIT},
            stream_mode="values",
        ):
            messages = chunk.get("messages", messages)
    except GraphRecursionError:
        hit_limit = True
    return messages, hit_limit


def _build_evidence_from_messages(messages: list, usage: Usage) -> list[Evidence]:
    """Construye la lista de `Evidence` (deduplicada y numerada) a partir de los mensajes del
    bucle ReAct, y acumula tokens/tool_calls en `usage` de paso."""
    raw_results: list[tuple[str, str]] = []  # (fuente, contenido), en orden de aparición
    n_calls = 0
    for msg in messages:
        if isinstance(msg, AIMessage):
            accumulate_usage(usage, msg)
        elif isinstance(msg, ToolMessage):
            n_calls += 1
            text = _truncate(_extract_tool_text(msg.content))
            raw_results.append((msg.name or "mcp_tool", text))

    usage.tool_calls += n_calls

    # Deduplicar antes de numerar: el agente ReAct a veces repite la misma llamada varias
    # veces en un mismo recorrido. usage.tool_calls sí cuenta todas las llamadas reales, dedup
    # o no: mide coste/latencia, no legibilidad del informe.
    seen: set[tuple[str, str]] = set()
    evidence: list[Evidence] = []
    for source, content in raw_results:
        key = (source, content)
        if key in seen:
            continue
        seen.add(key)
        evidence.append(Evidence(id=f"E{len(evidence) + 1}", source=source, content=content))
    return evidence


def make_collector_node(tools: list[BaseTool]) -> Callable[[OSINTState], dict]:
    """Crea el nodo recolector cerrando sobre las herramientas MCP descubiertas."""

    async def collector_node(state: OSINTState) -> dict:
        target = state["target"]
        check_domain = _target_is_domain(target)
        capped_tools = [_cap_tool_output(t, target, check_domain) for t in tools]

        llm = get_llm(state["usage"].provider, state["usage"].model)
        agent = create_react_agent(llm, capped_tools, prompt=_SYSTEM)

        plan_txt = "\n".join(f"- {s}" for s in state.get("plan", []))
        user = (
            f"Objetivo: {state['target']}\n"
            f"Petición: {state.get('query', '')}\n\n"
            f"Plan de recolección:\n{plan_txt}"
        )

        # Las herramientas MCP son solo asíncronas: hay que usar el camino async (no invoke),
        # o lanzan NotImplementedError. Envuelto en wait_for: sin timeout, un modelo que se
        # queda generando de forma indefinida bloquearía el pipeline sin límite.
        timeout_s = get_settings().collector_timeout_s
        usage = state["usage"]
        try:
            messages, hit_recursion_limit = await asyncio.wait_for(
                _run_agent_streaming(agent, user), timeout=timeout_s
            )
        except TimeoutError:
            evidence = [
                Evidence(
                    id="E1",
                    source="collector_timeout",
                    content=(
                        f"El recolector no terminó en {timeout_s}s y se abortó para evitar "
                        "un bloqueo indefinido. El informe se genera con la evidencia "
                        "recolectada hasta el momento del corte, si la hay."
                    ),
                )
            ]
            return {"evidence": evidence, "usage": usage}

        evidence = _build_evidence_from_messages(messages, usage)

        if hit_recursion_limit:
            # A diferencia del timeout de arriba, aquí sí se conserva la evidencia real ya
            # recolectada (ver _run_agent_streaming). Se añade un aviso, no se sustituye la
            # evidencia real por él, mismo id de fuente (`collector_recursion_limit`), así
            # que `analyst.py::_real_evidence()` lo sigue excluyendo de lo que puede citarse.
            evidence.append(
                Evidence(
                    id=f"E{len(evidence) + 1}",
                    source="collector_recursion_limit",
                    content=(
                        f"El recolector alcanzó el límite de {_RECURSION_LIMIT} "
                        "iteraciones antes de terminar — la evidencia de arriba sí se "
                        "recolectó de verdad, pero la investigación puede haber quedado "
                        "incompleta."
                    ),
                )
            )

        return {"evidence": evidence, "usage": usage}

    return collector_node
