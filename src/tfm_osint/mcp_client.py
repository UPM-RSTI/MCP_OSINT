"""Puente MCP → LangChain.

Construye un ``MultiServerMCPClient`` a partir de ``mcp_servers/servers.json`` y expone
las herramientas OSINT como herramientas LangChain consumibles por los agentes LangGraph.

Uso como script de verificación (Fase 1):

    python -m tfm_osint.mcp_client --list            # lista las tools descubiertas
    python -m tfm_osint.mcp_client --call crt_sh --arg domain=example.com
"""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools

from tfm_osint.config import get_settings, load_server_config


def build_connections() -> dict[str, dict]:
    """Traduce servers.json + entorno OSINT al formato de MultiServerMCPClient."""
    settings = get_settings()
    osint_env = settings.osint_env()
    connections: dict[str, dict] = {}

    for name, cfg in load_server_config().items():
        transport = cfg.get("transport", "stdio")
        if transport == "stdio":
            connections[name] = {
                "transport": "stdio",
                "command": cfg["command"],
                "args": cfg.get("args", []),
                # Heredamos el entorno del proceso y añadimos solo las claves OSINT presentes.
                "env": {**os.environ, **osint_env},
            }
        elif transport in ("streamable_http", "streamable-http", "http"):
            connections[name] = {"transport": "streamable_http", "url": cfg["url"]}
        else:
            raise ValueError(f"Transporte MCP no soportado para '{name}': {transport}")

    if not connections:
        raise RuntimeError(
            "No hay servidores MCP habilitados. Activa al menos uno en mcp_servers/servers.json."
        )
    return connections


def get_client() -> MultiServerMCPClient:
    return MultiServerMCPClient(build_connections())


async def load_tools() -> list[BaseTool]:
    """Descubre y devuelve todas las herramientas MCP como herramientas LangChain.

    OJO: usa ``client.get_tools()``, que crea una sesión nueva por cada llamada a
    herramienta (y, para un servidor stdio, un proceso nuevo). Válido para introspección
    puntual (``--list``, la pestaña "Herramientas MCP", el listado de `chat_intent.py`) pero
    no para el *pipeline* real, que invoca herramientas en bucle: usar
    ``mcp_tools_session()`` en su lugar.
    """
    client = get_client()
    return await client.get_tools()


@asynccontextmanager
async def mcp_tools_session() -> AsyncIterator[list[BaseTool]]:
    """Abre UNA sesión persistente por servidor MCP habilitado, un solo proceso `npx`,
    reutilizado para todas las llamadas a herramienta durante el bloque ``async with``, en
    vez de una sesión (y, para stdio, un proceso nuevo) por cada llamada.

    Requiere entrar en el `async with` ANTES de invocar cualquier tool y no salir hasta
    haber terminado de usarlas (el grafo entero, en `graph.py::run_pipeline`), las tools
    que produce quedan ligadas a esa sesión concreta, no son reutilizables fuera de ella.
    """
    client = get_client()
    async with AsyncExitStack() as stack:
        all_tools: list[BaseTool] = []
        for name in client.connections:
            session = await stack.enter_async_context(client.session(name))
            all_tools.extend(await load_mcp_tools(session, server_name=name))
        yield all_tools


async def tool_summaries() -> list[dict[str, str]]:
    """Nombre + primera línea de descripción de cada herramienta MCP descubierta.

    Fuente única de verdad para "qué herramientas hay disponibles", usada por la pestaña
    "Herramientas MCP" de `app.py` para mostrar la lista real, nunca nombres que el LLM se
    pueda inventar (mismo principio anti-alucinación que el resto del proyecto).
    """
    tools = await load_tools()
    summaries = []
    for t in tools:
        desc = (t.description or "").strip().splitlines()
        summaries.append({"name": t.name, "description": desc[0] if desc else ""})
    return summaries


# --------------------------------------------------------------------------- CLI


async def _list() -> None:
    summaries = await tool_summaries()
    print(f"Descubiertas {len(summaries)} herramientas OSINT vía MCP:\n")
    for s in summaries:
        print(f"  • {s['name']:<28} {s['description'][:80]}")


async def _call(name: str, kwargs: dict[str, str]) -> None:
    tools = {t.name: t for t in await load_tools()}
    if name not in tools:
        raise SystemExit(f"Herramienta '{name}' no encontrada. Usa --list para verlas.")
    result = await tools[name].ainvoke(kwargs)
    print(result)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verificación del puente MCP → LangChain.")
    p.add_argument("--list", action="store_true", help="Lista las herramientas descubiertas.")
    p.add_argument("--call", metavar="TOOL", help="Ejecuta una herramienta por nombre.")
    p.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="k=v",
        help="Argumento clave=valor para --call (repetible).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    if args.call:
        kwargs = dict(a.split("=", 1) for a in args.arg)
        asyncio.run(_call(args.call, kwargs))
    else:  # por defecto, listar
        asyncio.run(_list())


if __name__ == "__main__":
    main()
