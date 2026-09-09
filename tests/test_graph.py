"""Pruebas de las validaciones de entrada de run_pipeline (sin red ni LLM)."""

from contextlib import asynccontextmanager

import pytest

from tfm_osint import graph as graph_module
from tfm_osint.graph import run_pipeline


def _fake_session(tools_or_exc):
    """Sustituye a `mcp_tools_session()` en los tests: un context manager async que
    devuelve `tools_or_exc` (una lista de tools) o la lanza si es una excepción, mismo
    contrato que la sesión real, sin tocar red ni lanzar `npx`."""

    @asynccontextmanager
    async def _session():
        if isinstance(tools_or_exc, BaseException):
            raise tools_or_exc
        yield tools_or_exc

    return _session


async def test_run_pipeline_rejects_empty_target():
    # Antes un target vacío llegaba tal cual al planner y era el LLM quien decidía qué
    # hacer con él, ahora debe rechazarse pronto, con un error claro, en vez de gastar una
    # llamada al LLM (o a Claude, con coste real) sobre un objetivo sin sentido.
    with pytest.raises(ValueError, match="no puede estar vacío"):
        await run_pipeline("   ", "ollama", "qwen2.5:7b")


async def test_run_pipeline_wraps_mcp_load_failure_in_clear_error(monkeypatch):
    # Antes un fallo al cargar las herramientas MCP (p. ej. falta Node.js/npx) subía como la
    # excepción cruda de la librería MCP, ahora debe envolverse en un RuntimeError legible
    # para quien lo vea en la CLI o en Streamlit.
    monkeypatch.setattr(
        graph_module, "mcp_tools_session", _fake_session(ConnectionError("spawn npx ENOENT"))
    )

    with pytest.raises(RuntimeError, match="No se pudieron cargar las herramientas MCP"):
        await run_pipeline("example.com", "ollama", "qwen2.5:7b")


async def test_run_pipeline_rejects_hash_target_when_no_tool_supports_it(monkeypatch):
    # Hallazgo real: al no tener ninguna herramienta que admita un hash como objetivo, el
    # colector no tenía nada real que hacer y el modelo local sustituyó el objetivo por otro
    # completamente distinto sin avisar (un hash acabó investigando 'example.com'). Mejor
    # rechazarlo pronto, con un aviso claro, que generar un informe engañoso.
    monkeypatch.setattr(graph_module, "mcp_tools_session", _fake_session([]))

    with pytest.raises(ValueError, match="parece un hash"):
        await run_pipeline("44d88612fea8a8f36de82e1278abb02f", "ollama", "qwen2.5:7b")


async def test_run_pipeline_allows_hash_target_when_a_tool_supports_it(monkeypatch):
    # El bloqueo se comprueba contra las tools ya cargadas, no de forma fija, si en el
    # futuro se añade una herramienta real de consulta de hashes, debe dejar de bloquear
    # solo, sin tener que recordar quitar el aviso a mano.
    class _FakeTool:
        name = "vt_file_hash"
        description = "Consulta la reputación de un hash de fichero en VirusTotal."

    class _FakeApp:
        async def ainvoke(self, initial):
            return initial

    monkeypatch.setattr(graph_module, "mcp_tools_session", _fake_session([_FakeTool()]))
    monkeypatch.setattr(graph_module, "build_graph", lambda tools: _FakeApp())

    result = await run_pipeline("44d88612fea8a8f36de82e1278abb02f", "ollama", "qwen2.5:7b")
    assert result["target"] == "44d88612fea8a8f36de82e1278abb02f"
