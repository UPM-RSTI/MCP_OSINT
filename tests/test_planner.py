"""Pruebas del nodo Planificador."""

from tfm_osint.nodes import planner as planner_module
from tfm_osint.nodes.planner import planner_node
from tfm_osint.state import Usage


def test_planner_node_degrades_instead_of_crashing_on_llm_failure(monkeypatch):
    # Regresión de robustez: antes planner_node no tenía ningún try/except, si el LLM no
    # devolvía un plan válido (structured() agota su propio reintento), la excepción subía
    # sin capturar y tumbaba el pipeline entero antes incluso de recolectar nada.
    monkeypatch.setattr(
        planner_module,
        "structured",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("JSON no parseable")),
    )
    state = {
        "target": "example.com",
        "query": "",
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = planner_node(state)
    assert len(result["plan"]) == 1
    assert "example.com" in result["plan"][0]
