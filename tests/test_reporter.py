"""Pruebas del saneamiento de formato y del degradado ante fallos del nodo redactor."""

from tfm_osint.nodes.reporter import _risk_level_label, _strip_enclosing_fence, reporter_node
from tfm_osint.state import IOC, Usage


def test_strip_markdown_fence():
    # El modelo local a veces envuelve todo el informe en ```markdown ... ``` pese a que el
    # prompt se lo prohíbe explícitamente; sin este saneado, el informe se vería como un
    # bloque de código en vez de como Markdown renderizado.
    text = "```markdown\n# Informe\ntexto [E1]\n```"
    assert _strip_enclosing_fence(text) == "# Informe\ntexto [E1]"


def test_leaves_clean_markdown_untouched():
    # Caso base: un informe ya bien formado no debe alterarse (no-op).
    text = "## Resumen ejecutivo\nexample.com resuelve a 1.2.3.4 [E1]"
    assert _strip_enclosing_fence(text) == text


def test_does_not_strip_inner_code_blocks():
    # Una valla que NO envuelve todo el documento debe conservarse.
    text = "## Análisis\nEjemplo:\n```\ncódigo\n```\nFin del informe."
    assert _strip_enclosing_fence(text) == text


def _fake_state() -> dict:
    return {
        "target": "example.com",
        "iocs": [],
        "evidence": [],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }


def test_reporter_node_degrades_instead_of_crashing_on_llm_failure(monkeypatch):
    # Regresión de robustez: antes reporter_node no tenía ningún try/except alrededor de
    # llm.invoke(), si el LLM fallaba (red, API, modelo local caído), la excepción subía sin
    # capturar y tumbaba el pipeline entero, sin generar ningún informe. Ahora debe degradar a
    # un borrador explicando el fallo, para que verifier/render sigan teniendo algo que
    # procesar (mismo patrón "capturar, no romper" que ya usan collector_node/verifier_node).
    from tfm_osint.nodes import reporter as reporter_module

    def _boom(*args, **kwargs):
        raise RuntimeError("la API no responde")

    monkeypatch.setattr(reporter_module, "get_llm", lambda *a, **k: type("L", (), {"invoke": _boom})())

    result = reporter_node(_fake_state())
    assert "Resumen ejecutivo" in result["draft"]
    assert "no se pudo generar" in result["draft"].lower()


def test_risk_level_label_defaults_to_no_risk_identified_without_iocs():
    assert _risk_level_label(_fake_state()) == "Sin riesgo identificado"


def test_risk_level_label_matches_top_risk_of_iocs():
    # Misma fuente de verdad que el banner visual (report/render.py::top_risk), si aquí
    # dijera algo distinto al banner, el informe se contradiría a sí mismo.
    state = _fake_state()
    state["iocs"] = [IOC(type="ip", value="1.2.3.4", risk="critical")]
    assert _risk_level_label(state) == "Crítico"


def test_reporter_prompt_tells_the_llm_the_decided_risk_level(monkeypatch):
    # Hallazgo real del usuario: el mismo motor, sobre el mismo objetivo, ejecutado varias
    # veces seguidas, a veces escribía "Riesgo: INFORMATIVO" en su redacción y otras veces
    # no decía nada del nivel de riesgo, el prompt nunca se lo pedía como algo fijo. Ahora
    # el nivel se le da ya decidido (calculado en código, no algo que el LLM elija) y se le
    # pide justificarlo, no inventarlo, este test comprueba que ese nivel llega de verdad
    # al prompt.
    from tfm_osint.nodes import reporter as reporter_module

    captured_prompts = []

    class _FakeLLM:
        def invoke(self, prompt):
            captured_prompts.append(prompt)
            from langchain_core.messages import AIMessage

            return AIMessage(content="## Resumen ejecutivo\ntexto [E1]\n\n"
                              "## Evaluación de riesgo\njustificación [E1]\n\n"
                              "## Recomendaciones\nninguna")

    monkeypatch.setattr(reporter_module, "get_llm", lambda *a, **k: _FakeLLM())

    state = _fake_state()
    state["iocs"] = [IOC(type="ip", value="1.2.3.4", risk="critical")]
    reporter_node(state)

    assert captured_prompts, "el LLM debería haberse invocado"
    assert "Crítico" in captured_prompts[0]
