"""Pruebas del truncado de salida de tools en el collector (lógica pura, sin red ni LLM).

Cubre el arreglo del cuelgue con IPs muy conectadas (p. ej. 8.8.8.8): antes, el resultado de
una tool solo se truncaba al construir Evidence, DESPUÉS de que el bucle ReAct ya hubiera
terminado, el LLM recibía el resultado completo sin truncar en cada iteración siguiente.
Ahora se trunca también antes de reentrar en el historial del agente (_cap_tool_output), que
es lo que se prueba aquí.
"""

import asyncio

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphRecursionError

from tfm_osint.nodes import collector as collector_module
from tfm_osint.nodes.collector import (
    _MAX_TOOL_CHARS,
    _cap_tool_output,
    _extract_tool_text,
    _is_related_domain,
    _target_is_domain,
    _truncate,
    make_collector_node,
)
from tfm_osint.state import Usage


def test_truncate_keeps_short_text_unchanged():
    # Un resultado ya corto no debe modificarse ni acumular el aviso de truncado.
    assert _truncate("hola") == "hola"


def test_truncate_cuts_long_text_and_reports_original_size():
    # El aviso de truncado debe incluir el tamaño original, para poder diagnosticar cuánto
    # se perdió sin tener que ir a la fuente.
    text = "a" * (_MAX_TOOL_CHARS + 500)
    result = _truncate(text)
    assert len(result) < len(text)
    assert result.startswith("a" * _MAX_TOOL_CHARS)
    assert str(len(text)) in result


async def _fake_coroutine(**kwargs: object) -> str:
    return "x" * (_MAX_TOOL_CHARS + 1000)


def _make_fake_tool() -> StructuredTool:
    return StructuredTool.from_function(
        name="fake_osint_tool",
        description="Tool de prueba que devuelve un resultado enorme.",
        coroutine=_fake_coroutine,
    )


async def test_cap_tool_output_truncates_before_reentering_agent_history():
    # El arreglo central del cuelgue con 8.8.8.8: el truncado debe aplicarse ANTES de que el
    # resultado reentre en el historial del bucle ReAct, no solo al construir Evidence.
    capped = _cap_tool_output(_make_fake_tool(), target="example.com", check_domain=False)
    result = await capped.ainvoke({})
    assert len(result) <= _MAX_TOOL_CHARS + 100  # + margen del aviso de truncado
    assert "truncado" in result


async def _fake_content_blocks_coroutine(**kwargs: object) -> list[dict]:
    return [{"type": "text", "text": '{"domain": "example.com"}'}]


async def test_cap_tool_output_extracts_text_instead_of_dumping_repr():
    # _capped() hacía str(result) a secas ANTES de que _extract_tool_text() pudiera ver la
    # lista de bloques, el repr de Python crudo (p. ej. "[{'type': 'text', 'text': '...'}]")
    # llegaba ya aplanado a cadena a Evidence.content, así que el arreglo de
    # _extract_tool_text nunca se aplicaba de verdad sobre una tool MCP real.
    tool = StructuredTool.from_function(
        name="fake_structured_tool",
        description="Tool de prueba que devuelve bloques de contenido estructurados.",
        coroutine=_fake_content_blocks_coroutine,
    )
    capped = _cap_tool_output(tool, target="example.com", check_domain=False)
    result = await capped.ainvoke({})
    assert result == '{"domain": "example.com"}'
    assert "'type': 'text'" not in result


async def test_cap_tool_output_preserves_name_and_description():
    # El wrapper no debe cambiar cómo el LLM identifica la tool (nombre/descripción), solo
    # su comportamiento interno, si no, el agente ReAct dejaría de reconocerla.
    original = _make_fake_tool()
    capped = _cap_tool_output(original, target="example.com", check_domain=False)
    assert capped.name == original.name
    assert capped.description == original.description


async def _fake_artifact_coroutine(**kwargs: object) -> tuple[str, dict]:
    return ("resumen para el LLM", {"raw": "datos crudos"})


def test_cap_tool_output_normalizes_content_and_artifact_tools():
    # Regresión: model_copy() preservaba response_format="content_and_artifact" de la tool
    # original, pero _capped siempre devuelve una cadena, LangGraph exigía entonces una
    # tupla (content, artifact) y rompía la ejecución con ValueError en tiempo real.
    original = StructuredTool.from_function(
        name="fake_artifact_tool",
        description="Tool de prueba con response_format='content_and_artifact'.",
        coroutine=_fake_artifact_coroutine,
        response_format="content_and_artifact",
    )
    capped = _cap_tool_output(original, target="example.com", check_domain=False)
    assert capped.response_format == "content"


# --------------------------------------------------------- target-mixing


def test_is_related_domain_accepts_exact_match():
    assert _is_related_domain("scanme.nmap.org", "scanme.nmap.org") is True


def test_is_related_domain_accepts_subdomain_of_target():
    # www.example.com al investigar example.com: subdominio legítimo, no un objetivo distinto.
    assert _is_related_domain("www.example.com", "example.com") is True


def test_is_related_domain_accepts_parent_of_target():
    # nmap.org al investigar scanme.nmap.org: dominio padre, contexto legítimo (SPF/DMARC del
    # padre), no había que perderlo.
    assert _is_related_domain("nmap.org", "scanme.nmap.org") is True


def test_is_related_domain_rejects_unrelated_domain():
    # example.com no tiene ninguna relación con scanme.nmap.org.
    assert _is_related_domain("example.com", "scanme.nmap.org") is False


def test_target_is_domain_false_for_ip():
    assert _target_is_domain("8.8.8.8") is False


def test_target_is_domain_false_for_hash():
    assert _target_is_domain("d41d8cd98f00b204e9800998ecf8427e") is False  # md5, 32 hex


def test_target_is_domain_true_for_domain():
    assert _target_is_domain("scanme.nmap.org") is True


async def _fake_domain_arg_coroutine(domain: str = "") -> str:
    # Parámetro 'domain' con nombre real (no **kwargs genérico), igual que las tools MCP
    # reales (dns_lookup, whois_domain, osint_domain_recon...), para que
    # StructuredTool.from_function infiera un args_schema de verdad y el argumento se enrute
    # correctamente.
    return f"datos reales de {domain}"


def _make_domain_tool() -> StructuredTool:
    return StructuredTool.from_function(
        name="osint_domain_recon",
        description="Tool de prueba que toma un argumento 'domain'.",
        coroutine=_fake_domain_arg_coroutine,
    )


async def test_cap_tool_output_blocks_unrelated_domain_argument():
    # El colector puede invocar osint_domain_recon(domain="example.com") mientras investiga
    # scanme.nmap.org, y ese resultado ajeno acabaría en el resumen ejecutivo. Aquí se
    # bloquea ANTES de ejecutar la tool real, nunca debe verse "datos reales de
    # example.com" en el resultado.
    capped = _cap_tool_output(_make_domain_tool(), target="scanme.nmap.org", check_domain=True)
    result = await capped.ainvoke({"domain": "example.com"})
    assert "Bloqueado" in result
    assert "datos reales" not in result
    assert "scanme.nmap.org" in result  # explica cuál era el objetivo real


async def test_cap_tool_output_allows_matching_domain_argument():
    # Caso simétrico: si el argumento SÍ es el objetivo, debe ejecutarse con normalidad, el
    # bloqueo no debe volverse tan agresivo que rompa el uso normal de la propia tool.
    capped = _cap_tool_output(_make_domain_tool(), target="scanme.nmap.org", check_domain=True)
    result = await capped.ainvoke({"domain": "scanme.nmap.org"})
    assert result == "datos reales de scanme.nmap.org"


async def test_cap_tool_output_allows_related_domain_argument():
    # Un dominio padre/subdominio no debe bloquearse, es contexto legítimo (SPF/DMARC del
    # dominio padre).
    capped = _cap_tool_output(_make_domain_tool(), target="scanme.nmap.org", check_domain=True)
    result = await capped.ainvoke({"domain": "nmap.org"})
    assert result == "datos reales de nmap.org"


async def test_cap_tool_output_skips_domain_check_when_disabled():
    # Con check_domain=False (objetivo IP/hash, ver _target_is_domain), no debe bloquear nunca
    # aunque el argumento 'domain' no tenga nada que ver, no aplica en ese caso.
    capped = _cap_tool_output(_make_domain_tool(), target="8.8.8.8", check_domain=False)
    result = await capped.ainvoke({"domain": "example.com"})
    assert result == "datos reales de example.com"


def _fake_state() -> dict:
    return {
        "target": "example.com",
        "query": "",
        "plan": [],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }


async def test_collector_handles_graph_recursion_limit_with_no_progress(monkeypatch):
    # Caso degenerado: salta GraphRecursionError sin haber recolectado nada todavía (nunca
    # llegó a producirse ni un mensaje). Sin este except, tumbaba el pipeline entero
    # (CLI/Streamlit) sin generar ningún informe ni guardar nada en el historial.
    class _FakeAgent:
        async def astream(self, *args, **kwargs):
            raise GraphRecursionError("límite alcanzado")
            yield  # pragma: no cover, hace de este método un generador; nunca se alcanza

    monkeypatch.setattr(collector_module, "create_react_agent", lambda *a, **k: _FakeAgent())
    monkeypatch.setattr(collector_module, "get_llm", lambda *a, **k: object())

    node = make_collector_node(tools=[])
    result = await node(_fake_state())

    assert result["evidence"][0].source == "collector_recursion_limit"
    assert str(collector_module._RECURSION_LIMIT) in result["evidence"][0].content


async def test_collector_recovers_partial_evidence_on_recursion_limit(monkeypatch):
    # El bucle puede agotar el límite de recursión DESPUÉS de recolectar evidencia real y
    # productiva, antes se descartaba entera (ver el test de arriba, ese SÍ es el caso sin
    # nada recolectado). Ahora se recupera lo ya recolectado y se añade el aviso del corte
    # aparte, sin sustituir la evidencia real.
    def _usage(input_tokens: int, output_tokens: int) -> dict:
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }

    partial_messages = [
        AIMessage(content="pensando", usage_metadata=_usage(10, 5)),
        ToolMessage(content="A record: 1.2.3.4", name="dns_lookup", tool_call_id="1"),
    ]

    class _FakeAgent:
        async def astream(self, *args, **kwargs):
            # stream_mode="values": cada elemento es el estado COMPLETO acumulado hasta ese
            # punto, un solo yield con los mensajes ya "acumulados" antes de agotarse.
            yield {"messages": partial_messages}
            raise GraphRecursionError("límite alcanzado")

    monkeypatch.setattr(collector_module, "create_react_agent", lambda *a, **k: _FakeAgent())
    monkeypatch.setattr(collector_module, "get_llm", lambda *a, **k: object())

    node = make_collector_node(tools=[])
    result = await node(_fake_state())

    evidence = result["evidence"]
    assert evidence[0].source == "dns_lookup"  # evidencia real recuperada, no descartada
    assert evidence[0].content == "A record: 1.2.3.4"
    assert evidence[-1].source == "collector_recursion_limit"  # aviso, añadido, no sustituido
    assert str(collector_module._RECURSION_LIMIT) in evidence[-1].content
    assert result["usage"].tool_calls == 1
    assert result["usage"].input_tokens == 10  # sigue contando los tokens del tramo recuperado


def test_extract_tool_text_returns_plain_strings_unchanged():
    assert _extract_tool_text("hola") == "hola"


def test_extract_tool_text_parses_content_blocks_instead_of_dumping_repr():
    # Antes se guardaba str(content) sobre la lista completa, dejando el repr de Python
    # crudo en Evidence.content (p. ej. "[{'type': 'text', 'text': '...'}]"), ilegible en
    # la tabla de evidencia del informe. Aquí debe salir solo el texto real.
    content = [{"type": "text", "text": '{"domain": "example.com"}'}]
    assert _extract_tool_text(content) == '{"domain": "example.com"}'


def test_extract_tool_text_joins_multiple_blocks():
    content = [{"type": "text", "text": "parte 1"}, {"type": "text", "text": "parte 2"}]
    assert _extract_tool_text(content) == "parte 1\nparte 2"


def test_extract_tool_text_falls_back_to_str_for_unknown_shapes():
    assert _extract_tool_text(42) == "42"


async def test_collector_happy_path_numbers_evidence_and_dedupes_repeated_calls(monkeypatch):
    # Camino feliz del collector, sin mockear: antes solo estaban cubiertas las dos ramas de
    # excepción. Blinda la numeración E{n} de la evidencia, el conteo de usage.tool_calls y
    # el deduplicado de llamadas repetidas (la misma tool invocada varias veces con idéntico
    # resultado).
    def _usage(input_tokens: int, output_tokens: int) -> dict:
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }

    messages = [
        AIMessage(content="pensando", usage_metadata=_usage(10, 5)),
        ToolMessage(content="registrar: Example Inc.", name="whois_domain", tool_call_id="1"),
        AIMessage(content="pensando más", usage_metadata=_usage(8, 3)),
        ToolMessage(content="registrar: Example Inc.", name="whois_domain", tool_call_id="2"),
        ToolMessage(content="A record: 1.2.3.4", name="dns_lookup", tool_call_id="3"),
    ]

    class _FakeAgent:
        async def astream(self, *args, **kwargs):
            # stream_mode="values": el último elemento es el estado final completo, un solo
            # yield con todos los mensajes basta para el camino feliz.
            yield {"messages": messages}

    monkeypatch.setattr(collector_module, "create_react_agent", lambda *a, **k: _FakeAgent())
    monkeypatch.setattr(collector_module, "get_llm", lambda *a, **k: object())

    node = make_collector_node(tools=[])
    result = await node(_fake_state())

    evidence = result["evidence"]
    assert [e.id for e in evidence] == ["E1", "E2"]  # la llamada repetida a whois_domain no duplica
    assert evidence[0].source == "whois_domain"
    assert evidence[1].source == "dns_lookup"
    assert result["usage"].tool_calls == 3  # cuenta las 3 llamadas reales, dedup o no
    assert result["usage"].input_tokens == 18
    assert result["usage"].output_tokens == 8


async def test_collector_handles_timeout_gracefully(monkeypatch):
    class _FakeAgent:
        async def astream(self, *args, **kwargs):
            await asyncio.sleep(1)  # más que el timeout de prueba, de sobra
            yield {"messages": []}  # pragma: no cover, nunca se llega, hace generador el método

    class _FakeSettings:
        collector_timeout_s = 0.01

    monkeypatch.setattr(collector_module, "create_react_agent", lambda *a, **k: _FakeAgent())
    monkeypatch.setattr(collector_module, "get_llm", lambda *a, **k: object())
    monkeypatch.setattr(collector_module, "get_settings", lambda: _FakeSettings())

    node = make_collector_node(tools=[])
    result = await node(_fake_state())

    assert result["evidence"][0].source == "collector_timeout"
