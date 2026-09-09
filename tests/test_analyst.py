"""Pruebas del saneado determinista de IOCs (evidence_ids) del analista."""

from tfm_osint.nodes import analyst as analyst_module
from tfm_osint.nodes.analyst import (
    IOCList,
    _dedupe_iocs,
    _format_evidence,
    _sanitize_iocs,
    analyst_node,
)
from tfm_osint.state import IOC, DimensionRisk, Evidence, Usage


def test_sanitize_keeps_valid_evidence_ids():
    # Caso base: un id que sí existe no debe tocarse ni descartarse.
    iocs = [IOC(type="domain", value="example.com", evidence_ids=["E1", "E2"])]
    result = _sanitize_iocs(iocs, known={"E1", "E2"})
    assert result[0].evidence_ids == ["E1", "E2"]


def test_sanitize_drops_unknown_evidence_id():
    # El filtro no distingue "id con forma rara" (p. ej. un id interno de LangChain colado
    # en vez de 'E1') de "id bien formado pero inexistente" ('E9'), es el mismo filtro de
    # pertenencia (`in known`) en los dos casos, así que un solo test cubre ambos: no basta
    # con que el id tenga buena pinta, tiene que existir de verdad.
    iocs = [IOC(type="ip", value="93.184.216.34", evidence_ids=["E9"])]
    result = _sanitize_iocs(iocs, known={"E1"})
    assert result[0].evidence_ids == []


def test_format_evidence_excludes_synthetic_collector_notices():
    # Cuando el colector falla (timeout/límite de recursión), la única "evidencia" es un
    # aviso sintético del corte, el analyst no debe verlo como dato citable, o puede acabar
    # generando un IOC que respalda en "el recolector se detuvo".
    evidence = [
        Evidence(id="E1", source="collector_timeout", content="el recolector no terminó a tiempo"),
        Evidence(id="E2", source="whois_domain", content="registrar: Example Inc."),
    ]
    formatted = _format_evidence({"evidence": evidence})
    assert "E1" not in formatted
    assert "E2" in formatted


def test_dedupe_iocs_merges_case_insensitive_duplicates():
    # El mismo dominio citado dos veces con distinta capitalización no debe contarse como si
    # fueran dos IOCs distintos en la tabla del informe.
    iocs = [
        IOC(type="domain", value="ELLIOTT.NS.CLOUDFLARE.COM", risk="low", evidence_ids=["E1"]),
        IOC(type="domain", value="elliott.ns.cloudflare.com", risk="high", evidence_ids=["E2"]),
    ]
    result = _dedupe_iocs(iocs)
    assert len(result) == 1
    assert result[0].value == "ELLIOTT.NS.CLOUDFLARE.COM"  # grafía del primero visto
    assert result[0].risk == "high"  # el más grave de los duplicados
    assert result[0].evidence_ids == ["E1", "E2"]  # unión sin repetir


def test_dedupe_iocs_merges_dimensions_and_recomputes_risk():
    # El mismo IOC citado dos veces con distinto desglose por dimensión debe fusionarse por
    # dimensión (quedándose con el más grave de cada una), y el riesgo global recalcularse a
    # partir del resultado, no del de un único duplicado.
    iocs = [
        IOC(
            type="certificate", value="cert.example.com", risk="medium",
            dimensions=[DimensionRisk(dimension="confidencialidad", risk="medium")],
        ),
        IOC(
            type="certificate", value="cert.example.com", risk="low",
            dimensions=[
                DimensionRisk(dimension="confidencialidad", risk="low"),
                DimensionRisk(dimension="autenticidad", risk="critical"),
            ],
        ),
    ]
    result = _dedupe_iocs(iocs)
    assert len(result) == 1
    by_dim = {d.dimension: d.risk for d in result[0].dimensions}
    assert by_dim == {"confidencialidad": "medium", "autenticidad": "critical"}
    assert result[0].risk == "critical"  # el más grave de las dimensiones fusionadas


def test_dedupe_iocs_keeps_worst_risk_when_only_one_duplicate_has_dimensions():
    # Reproduce el bug real: un duplicado sin desglose por dimensión pero con 'risk' crítico,
    # fusionado con otro que sí trae dimensiones pero de menor gravedad. El recálculo posterior
    # a partir de 'dimensions' no debe perder la severidad del duplicado sin desglose.
    iocs = [
        IOC(type="ip", value="1.2.3.4", risk="critical"),
        IOC(
            type="ip", value="1.2.3.4", risk="low",
            dimensions=[DimensionRisk(dimension="disponibilidad", risk="low")],
        ),
    ]
    result = _dedupe_iocs(iocs)
    assert len(result) == 1
    assert result[0].risk == "critical"  # no se pierde el riesgo del duplicado sin dimensiones


def test_analyst_node_derives_risk_from_dimensions(monkeypatch):
    # El prompt ya no le pide 'risk' al LLM directamente: aunque el modelo dejara el default
    # ("info"), analyst_node debe recalcularlo como el más grave de 'dimensions'.
    ioc = IOC(
        type="other", value="TXT sin SPF", evidence_ids=["E1"],
        dimensions=[
            DimensionRisk(dimension="integridad", risk="critical"),
            DimensionRisk(dimension="autenticidad", risk="medium"),
        ],
    )
    monkeypatch.setattr(analyst_module, "structured", lambda *a, **k: IOCList(iocs=[ioc]))
    state = {
        "target": "example.com",
        "evidence": [Evidence(id="E1", source="dns_lookup", content="sin registro SPF")],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = analyst_node(state)
    assert result["iocs"][0].risk == "critical"


def test_analyst_node_keeps_manual_risk_when_no_dimensions(monkeypatch):
    # Compatibilidad hacia atrás: un IOC sin desglose por dimensión conserva el 'risk' que
    # traiga (no se sobrescribe a 'info' por no tener dimensiones que promediar).
    ioc = IOC(type="ip", value="1.2.3.4", risk="high")
    monkeypatch.setattr(analyst_module, "structured", lambda *a, **k: IOCList(iocs=[ioc]))
    state = {
        "target": "example.com",
        "evidence": [],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = analyst_node(state)
    assert result["iocs"][0].risk == "high"


def test_analyst_node_degrades_instead_of_crashing_on_llm_failure(monkeypatch):
    # Regresión de robustez: antes analyst_node no tenía ningún try/except, si el LLM no
    # devolvía una lista de IOCs válida, la excepción subía sin capturar y tumbaba el
    # pipeline entero, perdiendo también toda la evidencia ya recolectada.
    monkeypatch.setattr(
        analyst_module,
        "structured",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("JSON no parseable")),
    )
    state = {
        "target": "example.com",
        "evidence": [],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = analyst_node(state)
    assert result["iocs"] == []
