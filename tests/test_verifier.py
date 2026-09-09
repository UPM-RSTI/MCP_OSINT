"""Pruebas del control anti-alucinación (fallback determinista del verificador)."""

from tfm_osint.nodes import verifier as verifier_module
from tfm_osint.nodes.verifier import FindingList, _fallback_findings, verifier_node
from tfm_osint.state import DimensionRisk, Evidence, Finding, Usage


def test_fallback_marks_valid_citation_verified():
    # Red de seguridad si el LLM verificador falla del todo (ver verifier_node): una cita a
    # un id real debe bastar para marcar la afirmación como verificada.
    draft = "example.com resuelve a 93.184.216.34 [E1]."
    findings = _fallback_findings(draft, known={"E1"})
    assert len(findings) == 1
    assert findings[0].evidence_ids == ["E1"]
    assert findings[0].verified is True


def test_fallback_marks_unknown_citation_unverified():
    # Caso simétrico: una cita con buena forma pero a un id que no existe no debe colar.
    draft = "Afirmación sin respaldo real [E9]."
    findings = _fallback_findings(draft, known={"E1"})
    assert findings[0].verified is False


def test_fallback_explains_why_unverified():
    # El motivo del fallo (no solo el booleano verified) debe llegar hasta el Anexo, para que
    # el lector sepa si faltaba la cita, la evidencia no existía o no respaldaba el hecho.
    draft = "Afirmación sin respaldo real [E9]."
    findings = _fallback_findings(draft, known={"E1"})
    assert findings[0].reason == "cita a un id de evidencia que no existe"


def test_fallback_verified_finding_has_no_reason():
    draft = "example.com resuelve a 93.184.216.34 [E1]."
    findings = _fallback_findings(draft, known={"E1"})
    assert findings[0].reason == ""


def test_verifier_node_appendix_shows_reason(monkeypatch):
    # El Anexo de verificación no solo debe listar QUÉ afirmación no está respaldada, sino
    # POR QUÉ (antes se descartaba ese motivo aunque el propio LLM verificador ya lo diera).
    finding = Finding(statement="dato dudoso", evidence_ids=["E9"], verified=True)  # E9 no existe
    monkeypatch.setattr(
        verifier_module, "structured", lambda *a, **k: FindingList(findings=[finding])
    )
    state = {
        "draft": "dato dudoso [E9]",
        "evidence": [Evidence(id="E1", source="dns_lookup", content="1.2.3.4")],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = verifier_node(state)
    assert result["findings"][0].verified is False  # el refuerzo determinista lo corrige
    assert "cita a un id de evidencia que no existe" in result["report"]


def test_verifier_node_derives_risk_from_dimensions(monkeypatch):
    # El prompt ya no le pide 'risk' directamente al LLM: verifier_node debe recalcularlo como
    # el más grave de 'dimensions', igual que analyst_node hace con los IOCs.
    finding = Finding(
        statement="falta DMARC",
        evidence_ids=["E1"],
        verified=True,
        dimensions=[
            DimensionRisk(dimension="autenticidad", risk="critical"),
            DimensionRisk(dimension="integridad", risk="low"),
        ],
    )
    monkeypatch.setattr(
        verifier_module, "structured", lambda *a, **k: FindingList(findings=[finding])
    )
    state = {
        "draft": "falta DMARC [E1]",
        "evidence": [Evidence(id="E1", source="dns_lookup", content="sin registro DMARC")],
        "usage": Usage(provider="ollama", model="qwen2.5:7b"),
    }
    result = verifier_node(state)
    assert result["findings"][0].risk == "critical"


def test_fallback_defaults_to_info_risk():
    # Sin LLM no hay forma fiable de clasificar gravedad, el fallback debe quedarse en el
    # "info" por defecto de Finding, no inventar una clasificación (ver comentario en
    # _fallback_findings). Así el banner de riesgo global no se infla por este camino de
    # reserva, solo por los IOCs.
    draft = "example.com resuelve a 93.184.216.34 [E1]."
    findings = _fallback_findings(draft, known={"E1"})
    assert findings[0].risk == "info"


def test_fallback_ignores_lines_without_citations():
    # El fallback solo extrae findings de líneas CON cita, no debe inventar afirmaciones
    # sobre texto libre sin marcar.
    draft = "## Resumen ejecutivo\nTexto sin ninguna cita."
    assert _fallback_findings(draft, known={"E1"}) == []
