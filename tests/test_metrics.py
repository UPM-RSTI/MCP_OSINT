"""Pruebas de las métricas de evaluación."""

from metrics import compute_metrics

from tfm_osint.state import IOC, Evidence, Usage


def _state(iocs=None, report="", evidence_ids=()):
    return {
        "target": "example.com",
        "iocs": iocs or [],
        "evidence": [Evidence(id=i, source="t", content="x") for i in evidence_ids],
        "report": report,
        "findings": [],
        "usage": Usage(provider="claude", model="claude-opus-4-8"),
    }


def test_recall_and_precision():
    # Núcleo de la comparativa Claude vs Ollama: cuántos IOCs esperados se encontraron
    # (recall) y cuántos de los producidos eran correctos (precision), por separado.
    iocs = [
        IOC(type="domain", value="example.com"),
        IOC(type="domain", value="ruido.net"),  # no esperado
    ]
    m = compute_metrics(_state(iocs=iocs), expected_iocs=["example.com", "sub.example.com"])
    assert m.ioc_recall == 0.5  # 1 de 2 esperados
    assert m.ioc_precision == 0.5  # 1 de 2 producidos


def test_uncited_factual_claim_is_hallucination():
    # Afirmación factual (IP) SIN cita -> alucinación total.
    report = "example.com resuelve a 1.2.3.4"
    m = compute_metrics(_state(report=report), expected_iocs=[])
    assert m.factual_claims == 1
    assert m.uncited_claims == 1
    assert m.hallucination_rate == 1.0


def test_cited_factual_claim_is_grounded():
    # Caso simétrico al anterior: la misma afirmación, pero citando evidencia real, no
    # debe puntuar como alucinación, confirma que la métrica premia citar, no solo
    # penaliza no citar.
    report = "example.com resuelve a 1.2.3.4 [E1]"
    m = compute_metrics(_state(report=report, evidence_ids=["E1"]), expected_iocs=[])
    assert m.hallucination_rate == 0.0


def test_citation_to_unknown_evidence_is_hallucination():
    # Citar con formato correcto ([E9]) pero a un id que no existe debe contar igual que no
    # citar, una cita falsa no es mejor que ninguna cita.
    report = "dato sin respaldo real 9.9.9.9 [E9]"  # E9 no existe
    m = compute_metrics(_state(report=report, evidence_ids=["E1"]), expected_iocs=[])
    assert m.hallucination_rate == 1.0


def test_report_without_factual_claims_is_zero():
    # Un informe sin ningún dato concreto (solo recomendaciones) no tiene nada que alucinar:
    # la tasa debe ser 0, no indefinida ni 1 por falta de citas irrelevantes.
    report = "## Recomendaciones\nSe recomienda monitorización continua."
    m = compute_metrics(_state(report=report), expected_iocs=[])
    assert m.factual_claims == 0
    assert m.hallucination_rate == 0.0
