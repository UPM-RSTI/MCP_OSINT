"""Pruebas de los modelos de datos y el estado.

Bajo valor individual (documentan defaults de Pydantic más que lógica propia), pero sirven
de referencia rápida de qué asume el resto del código sobre estos modelos sin tener que leer
state.py, se dejan tal cual, no aportan pero tampoco estorban.
"""

from tfm_osint.state import IOC, Evidence, Finding, Usage


def test_evidence_and_ioc_roundtrip():
    # Un IOC debe poder citar el id de la Evidence que lo respalda sin transformación alguna.
    ev = Evidence(id="E1", source="crt_sh", content="cert for example.com")
    ioc = IOC(type="domain", value="example.com", evidence_ids=["E1"], risk="low")
    assert ioc.evidence_ids == ["E1"]
    assert ev.id == "E1"


def test_finding_defaults_unverified():
    # Por defecto un Finding nace SIN verificar, el verifier debe marcarlo explícitamente,
    # nunca al revés (una afirmación no puede darse por buena por omisión).
    f = Finding(statement="algo", evidence_ids=[])
    assert f.verified is False


def test_usage_defaults():
    # Los contadores de uso arrancan en cero, graph.py/los nodos dependen de poder sumar
    # sobre estos defaults sin inicializarlos a mano en cada sitio.
    u = Usage(provider="claude", model="claude-opus-4-8")
    assert u.input_tokens == 0
    assert u.cost_usd == 0.0
