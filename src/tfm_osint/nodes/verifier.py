"""Nodo Verificador: control anti-alucinación.

Extrae las afirmaciones del borrador con sus citas, comprueba que la evidencia citada existe
y realmente las respalda, y añade un anexo de verificación al informe final.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import structured
from tfm_osint.state import Finding, OSINTState, worst_risk

_CITATION = re.compile(r"\[([Ee]\d+(?:\s*,\s*[Ee]\d+)*)\]")

_PROMPT = """Eres un verificador de hechos de informes de inteligencia. Para cada afirmación
factual del borrador, comprueba si la evidencia citada la respalda realmente.

Devuelve una lista de 'findings'. Para cada uno:
- statement: la afirmación textual (resumida).
- evidence_ids: los id de evidencia citados.
- verified: true SOLO si la evidencia citada existe y respalda la afirmación; false si no
  hay cita, la evidencia no existe, o no la respalda.
- dimensions: desglose del riesgo por dimensión de seguridad afectada si la afirmación fuera
  cierta (una o varias, cada una con su propio nivel info/low/medium/high/critical) — no
  rellenes 'risk' directamente, se calcula aparte a partir de esto. Ejemplos: "no se
  detectaron amenazas" -> sin dimensiones o info en todas; "falta el registro DMARC, lo que
  permite suplantación de identidad" -> autenticidad alto o crítico (y opcionalmente
  integridad, si aplica). Las 5 dimensiones posibles son:
  - disponibilidad: el servicio o dato deja de estar accesible cuando hace falta.
  - confidencialidad: información que debería ser privada queda expuesta.
  - integridad: un dato o sistema puede ser modificado sin autorización.
  - trazabilidad: no queda registro fiable de quién hizo qué y cuándo.
  - autenticidad: no se puede verificar que algo (remitente, servidor) es quien dice ser.
  Criterio para elegir el nivel de riesgo de cada dimensión:
  - critical: compromiso total o explotación inmediata sin intervención adicional (credenciales
    expuestas, ejecución remota posible, servicio crítico caído).
  - high: explotable con esfuerzo moderado, o exposición de datos sensibles sin llegar al
    compromiso total (panel de administración expuesto, certificado caducado en producción).
  - medium: debilidad real pero no explotable directamente, o requiere condiciones adicionales
    (cabecera de seguridad ausente, software desactualizado sin CVE conocido asociado).
  - low: desviación de buenas prácticas sin impacto inmediato demostrable (TTL de caché muy
    largo, versión de software visible sin vulnerabilidad asociada).
  - info: dato de contexto, sin implicación de riesgo por sí mismo (fecha de registro de un
    dominio, proveedor de hosting).
  Clasifícala aunque verified sea false (una afirmación sin respaldo también tiene una
  gravedad "si fuera cierta" — pero solo se usará si luego queda verificada).
- reason: si verified=false, una frase breve explicando por qué (p. ej. "sin cita", "la
  evidencia E3 no menciona esto", "cita E7 pero esa evidencia no existe"); si verified=true,
  déjalo vacío.

Borrador:
{draft}

Evidencia disponible (id → contenido):
{evidence}"""


class FindingList(BaseModel):
    findings: list[Finding]


def _known_ids(state: OSINTState) -> set[str]:
    return {e.id for e in state.get("evidence", [])}


def _format_evidence(state: OSINTState) -> str:
    return "\n\n".join(f"[{e.id}] {e.content}" for e in state.get("evidence", []))


def verifier_node(state: OSINTState) -> dict:
    usage = state["usage"]
    llm = get_llm(usage.provider, usage.model)
    draft = state.get("draft", "")
    prompt = _PROMPT.format(draft=draft, evidence=_format_evidence(state) or "(sin evidencia)")

    try:
        result = structured(llm, FindingList, prompt, usage=usage)
        findings = result.findings
        for f in findings:
            if f.dimensions:
                f.risk = worst_risk((d.risk for d in f.dimensions), default=f.risk)
    except Exception:  # noqa: BLE001, fallback determinista si el LLM falla
        findings = _fallback_findings(draft, _known_ids(state))

    # Refuerzo determinista: una cita a un id inexistente nunca puede estar verificada. El
    # motivo se sobrescribe aquí (no se deja el que diera el LLM) porque estos dos casos son
    # comprobables mecánicamente contra `known`, no dependen de que el LLM lo explique bien.
    known = _known_ids(state)
    for f in findings:
        if not f.evidence_ids:
            f.verified = False
            f.reason = "sin cita a ninguna evidencia"
        elif not set(f.evidence_ids).issubset(known):
            f.verified = False
            f.reason = "cita a un id de evidencia que no existe"
        elif not f.verified and not f.reason:
            f.reason = "la evidencia citada no respalda la afirmación"

    unverified = [f for f in findings if not f.verified]
    report = draft
    if unverified:
        report += "\n\n---\n\n## Anexo de verificación\n\n"
        report += (
            f"Se detectaron **{len(unverified)}** afirmación(es) sin respaldo verificable "
            "en la evidencia recolectada:\n\n"
        )
        for f in unverified:
            reason = f" _({f.reason})_" if f.reason else ""
            report += f"- ⚠️ {f.statement}{reason}\n"

    return {"findings": findings, "report": report, "usage": usage}


def _fallback_findings(draft: str, known: set[str]) -> list[Finding]:
    """Extracción determinista basada solo en las citas del texto, camino de reserva si el
    LLM falla. Sin LLM no hay forma fiable de clasificar la gravedad de cada afirmación, así
    que se deja el `risk="info"` por defecto de `Finding`.
    """
    findings: list[Finding] = []
    for line in draft.splitlines():
        m = _CITATION.search(line)
        if not m:
            continue
        ids = [x.strip().upper() for x in m.group(1).split(",")]
        verified = bool(ids) and set(ids).issubset(known)
        findings.append(
            Finding(
                statement=line.strip()[:200],
                evidence_ids=ids,
                verified=verified,
                reason="" if verified else "cita a un id de evidencia que no existe",
            )
        )
    return findings
