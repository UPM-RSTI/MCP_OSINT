"""Nodo Analista: normaliza la evidencia en IOCs y les asigna riesgo."""

from __future__ import annotations

from pydantic import BaseModel

from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import structured
from tfm_osint.nodes.collector import SYNTHETIC_EVIDENCE_SOURCES
from tfm_osint.report.style import RISK_ORDER
from tfm_osint.state import IOC, DimensionRisk, Evidence, OSINTState, worst_risk

_PROMPT = """Eres un analista de threat intelligence. A partir de la evidencia recolectada,
extrae y normaliza los indicadores de compromiso (IOCs) relevantes para el objetivo '{target}'.

Reglas:
- Cada IOC debe citar los id de evidencia que lo respaldan (campo evidence_ids).
- No inventes IOCs que no aparezcan en la evidencia.
- Rellena 'dimensions' con una o varias dimensiones de seguridad afectadas por el IOC, cada una
  con su propio nivel de riesgo (info/low/medium/high/critical) — un mismo IOC puede tener
  distinta gravedad en cada dimensión (p. ej. crítico en integridad, medio en autenticidad). No
  rellenes 'risk' directamente, se calcula aparte a partir de 'dimensions'. Las 5 dimensiones
  posibles son:
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
- Descarta ruido y duplicados.
- El campo 'type' SOLO admite: domain, ip, url, hash, email, cve, asn, certificate, other. Un
  registro DNS crudo (TXT, SPF, DMARC, verificación de propiedad, cualquier valor que no encaje
  en los demás tipos) va como 'other' — nunca inventes un tipo nuevo fuera de esta lista, un
  solo valor no admitido invalida el IOC completo.

Evidencia:
{evidence}"""


class IOCList(BaseModel):
    iocs: list[IOC]


def _real_evidence(state: OSINTState) -> list[Evidence]:
    """Evidencia real recolectada, sin los avisos sintéticos del colector (timeout/límite de
    recursión), no son datos OSINT, y un IOC no debe poder citarlos como respaldo factual."""
    return [e for e in state.get("evidence", []) if e.source not in SYNTHETIC_EVIDENCE_SOURCES]


def _format_evidence(state: OSINTState) -> str:
    lines = [f"[{e.id}] fuente={e.source}\n{e.content}" for e in _real_evidence(state)]
    return "\n\n".join(lines) if lines else "(sin evidencia)"


def _known_ids(evidence: list[Evidence]) -> set[str]:
    return {e.id for e in evidence if e.source not in SYNTHETIC_EVIDENCE_SOURCES}


def _sanitize_iocs(iocs: list[IOC], known: set[str]) -> list[IOC]:
    """Descarta de ``evidence_ids`` cualquier id que no corresponda a evidencia real.

    El modelo local a veces cita un identificador ajeno al esquema (p. ej. el id interno de
    LangChain ``lc_2d7b4119-...``) en vez de un id ``E#`` real. Un id así no debe propagarse
    al informe como si respaldara el IOC, el verifier ya lo trataría como no verificado, pero
    es mejor no generarlo: aquí se filtra en origen para que la tabla de IOCs del reporter no
    muestre citas falsas.
    """
    for ioc in iocs:
        ioc.evidence_ids = [i for i in ioc.evidence_ids if i in known]
    return iocs


def _merge_dimensions(existing: list, incoming: list) -> list:
    """Une dos listas de ``DimensionRisk`` por dimensión, quedándose con el riesgo más grave
    cuando la misma dimensión aparece en ambas (mismo criterio que el resto de esta función)."""
    by_dimension = {d.dimension: d.risk for d in existing}
    for d in incoming:
        if d.dimension not in by_dimension or (
            RISK_ORDER.index(d.risk) < RISK_ORDER.index(by_dimension[d.dimension])
        ):
            by_dimension[d.dimension] = d.risk
    return [DimensionRisk(dimension=dim, risk=risk) for dim, risk in by_dimension.items()]


def _dedupe_iocs(iocs: list[IOC]) -> list[IOC]:
    """Fusiona IOCs que solo difieren en mayúsculas/minúsculas del mismo valor (mismo tipo).

    Conserva la grafía del primero visto, une ``evidence_ids`` sin repetir citas, y se queda
    con el riesgo más grave de los duplicados (``RISK_ORDER``, de más a menos grave). Si hay
    desglose por dimensión (``dimensions``), también se une por dimensión y ``risk`` se
    recalcula como el más grave entre esas dimensiones fusionadas y el riesgo ya fusionado de
    ambos duplicados — nunca solo a partir de las dimensiones, o se perdería la severidad de
    un duplicado que no trajera desglose (p. ej. uno de los dos citado sin 'dimensions').
    """
    merged: dict[tuple[str, str], IOC] = {}
    for ioc in iocs:
        key = (ioc.type, ioc.value.strip().lower())
        existing = merged.get(key)
        if existing is None:
            merged[key] = ioc
            continue
        for evidence_id in ioc.evidence_ids:
            if evidence_id not in existing.evidence_ids:
                existing.evidence_ids.append(evidence_id)
        if RISK_ORDER.index(ioc.risk) < RISK_ORDER.index(existing.risk):
            existing.risk = ioc.risk
        if ioc.dimensions or existing.dimensions:
            existing.dimensions = _merge_dimensions(existing.dimensions, ioc.dimensions)
            existing.risk = worst_risk(
                [*(d.risk for d in existing.dimensions), existing.risk],
                default=existing.risk,
            )
    return list(merged.values())


def _apply_dimension_risk(iocs: list[IOC]) -> list[IOC]:
    """Recalcula ``risk`` como el más grave de ``dimensions``, no lo asigna el LLM
    directamente (ver la regla del prompt) — un IOC sin desglose por dimensión conserva su
    ``risk`` tal cual (compatibilidad con construcciones directas, p. ej. en tests)."""
    for ioc in iocs:
        if ioc.dimensions:
            ioc.risk = worst_risk((d.risk for d in ioc.dimensions), default=ioc.risk)
    return iocs


def analyst_node(state: OSINTState) -> dict:
    usage = state["usage"]
    llm = get_llm(usage.provider, usage.model)
    prompt = _PROMPT.format(target=state["target"], evidence=_format_evidence(state))
    try:
        result = structured(llm, IOCList, prompt, usage=usage)
        iocs = _apply_dimension_risk(result.iocs)
        iocs = _sanitize_iocs(iocs, _known_ids(state.get("evidence", [])))
        iocs = _dedupe_iocs(iocs)
    except Exception:  # noqa: BLE001, sin IOCs válidos, seguir con una lista vacía en vez de
        # tumbar el pipeline.
        iocs = []
    return {"iocs": iocs, "usage": usage}
