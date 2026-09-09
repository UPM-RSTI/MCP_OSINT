"""Modelos de datos y estado del grafo LangGraph."""

from __future__ import annotations

import operator
from collections.abc import Iterable
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field

# Mismo orden que RISK_ORDER en report/style.py (de más a menos grave); duplicado aquí, no
# importado de report/style.py, para que state.py no dependa de report/ (evitaría un ciclo:
# report/render.py ya importa de state.py).
_RISK_SEVERITY = ["critical", "high", "medium", "low", "info"]

# Las 5 dimensiones clásicas de un análisis de riesgo (terminología MAGERIT/ENS): a qué
# propiedad de seguridad concreta afecta un IOC o una afirmación, no solo "cuán grave es".
Dimension = Literal["disponibilidad", "confidencialidad", "integridad", "trazabilidad", "autenticidad"]


class DimensionRisk(BaseModel):
    """Nivel de riesgo de un IOC/Finding en UNA dimensión de seguridad concreta.

    Un mismo IOC puede afectar a varias dimensiones a la vez, con severidad distinta en cada
    una (p. ej. crítico en integridad, medio en autenticidad) — por eso ``IOC.dimensions``/
    ``Finding.dimensions`` son listas de estos pares, no un único valor.
    """

    dimension: Dimension
    risk: Literal["info", "low", "medium", "high", "critical"]


def worst_risk(risks: Iterable[str], default: str = "info") -> str:
    """El nivel de riesgo más grave de una colección, mismo criterio que ``RISK_ORDER``.

    ``default`` cubre el caso "colección vacía" (nunca debería darse en la práctica dado que
    los prompts piden al menos una dimensión, pero evita una excepción si ``_sanitize_iocs`` u
    otro filtro dejara la lista vacía tras limpiar algo).
    """
    present = set(risks)
    return next((r for r in _RISK_SEVERITY if r in present), default)


class Evidence(BaseModel):
    """Un fragmento de evidencia cruda recolectado de una herramienta OSINT."""

    id: str = Field(description="Identificador único, p. ej. 'E1'.")
    source: str = Field(description="Nombre de la herramienta/fuente MCP que la produjo.")
    query: str = Field(default="", description="Consulta o argumento usado.")
    content: str = Field(description="Contenido devuelto por la fuente (crudo/resumido).")


class IOC(BaseModel):
    """Indicador de compromiso normalizado."""

    type: Literal["domain", "ip", "url", "hash", "email", "cve", "asn", "certificate", "other"] = (
        Field(
            description=(
                "Registros DNS crudos (TXT, SPF, DMARC, verificación de propiedad...) no "
                "tienen tipo propio: usar 'other' para ellos, nunca un valor fuera de esta "
                "lista."
            )
        )
    )
    value: str
    context: str = Field(default="", description="Por qué es relevante / cómo se relaciona.")
    evidence_ids: list[str] = Field(default_factory=list)
    risk: Literal["info", "low", "medium", "high", "critical"] = "info"
    dimensions: list[DimensionRisk] = Field(
        default_factory=list,
        description=(
            "Desglose del riesgo por dimensión de seguridad afectada (una o varias). Si se "
            "rellena, 'risk' se recalcula en código como la más grave de estas — no lo asigna "
            "el LLM directamente, ver nodes/analyst.py::analyst_node()."
        ),
    )


class Finding(BaseModel):
    """Afirmación del informe con su respaldo en evidencia (control anti-alucinación)."""

    statement: str
    evidence_ids: list[str] = Field(default_factory=list)
    verified: bool = False
    risk: Literal["info", "low", "medium", "high", "critical"] = Field(
        default="info",
        description="Gravedad de la afirmación si fuera cierta, mismo criterio que IOC.risk.",
    )
    dimensions: list[DimensionRisk] = Field(
        default_factory=list,
        description="Mismo desglose por dimensión que IOC.dimensions, ver ese campo.",
    )
    reason: str = Field(
        default="",
        description=(
            "Motivo breve si verified=False (p. ej. sin cita, evidencia inexistente, la "
            "evidencia no respalda la afirmación); vacío si verified=True."
        ),
    )


class Usage(BaseModel):
    """Métricas de uso agregadas del pipeline."""

    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_s: float = 0.0
    tool_calls: int = 0


class OSINTState(TypedDict, total=False):
    """Estado compartido entre los nodos del grafo."""

    target: str  # objetivo de la investigación (dominio, IP, hash…)
    query: str  # instrucción en lenguaje natural
    plan: list[str]  # subtareas decididas por el Planner
    evidence: Annotated[list[Evidence], operator.add]  # se acumula
    iocs: list[IOC]  # IOCs normalizados por el Analista
    findings: list[Finding]  # afirmaciones verificadas
    draft: str  # borrador del informe (Markdown)
    report: str  # informe final (Markdown)
    usage: Usage  # métricas
