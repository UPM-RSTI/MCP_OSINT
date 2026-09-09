"""Nodo Redactor: genera el borrador del informe en Markdown a partir de IOCs y evidencia.

La tabla de IOCs NO la redacta el LLM: se genera íntegramente en código en
``report/render.py::render_ioc_table_markdown`` a partir de ``state["iocs"]`` (ya saneados por
``nodes/analyst.py::_sanitize_iocs``) y se antepone al texto de este nodo, elimina el riesgo
de que el modelo invente filas, etiquete mal el tipo de IOC o duplique valores.
"""

from __future__ import annotations

import re

from langchain_core.messages import AIMessage

from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import accumulate_usage
from tfm_osint.report.render import top_risk
from tfm_osint.report.style import RISK_STYLES
from tfm_osint.state import OSINTState

_PROMPT = """Eres un redactor de informes de threat intelligence.

REGLA MÁS IMPORTANTE, se comprueba automáticamente después — no la incumplas: cada frase que
afirme un hecho concreto (IP, dominio, fecha, certificado, nivel de riesgo, ausencia de algo...)
debe terminar con la cita entre corchetes de la evidencia que la respalda. Esto incluye el
Resumen ejecutivo y la Evaluación de riesgo, no solo las recomendaciones — no son un resumen
libre, cada frase suya también debe citar.

- Bien citado: "El certificado TLS fue emitido para *.example.com [E4]."
- Mal citado, evítalo: "El dominio no presenta amenazas significativas." (afirma un hecho sin
  citar de dónde sale). O bien se cita la evidencia que lo respalda, o no se afirma.
- Si una frase no tiene evidencia que la respalde, no la escribas — omítela o suaviza a algo que
  no dependa de evidencia (p. ej. una recomendación).

Redacta el informe en español y en Markdown sobre el objetivo '{target}'.

Estructura obligatoria (NO añadas ninguna otra sección):
## Resumen ejecutivo
## Evaluación de riesgo
## Recomendaciones

IMPORTANTE: NO redactes una tabla de indicadores de compromiso (IOCs) — esa tabla se genera
automáticamente a partir de los IOCs ya normalizados y se muestra al lector antes de tu texto.
No la dupliques ni la resumas de nuevo.

El nivel de riesgo global YA LO HA DECIDIDO EL SISTEMA a partir de los IOCs y las afirmaciones
verificadas — no es algo que tú decidas: es **{risk_level}**. NO escribas tú ninguna línea de
nivel de riesgo (nada de "Riesgo:", "Nivel de riesgo:" ni similar) — el sistema la añade en
código automáticamente al principio de "## Evaluación de riesgo", antes de que se muestre tu
texto. Esa sección debe limitarse a 2-4 frases que JUSTIFIQUEN por qué ese nivel concreto
({risk_level}) es el adecuado, citando la evidencia [E#] de los IOCs/hallazgos que lo sustentan
— o, si el nivel es bajo, citando por qué no hay motivo de alarma mayor.

Reglas de formato:
- Responde DIRECTAMENTE en Markdown, empezando por '## Resumen ejecutivo'.
- NO envuelvas el informe en un bloque de código (nada de ``` ni ```markdown).

Reglas de citación (repaso):
- CADA afirmación factual va con cita [E1] o [E2, E3] — incluye resumen ejecutivo y evaluación
  de riesgo.
- Las recomendaciones (sección "Recomendaciones") son sugerencias, no hechos: NO requieren cita.
- No incluyas ningún dato factual que no esté respaldado por la evidencia.
- Sé conciso y accionable.

IOCs normalizados (para que los tengas en cuenta al redactar; ya se muestran en una tabla
aparte, no los repitas):
{iocs}

Evidencia disponible (para citar por id):
{evidence}

Antes de responder, repasa mentalmente el Resumen ejecutivo y la Evaluación de riesgo: si alguna
frase termina sin un [E#], añádelo o elimina la frase."""

_FALLBACK_DRAFT = """## Resumen ejecutivo

_No se pudo generar la redacción narrativa del informe ({reason}). Los indicadores de \
compromiso detectados, si los hay, se muestran igualmente arriba a partir de la evidencia \
recolectada — esta sección solo pierde el texto que redacta el LLM._

## Evaluación de riesgo

_Sin redacción disponible — consulta directamente los IOCs y su nivel de riesgo._

## Recomendaciones

_Sin redacción disponible._"""

# Detecta un bloque de código que envuelve TODO el informe (```markdown ... ```),
# error frecuente en modelos locales al pedirles salida en Markdown.
_ENCLOSING_FENCE = re.compile(r"^\s*```[a-zA-Z]*\s*\n(.*?)\n?```\s*$", re.DOTALL)


def _strip_enclosing_fence(text: str) -> str:
    """Elimina las vallas de código si envuelven el informe completo."""
    match = _ENCLOSING_FENCE.match(text)
    return match.group(1).strip() if match else text.strip()


def _format_iocs(state: OSINTState) -> str:
    rows = []
    for i in state.get("iocs", []):
        ev = ", ".join(i.evidence_ids)
        rows.append(f"- {i.type}: {i.value} | riesgo={i.risk} | evidencia=[{ev}] | {i.context}")
    return "\n".join(rows) if rows else "(sin IOCs)"


def _format_evidence(state: OSINTState) -> str:
    return "\n\n".join(f"[{e.id}] {e.source}\n{e.content}" for e in state.get("evidence", []))


def _risk_level_label(state: OSINTState) -> str:
    """Etiqueta del nivel de riesgo global, misma fuente de verdad que el banner visual
    (``report/render.py::top_risk`` + ``RISK_STYLES``), nunca puede desincronizarse de lo
    que ya se muestra ahí, porque es literalmente la misma función."""
    level = top_risk(state.get("iocs", []), state.get("findings", []))
    return RISK_STYLES[level]["label"] if level else "Sin riesgo identificado"


def reporter_node(state: OSINTState) -> dict:
    llm = get_llm(state["usage"].provider, state["usage"].model)
    level_label = _risk_level_label(state)
    prompt = _PROMPT.format(
        target=state["target"],
        iocs=_format_iocs(state),
        evidence=_format_evidence(state) or "(sin evidencia)",
        risk_level=level_label,
    )
    try:
        msg = llm.invoke(prompt)
        if isinstance(msg, AIMessage):
            accumulate_usage(state["usage"], msg)
        raw = msg.content if isinstance(msg.content, str) else str(msg.content)
        draft = _strip_enclosing_fence(raw)
    except Exception as exc:  # noqa: BLE001, sin redacción, seguir con un borrador degradado
        # en vez de tumbar el pipeline.
        draft = _FALLBACK_DRAFT.format(reason=exc)
    return {"draft": draft, "usage": state["usage"]}
