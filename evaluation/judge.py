"""LLM-as-judge: puntúa la calidad del informe con una rúbrica estructurada.

El juez usa siempre el mismo modelo (fijo, vía Bedrock, ver `settings.bedrock_judge_model`)
con independencia del proveedor que generó el informe, para que las puntuaciones sean
comparables entre experimentos. Deliberadamente de un proveedor distinto a los motores
comparados por el TFM, un juez de la misma familia que uno de los motores evaluados
sesgaría las puntuaciones a su favor (auto-preferencia, documentado en la literatura de
LLM-as-judge).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from tfm_osint.config import get_settings
from tfm_osint.llm import get_llm
from tfm_osint.nodes._common import structured

_PROMPT = """Eres un evaluador experto de informes de threat intelligence. Puntúa el
siguiente informe según la rúbrica, en una escala de 1 (muy deficiente) a 5 (excelente).

Rúbrica:
- utilidad: ¿aporta inteligencia accionable?
- exactitud: ¿las afirmaciones son correctas y están respaldadas por citas?
- accionabilidad: ¿las recomendaciones son concretas y aplicables?
- claridad: ¿está bien estructurado y es legible?

Contexto del objetivo: {target}
Hechos esperados (referencia): {expected}

Informe a evaluar:
---
{report}
---"""


class JudgeScore(BaseModel):
    utilidad: int = Field(ge=1, le=5)
    exactitud: int = Field(ge=1, le=5)
    accionabilidad: int = Field(ge=1, le=5)
    claridad: int = Field(ge=1, le=5)
    comentario: str = ""

    @property
    def media(self) -> float:
        return round((self.utilidad + self.exactitud + self.accionabilidad + self.claridad) / 4, 2)


def judge_report(report: str, target: str, expected_facts: list[str]) -> JudgeScore:
    llm = get_llm("bedrock", get_settings().bedrock_judge_model)
    prompt = _PROMPT.format(
        target=target,
        expected="; ".join(expected_facts) or "(sin referencia)",
        report=report,
    )
    return structured(llm, JudgeScore, prompt)
