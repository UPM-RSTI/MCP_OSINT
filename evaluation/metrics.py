"""Métricas automáticas del pipeline OSINT.

La tasa de alucinación se mide sobre el **texto del informe**: se identifican las
afirmaciones factuales (líneas que contienen datos concretos: IPs, UUIDs, hashes, CVEs,
fechas ISO o URLs) y se considera *no respaldada* toda afirmación factual que carezca de una
cita válida a evidencia existente. Esto penaliza tanto las citas a evidencia inexistente como
la **ausencia total de cita**, un informe que no cita nada no obtiene una alucinación de 0,
que sería engañoso, sino una alta.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from tfm_osint.state import OSINTState

# Patrones de "dato concreto": una línea que contiene alguno de ellos afirma un hecho.
# Se eligen patrones de alta precisión (se excluyen los dominios, demasiado comunes, para
# evitar falsos positivos).
_FACTUAL_PATTERNS = [
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # IPv4
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b[a-fA-F0-9]{32,64}\b"),  # hash
    re.compile(r"\bCVE-\d{4}-\d+\b"),  # CVE
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),  # fecha ISO
    re.compile(r"https?://\S+"),  # URL
]
_CITATION = re.compile(r"\[[Ee]\d+(?:\s*,\s*[Ee]\d+)*\]")


@dataclass
class Metrics:
    ioc_recall: float  # cobertura de IOCs esperados
    ioc_precision: float  # proporción de IOCs producidos que son esperados
    hallucination_rate: float  # % de afirmaciones factuales sin respaldo verificable
    factual_claims: int  # nº de afirmaciones factuales detectadas en el informe
    uncited_claims: int  # nº de esas afirmaciones sin cita válida
    n_iocs: int
    n_findings: int
    latency_s: float
    cost_usd: float
    input_tokens: int
    output_tokens: int
    tool_calls: int

    def as_dict(self) -> dict:
        return asdict(self)


def _norm(v: str) -> str:
    return v.strip().lower()


def _cited_ids(line: str) -> list[str]:
    ids: list[str] = []
    for match in _CITATION.finditer(line):
        ids.extend(x.strip().upper() for x in match.group(0).strip("[]").split(","))
    return ids


def _factual_lines(report: str) -> list[str]:
    """Líneas del informe que afirman un hecho concreto (excluye títulos y separadores)."""
    lines: list[str] = []
    for raw in report.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or set(line) <= set("|-: "):
            continue
        if any(p.search(line) for p in _FACTUAL_PATTERNS):
            lines.append(line)
    return lines


def compute_metrics(state: OSINTState, expected_iocs: list[str]) -> Metrics:
    # --- IOCs ---
    produced = {_norm(i.value) for i in state.get("iocs", [])}
    expected = {_norm(v) for v in expected_iocs}
    hits = produced & expected
    ioc_recall = len(hits) / len(expected) if expected else 0.0
    ioc_precision = len(hits) / len(produced) if produced else 0.0

    # --- Alucinación (sobre el texto del informe) ---
    known = {e.id.upper() for e in state.get("evidence", [])}
    report = state.get("report") or state.get("draft") or ""
    claims = _factual_lines(report)
    uncited = 0
    for line in claims:
        cited = _cited_ids(line)
        supported = bool(cited) and set(cited) <= known
        if not supported:
            uncited += 1
    hallucination_rate = uncited / len(claims) if claims else 0.0

    u = state["usage"]
    return Metrics(
        ioc_recall=round(ioc_recall, 3),
        ioc_precision=round(ioc_precision, 3),
        hallucination_rate=round(hallucination_rate, 3),
        factual_claims=len(claims),
        uncited_claims=uncited,
        n_iocs=len(produced),
        n_findings=len(state.get("findings", [])),
        latency_s=u.latency_s,
        cost_usd=u.cost_usd,
        input_tokens=u.input_tokens,
        output_tokens=u.output_tokens,
        tool_calls=u.tool_calls,
    )
