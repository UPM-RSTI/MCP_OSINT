"""Ensamblado del informe final (Markdown) y conversión opcional a PDF."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tfm_osint.report.style import (
    DIMENSION_LABELS,
    DIMENSION_ORDER,
    REPORT_CSS,
    RISK_ORDER,
    RISK_STYLES,
)
from tfm_osint.state import IOC, Evidence, Finding, OSINTState

_TEMPLATE_DIR = Path(__file__).parent
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=()),  # Markdown, no HTML autoescape
)


def _dot(color: str) -> str:
    """Punto de color dibujado en CSS, no un emoji Unicode, evita un problema real de
    alineación vertical de los glifos de emoji a color en la exportación a PDF (WeasyPrint/
    Pango): un `<span>` con `border-radius:50%` es una caja normal, sin la asimetría interna
    del glifo, y se alinea con el texto de forma predecible.
    """
    return (
        '<span style="display:inline-block;width:9px;height:9px;border-radius:50%;'
        f'background:{color};vertical-align:middle;"></span>'
    )


def _badge_html(risk: str, count: int) -> str:
    s = RISK_STYLES[risk]
    return (
        '<span style="display:inline-flex;align-items:center;gap:6px;white-space:nowrap;'
        "padding:4px 12px;border-radius:999px;font-size:9pt;font-weight:600;"
        f'color:{s["ink"]};background:{s["bg"]};">'
        f'{_dot(s["border"])} {s["label"]}: {count}</span>'
    )


def top_risk(iocs: list[IOC], findings: list[Finding] | None = None) -> str | None:
    """El nivel de riesgo más grave presente entre los IOCs y las afirmaciones ya verificadas.

    Se suman los ``risk`` de los ``findings``, pero solo los ``verified=True``: una
    afirmación sin respaldo real no debe poder inflar el banner de riesgo. Pública porque
    además del banner de este módulo, la usa ``nodes/reporter.py`` para fijar el "Nivel de
    Riesgo" que se inserta en la narrativa del informe, misma fuente de verdad en ambos.
    """
    present = {i.risk for i in iocs}
    if findings:
        present |= {f.risk for f in findings if f.verified}
    return next((r for r in RISK_ORDER if r in present), None)


def _risk_banner_html(top_risk: str | None) -> str:
    if top_risk is None:
        return (
            '<div style="padding:12px 16px;margin:14px 0;border-radius:8px;'
            'border-left:5px solid #c7cdd6;background:#f1f4f8;color:#16233a;'
            f'font-size:10.5pt;">{_dot("#c7cdd6")} No se detectaron indicadores de riesgo en esta '
            "investigación.</div>"
        )
    s = RISK_STYLES[top_risk]
    return (
        '<div style="padding:12px 16px;margin:14px 0;border-radius:8px;'
        f'border-left:5px solid {s["border"]};background:{s["bg"]};color:{s["ink"]};'
        f'font-size:10.5pt;">{_dot(s["border"])} <strong>Riesgo global: '
        f'{s["label"].upper()}</strong> — nivel más alto detectado entre los indicadores '
        "recolectados.</div>"
    )


def _risk_badges_html(iocs: list[IOC]) -> str:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.risk] = counts.get(ioc.risk, 0) + 1
    badges = "".join(_badge_html(r, counts[r]) for r in RISK_ORDER if counts.get(r))
    if not badges:
        return ""
    return f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0;">{badges}</div>'


def _dimension_matrix_html(iocs: list[IOC], findings: list[Finding] | None = None) -> str:
    """Matriz dimensión × nivel de riesgo: cuántos IOCs/afirmaciones verificadas afectan a
    cada dimensión de seguridad (MAGERIT/ENS), y con qué gravedad. Complementa las insignias
    por nivel (``_risk_badges_html``, "cuánto de grave") con "en qué se traduce" ese riesgo —
    de un vistazo, sin tener que leer la tabla de IOCs entera. Mismo criterio que ``top_risk()``
    para findings: solo cuentan los ya verificados, una afirmación sin respaldo no debe poder
    inflar la matriz.

    Cadena vacía si ningún IOC/finding tiene desglose por dimensión (informes generados antes
    de esta función, o casos sin ningún IOC), igual que ``_risk_badges_html`` con las insignias.
    """
    counts: dict[str, dict[str, int]] = {dim: dict.fromkeys(RISK_ORDER, 0) for dim in DIMENSION_ORDER}
    sources = list(iocs) + [f for f in (findings or []) if f.verified]
    for item in sources:
        for d in item.dimensions:
            if d.dimension in counts:
                counts[d.dimension][d.risk] += 1
    if not any(any(row.values()) for row in counts.values()):
        return ""

    header_cells = "".join(
        f'<th style="padding:6px 8px;text-align:center;font-size:8pt;text-transform:uppercase;'
        f'letter-spacing:.03em;color:{RISK_STYLES[r]["ink"]};">{RISK_STYLES[r]["label"]}</th>'
        for r in reversed(RISK_ORDER)  # info -> crítico, de menos a más grave leyendo a la derecha
    )
    rows_html = []
    for dim in DIMENSION_ORDER:
        row = counts[dim]
        cells = []
        for r in reversed(RISK_ORDER):
            n = row[r]
            if n:
                s = RISK_STYLES[r]
                cell = (
                    f'<td style="padding:6px 8px;text-align:center;font-weight:700;'
                    f'background:{s["bg"]};color:{s["ink"]};border:1px solid {s["border"]};">{n}</td>'
                )
            else:
                cell = (
                    '<td style="padding:6px 8px;text-align:center;background:#f9f9f7;'
                    'color:#c7cdd6;border:1px solid #e6dcc9;">–</td>'
                )
            cells.append(cell)
        rows_html.append(
            '<tr><td style="padding:6px 10px;font-weight:600;font-size:9.5pt;'
            f'color:#16233a;white-space:nowrap;">{DIMENSION_LABELS[dim]["label"]}</td>'
            f"{''.join(cells)}</tr>"
        )
    return (
        '<div style="margin:10px 0;overflow-x:auto;">'
        '<table style="border-collapse:collapse;font-size:9pt;">'
        f'<thead><tr><th></th>{header_cells}</tr></thead>'
        f"<tbody>{''.join(rows_html)}</tbody></table></div>"
    )


def _quick_stats_html(state: OSINTState) -> str:
    usage = state["usage"]
    findings = state.get("findings", [])
    n_verified = sum(1 for f in findings if f.verified)
    stats = [
        ("IOCs detectados", str(len(state.get("iocs", [])))),
        ("Afirmaciones verificadas", f"{n_verified}/{len(findings)}"),
        ("Coste estimado", f"${usage.cost_usd:.4f}"),
        ("Latencia", f"{usage.latency_s}s"),
    ]
    cells = "".join(
        '<div style="flex:1;min-width:120px;padding:10px 14px;background:#f1f4f8;'
        'border-radius:8px;text-align:center;">'
        '<div style="font-size:8pt;color:#52514e;text-transform:uppercase;'
        f'letter-spacing:.03em;">{label}</div>'
        f'<div style="font-size:15pt;font-weight:700;color:#16233a;margin-top:2px;">'
        f"{value}</div></div>"
        for label, value in stats
    )
    return f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:14px 0;">{cells}</div>'


def _reliability_notice_html(state: OSINTState) -> str:
    """Aviso corto, arriba del informe, si hay afirmaciones no verificadas, remite al Anexo
    de verificación (``nodes/verifier.py``) en vez de duplicar su contenido."""
    unverified = [f for f in state.get("findings", []) if not f.verified]
    if not unverified:
        return ""
    return (
        '<div style="padding:8px 14px;margin:6px 0;border-radius:6px;'
        'background:#fef3d9;color:#16233a;font-size:9.5pt;">'
        f"{_dot('#fab219')} <strong>{len(unverified)}</strong> afirmación(es) de este informe no están "
        "verificadas frente a la evidencia recolectada — ver el <strong>Anexo de "
        "verificación</strong> al final antes de dar por buenas las conclusiones."
        "</div>"
    )


def _target_mentioned(state: OSINTState) -> bool:
    """¿Aparece el objetivo solicitado en algún lugar del informe (narrativa o IOCs)?"""
    target = (state.get("target") or "").strip().lower()
    if not target:
        return True  # nada que comprobar
    narrative = (state.get("report") or state.get("draft") or "").lower()
    if target in narrative:
        return True
    return any(target in ioc.value.lower() for ioc in state.get("iocs", []))


def _target_mismatch_notice_html(state: OSINTState) -> str:
    """Aviso crítico si el objetivo pedido no aparece en ningún lugar del informe.

    Comprobación determinista y barata contra un fallo real posible: el modelo puede sustituir
    el objetivo por otro y redactar un informe convincente sobre ese, con citas válidas a
    evidencia real, el control anti-alucinación habitual no lo detectaría, porque la
    evidencia citada es real, solo que no es del objetivo pedido. Va antes incluso del banner
    de riesgo, que sería engañoso mostrar primero si todo el informe trata de otra cosa.
    """
    if _target_mentioned(state):
        return ""
    target = html.escape(state.get("target", ""))
    return (
        '<div style="padding:10px 16px;margin:6px 0;border-radius:8px;'
        'border-left:5px solid #d03b3b;background:#f9dcdc;color:#16233a;font-size:9.5pt;">'
        f"{_dot('#d03b3b')} <strong>Aviso crítico:</strong> el objetivo solicitado (<code>{target}</code>) "
        "no aparece en ningún lugar de este informe — es posible que el sistema haya "
        "investigado un objetivo distinto por error. No des este informe por válido sin "
        "comprobarlo manualmente."
        "</div>"
    )


def render_summary_html(state: OSINTState, *, include_quick_stats: bool = True) -> str:
    """Resumen visual "de un vistazo": aviso de integridad del objetivo si procede, banner
    de riesgo global, aviso de fiabilidad si procede, insignias por nivel, matriz por
    dimensión de seguridad si hay datos y, opcionalmente, una tira de cifras clave. Construido
    de forma determinista a partir del estado, nunca a
    partir de texto redactado por el LLM, es el único HTML que se renderiza sin escapar en
    Streamlit; el cuerpo redactado por el LLM nunca pasa por ``unsafe_allow_html``.
    """
    iocs = state.get("iocs", [])
    parts = []
    mismatch = _target_mismatch_notice_html(state)
    if mismatch:
        parts.append(mismatch)
    parts.append(_risk_banner_html(top_risk(iocs, state.get("findings", []))))
    notice = _reliability_notice_html(state)
    if notice:
        parts.append(notice)
    badges = _risk_badges_html(iocs)
    if badges:
        parts.append(badges)
    matrix = _dimension_matrix_html(iocs, state.get("findings", []))
    if matrix:
        parts.append(matrix)
    if include_quick_stats:
        parts.append(_quick_stats_html(state))
    return "\n".join(parts)


def _risk_legend_html() -> str:
    """Explica qué significa cada nivel de riesgo (los mismos colores/emoji que las
    insignias de ``render_summary_html``, para que ambos no puedan desincronizarse)."""
    rows = "".join(
        '<div style="display:flex;align-items:center;gap:6px;margin:3px 0;'
        f'font-size:9pt;color:{RISK_STYLES[r]["ink"]};">'
        f'{_dot(RISK_STYLES[r]["border"])} <strong>{RISK_STYLES[r]["label"]}</strong>'
        f' — {RISK_STYLES[r]["desc"]}</div>'
        for r in RISK_ORDER
    )
    return (
        '<div style="margin:4px 0 10px;padding:12px 16px;background:#f9f9f7;'
        'border:1px solid #e1e0d9;border-radius:8px;">'
        '<div style="font-size:8pt;font-weight:700;color:#52514e;text-transform:uppercase;'
        f'letter-spacing:.03em;margin-bottom:6px;">Niveles de riesgo</div>{rows}</div>'
    )


def _dimension_legend_html() -> str:
    """Explica qué cubre cada dimensión de seguridad (MAGERIT/ENS), mismo estilo educativo
    que ``_risk_legend_html`` y siempre completa, no solo las presentes en esta investigación."""
    rows = "".join(
        '<div style="margin:3px 0;font-size:9pt;color:#16233a;">'
        f'<strong>{DIMENSION_LABELS[dim]["label"]}</strong> — {DIMENSION_LABELS[dim]["desc"]}</div>'
        for dim in DIMENSION_ORDER
    )
    return (
        '<div style="margin:4px 0 10px;padding:12px 16px;background:#f9f9f7;'
        'border:1px solid #e1e0d9;border-radius:8px;">'
        '<div style="font-size:8pt;font-weight:700;color:#52514e;text-transform:uppercase;'
        f'letter-spacing:.03em;margin-bottom:6px;">Dimensiones de seguridad</div>{rows}</div>'
    )


def _truncate_plain(text: str, limit: int) -> str:
    text = " ".join(text.split())  # colapsa saltos de línea/espacios para que quepa en una celda
    return text if len(text) <= limit else text[:limit] + "…"


def _evidence_table_html(evidence: list[Evidence]) -> str:
    """Tabla id → fuente → resumen, para poder localizar a qué se refiere una cita [E#].

    El contenido de cada evidencia viene de fuentes OSINT externas (WHOIS, DNS, certificados…)
    no controladas por el sistema, a diferencia del resto de este módulo (que solo inserta
    texto propio, ya de confianza), aquí se escapa con ``html.escape()`` antes de insertarlo.
    """
    if not evidence:
        return (
            '<p style="font-size:9.5pt;color:#52514e;">No se recolectó evidencia citable en '
            "esta investigación.</p>"
        )
    rows = "".join(
        "<tr>"
        f'<td style="padding:5px 8px;border:1px solid #e1e0d9;font-weight:600;'
        f'white-space:nowrap;">{html.escape(e.id)}</td>'
        f'<td style="padding:5px 8px;border:1px solid #e1e0d9;">{html.escape(e.source)}</td>'
        '<td style="padding:5px 8px;border:1px solid #e1e0d9;font-size:8.5pt;color:#52514e;">'
        f"{html.escape(_truncate_plain(e.content, 150))}</td></tr>"
        for e in evidence
    )
    return (
        '<table style="width:100%;border-collapse:collapse;margin:6px 0 10px;font-size:9pt;">'
        "<thead><tr>"
        '<th style="padding:5px 8px;border:1px solid #e1e0d9;background:#eef2f7;'
        'text-align:left;">ID</th>'
        '<th style="padding:5px 8px;border:1px solid #e1e0d9;background:#eef2f7;'
        'text-align:left;">Fuente</th>'
        '<th style="padding:5px 8px;border:1px solid #e1e0d9;background:#eef2f7;'
        'text-align:left;">Contenido (resumen)</th>'
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def render_legend_html(state: OSINTState) -> str:
    """Leyenda para leer el informe: qué significa cada nivel de riesgo y a qué evidencia
    concreta se refiere cada cita ``[E#]``. Determinista, igual que ``render_summary_html``
    y por el mismo motivo (fiabilidad + único HTML permitido sin escapar en Streamlit),
    salvo la tabla de evidencia, que sí escapa su contenido por venir de fuentes externas
    (ver ``_evidence_table_html``).
    """
    intro = (
        '<p style="margin:0 0 4px;font-size:9.5pt;color:#16233a;">Cada afirmación '
        "factual del informe cita entre corchetes el id de la evidencia que la "
        "respalda (p. ej. <code>[E3]</code>). Evidencia recolectada en esta "
        "investigación:</p>"
    )
    return "\n".join(
        [
            _risk_legend_html(),
            _dimension_legend_html(),
            intro,
            _evidence_table_html(state.get("evidence", [])),
        ]
    )


def render_ioc_table_markdown(iocs: list[IOC]) -> str:
    """Tabla de IOCs (tipo, valor, riesgo, evidencia) generada íntegramente en código.

    Deliberadamente NO la redacta el LLM (ver ``nodes/reporter.py``): al construirla a partir
    de ``state["iocs"]``, ya saneados en origen por ``nodes/analyst.py::_sanitize_iocs``, el
    contenido mostrado es siempre correcto, cero riesgo de alucinación en esta sección.
    """
    if not iocs:
        return (
            "## Indicadores de compromiso (IOCs)\n\n_No se detectaron IOCs en esta "
            "investigación._"
        )
    header = (
        "## Indicadores de compromiso (IOCs)\n\n"
        "| Tipo | Valor | Riesgo | Dimensiones | Contexto | Evidencia |\n|---|---|---|---|---|---|"
    )
    # Crítico primero: un lector con prisa debe ver lo más grave sin tener que escanear la
    # tabla entera. sorted() es estable: dentro de un mismo nivel de riesgo se conserva el
    # orden original.
    ordered = sorted(iocs, key=lambda i: RISK_ORDER.index(i.risk))
    rows = []
    for i in ordered:
        style = RISK_STYLES[i.risk]
        # Solo texto, sin emoji: esta misma tabla también se muestra en Streamlit vía
        # report_body() con st.markdown() sin unsafe_allow_html, así que un <span> de color
        # saldría como texto literal, no como un punto de color.
        risk_cell = style["label"].lower()
        dimensions_cell = (
            ", ".join(f"{d.dimension} ({RISK_STYLES[d.risk]['label'].lower()})" for d in i.dimensions)
            if i.dimensions
            else "—"
        )
        evidence_cell = ", ".join(f"[{e}]" for e in i.evidence_ids) if i.evidence_ids else "—"
        value = i.value.replace("|", "\\|")
        context_cell = i.context.replace("|", "\\|") if i.context else "—"
        rows.append(
            f"| {i.type} | {value} | {risk_cell} | {dimensions_cell} | {context_cell} | "
            f"{evidence_cell} |"
        )
    return "\n".join([header, *rows])


def render_methodology_markdown(state: OSINTState) -> str:
    """Metodología: instrucción recibida + plan de recolección seguido, en Markdown plano.

    Cadena vacía si no hay ni `query` ni `plan`. Se construye aquí, no en
    ``template.md.j2``, para que llegue también a ``report_body()`` (usado por el frontend).
    """
    query = state.get("query", "")
    plan = state.get("plan", [])
    if not query and not plan:
        return ""
    parts = ["## Metodología"]
    if query:
        parts.append(f"**Instrucción recibida:** {query}")
    if plan:
        steps = "\n".join(f"- {step}" for step in plan)
        parts.append(f"**Plan de recolección seguido:**\n{steps}")
    return "\n\n".join(parts)


def _risk_level_label(state: OSINTState) -> str:
    """Etiqueta del nivel de riesgo global, misma fuente de verdad que el banner visual
    (``top_risk()`` + ``RISK_STYLES``), nunca puede desincronizarse de lo que ya muestra
    ``render_summary_html`` porque es literalmente el mismo cálculo."""
    level = top_risk(state.get("iocs", []), state.get("findings", []))
    return RISK_STYLES[level]["label"] if level else "Sin riesgo identificado"


def _insert_risk_level(narrative: str, level_label: str) -> str:
    """Inserta "**Nivel de Riesgo: X**" justo debajo de "## Evaluación de riesgo".

    Se inserta aquí, determinista y sin pasar por el verifier a propósito: es un hecho
    calculado en código a partir de ``state["iocs"]``/``findings`` ya verificados, no una
    afirmación nueva del LLM que necesite su propia cita/verificación.
    """
    heading = "## Evaluación de riesgo"
    if heading not in narrative:
        return narrative  # estructura inesperada (p. ej. degradado), no forzar un formato
    # El "\n" final deja una línea en blanco real entre el nivel y la justificación del LLM:
    # sin él, Markdown los trata como el mismo párrafo y salen pegados en una sola frase.
    return narrative.replace(heading, f"{heading}\n\n**Nivel de Riesgo: {level_label}**\n", 1)


def report_body(state: OSINTState) -> str:
    """El informe legible: tabla de IOCs (código) + metodología + texto redactado por el LLM
    + anexo de verificación, sin el resumen visual ni el encabezado.

    A propósito sin el resumen visual/encabezado (ver ``render_markdown``): es lo que hay que
    usar para mostrar "el informe completo" en Streamlit con ``st.markdown()`` normal, sin
    ``unsafe_allow_html``.
    """
    ioc_table = render_ioc_table_markdown(state.get("iocs", []))
    methodology = render_methodology_markdown(state)
    narrative = state.get("report") or state.get("draft") or "_(sin contenido)_"
    narrative = _insert_risk_level(narrative, _risk_level_label(state))
    parts = [ioc_table]
    if methodology:
        parts.append(methodology)
    parts.append(narrative)
    return "\n\n".join(parts)


def render_markdown(state: OSINTState) -> str:
    """Envuelve el cuerpo del informe (verificado) con encabezado, resumen visual y
    metadatos."""
    template = _env.get_template("template.md.j2")
    findings = state.get("findings", [])
    n_verified = sum(1 for f in findings if f.verified)
    return template.render(
        target=state["target"],
        date=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        usage=state["usage"],
        risk_summary=render_summary_html(state),
        legend=render_legend_html(state),
        body=report_body(state),
        n_iocs=len(state.get("iocs", [])),
        n_findings=len(findings),
        n_verified=n_verified,
    )


def render_pdf_bytes(markdown_text: str) -> bytes:
    """Convierte Markdown a PDF y devuelve los bytes en memoria (sin tocar disco).

    Requiere el extra ``[pdf]`` (weasyprint + markdown-it-py). Pensada para
    ``st.download_button`` en `app.py`, que necesita los bytes directamente, no una ruta.
    """
    from markdown_it import MarkdownIt
    from weasyprint import HTML

    html_body = MarkdownIt("commonmark", {"html": True}).enable("table").render(markdown_text)
    html_doc = (
        f'<!doctype html><html><head><meta charset="utf-8">'
        f"<style>{REPORT_CSS}</style></head><body>{html_body}</body></html>"
    )
    return HTML(string=html_doc).write_pdf()


def render_pdf(markdown_text: str, out_path: Path) -> Path:
    """Convierte Markdown a PDF y lo escribe en ``out_path`` (requiere el extra [pdf])."""
    out_path.write_bytes(render_pdf_bytes(markdown_text))
    return out_path
