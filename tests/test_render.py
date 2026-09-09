"""Pruebas del resumen visual del informe (lógica pura, sin red ni LLM).

El resumen (insignias de riesgo, banner de riesgo global, cifras clave) se construye de
forma determinista en render.py a partir de state["iocs"]/["findings"]/["usage"], nunca a
partir del texto que redacta el LLM.
"""

from tfm_osint.report.render import (
    render_ioc_table_markdown,
    render_legend_html,
    render_markdown,
    render_methodology_markdown,
    render_summary_html,
    report_body,
)
from tfm_osint.state import IOC, DimensionRisk, Evidence, Finding, OSINTState, Usage


def _state(
    risks: list[str],
    n_verified: int = 0,
    n_findings: int = 0,
    evidence: list[Evidence] | None = None,
    findings: list[Finding] | None = None,
) -> OSINTState:
    iocs = [IOC(type="ip", value=f"1.2.3.{i}", risk=r) for i, r in enumerate(risks)]
    if findings is None:
        findings = [Finding(statement="x", verified=i < n_verified) for i in range(n_findings)]
    return {
        "target": "example.com",
        "iocs": iocs,
        "findings": findings,
        "evidence": evidence or [],
        "usage": Usage(provider="ollama", model="qwen2.5:7b", cost_usd=0.1234, latency_s=5.5),
    }


def test_summary_with_no_iocs_shows_neutral_banner():
    # Caso "investigación limpia": sin IOCs no debe aparecer un banner de riesgo alarmante.
    html = render_summary_html(_state([]))
    assert "No se detectaron indicadores de riesgo" in html
    assert "Riesgo global" not in html


def test_summary_banner_picks_most_severe_risk_present():
    # El banner debe mostrar el PEOR riesgo presente, no el primero ni una media.
    html = render_summary_html(_state(["low", "critical", "medium"]))
    assert "Riesgo global: CRÍTICO" in html


def test_summary_banner_elevated_by_verified_finding_without_matching_ioc():
    # El analyst no siempre convierte una ausencia de control en IOC, a veces se queda solo
    # en la prosa del reporter. Antes el banner solo miraba `iocs` y se quedaba en BAJO aunque
    # el informe dijera "riesgo crítico"; ahora debe elevarse también por una afirmación YA
    # VERIFICADA, aunque ningún IOC individual sea crítico.
    finding = Finding(statement="Falta DMARC, riesgo crítico", verified=True, risk="critical")
    html = render_summary_html(_state(["info", "low"], findings=[finding]))
    assert "Riesgo global: CRÍTICO" in html


def test_summary_banner_not_elevated_by_unverified_finding():
    # Caso simétrico y crítico para la seguridad del banner: una afirmación que el verifier
    # NO pudo confirmar no debe poder inflar un badge que se presenta como contenido de
    # confianza, si no fuera así, una alucinación del LLM ("riesgo crítico" sin respaldo)
    # bastaría para disparar el banner más alarmante posible.
    finding = Finding(statement="Alucinación sin respaldo", verified=False, risk="critical")
    html = render_summary_html(_state(["info", "low"], findings=[finding]))
    assert "Riesgo global: CRÍTICO" not in html
    assert "Riesgo global: BAJO" in html


def test_summary_badges_count_iocs_per_risk_level():
    # Las insignias ya no llevan el emoji de círculo Unicode como texto (ver _dot() en
    # render.py: un <span> con border-radius:50%, no un glifo), se comprueba por el color
    # de fondo del punto (RISK_STYLES[...]['border']) junto a la etiqueta y el recuento.
    html = render_summary_html(_state(["high", "high", "low"]))
    assert "background:#ec835a" in html and "Alto: 2" in html
    assert "background:#0ca30c" in html and "Bajo: 1" in html
    assert "Medio" not in html  # ningún IOC de ese nivel: no debe aparecer su insignia


def test_summary_omits_dimension_matrix_when_no_dimension_data():
    # Compatibilidad hacia atrás: un estado sin ningún IOC/finding con 'dimensions' (el caso
    # normal antes de esta función, o cualquier construcción directa en tests) no debe mostrar
    # una matriz vacía.
    html = render_summary_html(_state(["high"]))
    assert "Confidencialidad" not in html


def test_summary_dimension_matrix_counts_iocs_by_dimension_and_risk():
    state = _state([])
    state["iocs"] = [
        IOC(
            type="certificate",
            value="cert.example.com",
            dimensions=[
                DimensionRisk(dimension="confidencialidad", risk="high"),
                DimensionRisk(dimension="autenticidad", risk="medium"),
            ],
        )
    ]
    html = render_summary_html(state)
    assert "Confidencialidad" in html
    assert "Autenticidad" in html
    assert "Disponibilidad" in html  # dimensión educativa: la matriz siempre lista las 5 filas


def test_summary_dimension_matrix_only_counts_verified_findings():
    # Mismo criterio que top_risk(): una afirmación sin respaldo no debe poder aportar una
    # celda a la matriz, igual que no puede inflar el banner de riesgo global.
    unverified = Finding(
        statement="alucinación",
        verified=False,
        dimensions=[DimensionRisk(dimension="disponibilidad", risk="critical")],
    )
    state = _state([], findings=[unverified])
    html = render_summary_html(state)
    assert "Confidencialidad" not in html  # sin IOCs y el único finding no cuenta


def test_summary_quick_stats_included_by_default():
    # Las cifras clave (IOCs, verificadas, coste, latencia) deben poder leerse en el HTML.
    html = render_summary_html(_state(["low"], n_verified=1, n_findings=2))
    assert "1/2" in html
    assert "$0.1234" in html
    assert "5.5s" in html


def test_summary_quick_stats_can_be_excluded():
    html = render_summary_html(_state(["low"], n_verified=1, n_findings=2), include_quick_stats=False)
    assert "Coste estimado" not in html
    assert "Bajo: 1" in html  # el banner/insignias sí se mantienen


def test_render_markdown_embeds_the_risk_summary():
    # El documento exportado (.md/.pdf) debe llevar el resumen visual Y el texto del LLM,
    # no solo uno de los dos.
    state = _state(["critical"])
    state["report"] = "## Resumen ejecutivo\ntexto [E1]"
    markdown = render_markdown(state)
    assert "Riesgo global: CRÍTICO" in markdown
    assert "texto [E1]" in markdown


def test_legend_lists_all_five_risk_levels_regardless_of_iocs_present():
    # La leyenda es educativa (explica la escala completa), no un resumen de lo encontrado:
    # debe listar los 5 niveles aunque esta investigación solo tenga IOCs de uno.
    html = render_legend_html(_state(["low"]))
    for label in ("Crítico", "Alto", "Medio", "Bajo", "Info"):
        assert label in html


def test_legend_lists_all_five_dimensions_regardless_of_iocs_present():
    # Mismo criterio educativo que la leyenda de niveles: la leyenda de dimensiones se
    # muestra completa aunque esta investigación en concreto no tenga ningún IOC clasificado.
    html = render_legend_html(_state(["low"]))
    for label in ("Disponibilidad", "Confidencialidad", "Integridad", "Trazabilidad", "Autenticidad"):
        assert label in html


def test_legend_evidence_table_lists_id_and_source():
    # Sin esto, un lector no puede saber a qué se refiere una cita [E1] del informe.
    ev = [Evidence(id="E1", source="whois_domain", content="registrar: Example Inc.")]
    html = render_legend_html(_state([], evidence=ev))
    assert "E1" in html
    assert "whois_domain" in html
    assert "registrar: Example Inc." in html


def test_legend_evidence_table_escapes_untrusted_content():
    # La evidencia viene de fuentes externas (WHOIS/DNS/certificados) no controladas por el
    # sistema. Debe escaparse, no insertarse tal cual, para no abrir una XSS al mostrarse con
    # unsafe_allow_html=True en Streamlit.
    ev = [Evidence(id="E1", source="dns_lookup", content="<script>alert(1)</script>")]
    html = render_legend_html(_state([], evidence=ev))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_legend_handles_no_evidence():
    html = render_legend_html(_state([]))
    assert "No se recolectó evidencia citable" in html


def test_summary_shows_reliability_notice_when_findings_unverified():
    # Antes el aviso de "hay afirmaciones sin verificar" solo aparecía al final del
    # documento (Anexo de verificación); un lector que solo lea el principio (plausible con
    # tiempo limitado) se llevaba una impresión de fiabilidad que el informe contradice más
    # abajo. El resumen "de un vistazo" debe advertirlo también, cerca del banner de riesgo.
    html = render_summary_html(_state(["low"], n_verified=1, n_findings=3))
    assert "2" in html  # 3 findings - 1 verificado = 2 sin verificar
    assert "Anexo de verificación" in html


def test_summary_has_no_reliability_notice_when_all_verified():
    html = render_summary_html(_state(["low"], n_verified=2, n_findings=2))
    assert "Anexo de verificación" not in html


def test_summary_shows_target_mismatch_notice_when_target_never_mentioned():
    # Hallazgo real: un hash sin herramientas que lo admitieran acabó investigando
    # 'example.com' en su lugar, con citas válidas a evidencia real de ese otro objetivo.
    # El aviso de fiabilidad habitual no lo detecta (la evidencia SÍ está bien citada, solo
    # que no es del objetivo pedido). Este aviso comprueba algo distinto: si el propio
    # objetivo aparece mencionado en algún sitio del informe.
    state = _state([])
    state["target"] = "44d88612fea8a8f36de82e1278abb02f"
    state["report"] = "## Resumen ejecutivo\nEl dominio example.com no presenta riesgos [E1]."
    html = render_summary_html(state)
    assert "Aviso crítico" in html
    assert "44d88612fea8a8f36de82e1278abb02f" in html


def test_summary_has_no_target_mismatch_notice_when_target_is_mentioned():
    state = _state([])
    state["target"] = "example.com"
    state["report"] = "## Resumen ejecutivo\nEl dominio example.com no presenta riesgos [E1]."
    html = render_summary_html(state)
    assert "Aviso crítico" not in html


def test_ioc_table_generated_entirely_from_state_not_llm_text():
    # La tabla de IOCs ya no la redacta el LLM (ver nodes/reporter.py), se construye aquí
    # directamente desde IOC.risk, así que el riesgo mostrado no puede desincronizarse nunca
    # de RISK_STYLES (a diferencia del antiguo _sanitize_ioc_table, que corregía a posteriori
    # una tabla que el LLM podía seguir rellenando mal de otras formas).
    iocs = [IOC(type="ip", value="1.2.3.4", risk="critical", evidence_ids=["E1", "E2"])]
    table = render_ioc_table_markdown(iocs)
    # Sin emoji en la celda de riesgo: límite real de WeasyPrint/Pango con glifos de emoji a
    # color dentro de <td> (ver comentario en render_ioc_table_markdown), y esta tabla
    # también se muestra en Streamlit con st.markdown() sin unsafe_allow_html, donde un
    # <span> HTML (la alternativa que sí funciona en el resto del documento) saldría como
    # texto literal.
    assert "| ip | 1.2.3.4 | crítico | — | — | [E1], [E2] |" in table
    assert table.startswith("## Indicadores de compromiso (IOCs)")


def test_ioc_table_includes_dimensions_column():
    iocs = [
        IOC(
            type="certificate",
            value="cert.example.com",
            risk="high",
            dimensions=[
                DimensionRisk(dimension="confidencialidad", risk="high"),
                DimensionRisk(dimension="autenticidad", risk="medium"),
            ],
        )
    ]
    table = render_ioc_table_markdown(iocs)
    assert "Dimensiones" in table
    assert "confidencialidad (alto), autenticidad (medio)" in table


def test_ioc_table_dimensions_column_shows_dash_when_absent():
    # Un IOC sin desglose por dimensión (compatibilidad hacia atrás) no debe dejar la celda
    # vacía, sino con el mismo marcador '—' que ya usan Contexto/Evidencia.
    iocs = [IOC(type="ip", value="1.2.3.4", risk="low")]
    table = render_ioc_table_markdown(iocs)
    assert "| ip | 1.2.3.4 | bajo | — | — | — |" in table


def test_ioc_table_handles_no_iocs():
    table = render_ioc_table_markdown([])
    assert "No se detectaron IOCs" in table


def test_ioc_table_escapes_pipe_in_value():
    # Un valor de IOC con '|' rompería la tabla Markdown si no se escapa.
    iocs = [IOC(type="other", value="a|b", risk="info", evidence_ids=[])]
    table = render_ioc_table_markdown(iocs)
    assert "a\\|b" in table


def test_ioc_table_includes_context_column():
    # El analyst ya redacta 'context' (por qué es relevante) pero se descartaba al construir
    # la tabla, un lector no podía saber por qué figuraba un IOC sin leer toda la narrativa.
    iocs = [IOC(type="domain", value="example.com", risk="low", context="Dominio principal del objetivo")]
    table = render_ioc_table_markdown(iocs)
    assert "Contexto" in table
    assert "Dominio principal del objetivo" in table


def test_ioc_table_escapes_pipe_in_context():
    iocs = [IOC(type="other", value="x", risk="info", context="a|b")]
    table = render_ioc_table_markdown(iocs)
    assert "a\\|b" in table


def test_ioc_table_sorted_by_risk_severity_regardless_of_input_order():
    # Antes salían en el orden en que el analyst los generaba, sin relación con la gravedad:
    # un lector con prisa debe ver lo más crítico primero sin escanear la tabla entera.
    iocs = [
        IOC(type="ip", value="1.1.1.1", risk="low"),
        IOC(type="ip", value="2.2.2.2", risk="critical"),
        IOC(type="ip", value="3.3.3.3", risk="medium"),
    ]
    table = render_ioc_table_markdown(iocs)
    rows_order = [line for line in table.splitlines() if line.startswith("| ip")]
    assert [r.split("|")[2].strip() for r in rows_order] == ["2.2.2.2", "3.3.3.3", "1.1.1.1"]


def test_render_markdown_escapes_raw_html_reproduced_by_the_llm():
    # El texto del cuerpo (state["report"]/["draft"]) lo redacta el LLM a partir de evidencia
    # externa (WHOIS/DNS/certificados) no controlada por el sistema. render_pdf() procesa
    # este Markdown con MarkdownIt(html=True), así que cualquier HTML crudo que el LLM
    # reproduzca literalmente debe quedar neutralizado antes de llegar ahí, sin romper el
    # HTML de confianza que el propio código inserta (risk_summary/legend).
    state = _state(["critical"])
    state["report"] = '## Resumen ejecutivo\n<img src=x onerror="alert(1)"> [E1]'
    markdown = render_markdown(state)
    assert "<img src=x" not in markdown
    assert "&lt;img src=x" in markdown
    assert "Riesgo global: CRÍTICO" in markdown  # el HTML de confianza sigue sin escapar


def test_methodology_empty_when_no_query_or_plan():
    assert render_methodology_markdown(_state([])) == ""


def test_methodology_includes_query_and_plan():
    state = _state([])
    state["query"] = "Investiga certificados sospechosos"
    state["plan"] = ["Buscar en crt.sh", "Revisar WHOIS"]
    md = render_methodology_markdown(state)
    assert "## Metodología" in md
    assert "Investiga certificados sospechosos" in md
    assert "- Buscar en crt.sh" in md
    assert "- Revisar WHOIS" in md


def test_report_body_includes_methodology_when_present():
    # La Metodología debe llegar tanto al .md/.pdf exportado por la CLI (render_markdown())
    # como a Streamlit (report_body()), no solo a uno de los dos.
    state = _state([])
    state["query"] = "Investiga example.com"
    body = report_body(state)
    assert "## Metodología" in body
    assert "Investiga example.com" in body


def test_report_body_omits_methodology_section_when_absent():
    body = report_body(_state([]))
    assert "## Metodología" not in body


def test_report_body_inserts_deterministic_risk_level_line():
    # Hallazgo real del usuario: el mismo motor, sobre el mismo objetivo, ejecutado varias
    # veces seguidas, a veces escribía una línea de nivel de riesgo en su redacción y otras
    # veces no decía nada, dependía de que el LLM decidiera incluirla o no. Ahora la línea
    # la inserta el código, siempre, con el mismo nivel que ya muestra el banner visual.
    state = _state(["critical"])
    state["report"] = "## Resumen ejecutivo\ntexto [E1]\n\n## Evaluación de riesgo\njustificación [E1]"
    body = report_body(state)
    assert "**Nivel de Riesgo: Crítico**" in body
    # Justo debajo del encabezado, antes de la justificación del LLM.
    assert body.index("## Evaluación de riesgo") < body.index("**Nivel de Riesgo: Crítico**") < body.index(
        "justificación"
    )


def test_report_body_risk_level_line_says_no_risk_identified_without_iocs():
    state = _state([])
    state["report"] = "## Resumen ejecutivo\ntexto [E1]\n\n## Evaluación de riesgo\nsin hallazgos [E1]"
    body = report_body(state)
    assert "**Nivel de Riesgo: Sin riesgo identificado**" in body


def test_report_body_risk_level_line_is_never_sent_to_the_verifier():
    # La línea se inserta sobre state["report"]/["draft"] YA VERIFICADO (en render, no en el
    # reporter), así que nunca pasa por el verifier como una afirmación nueva del LLM que
    # necesitaría su propia cita. Este test fija ese contrato: state["report"] (lo que sí ve
    # el verifier antes de renderizar) no debe llevar la línea, solo el body ya renderizado.
    state = _state(["critical"])
    state["report"] = "## Resumen ejecutivo\ntexto [E1]\n\n## Evaluación de riesgo\njustificación [E1]"
    report_body(state)  # fuerza el render
    assert "Nivel de Riesgo" not in state["report"]


def test_render_markdown_escapes_target_in_header():
    # 'target' también viene de fuera (formulario o chat), aunque con menor riesgo que el
    # texto del LLM, igual debe escaparse antes de interpolarse en la cabecera.
    state = _state([])
    state["target"] = '<script>alert(1)</script>'
    markdown = render_markdown(state)
    assert "<script>alert(1)</script>" not in markdown
    assert "&lt;script&gt;" in markdown
