"""Frontend de demo (MVP2), Streamlit.

Uso:
    streamlit run app.py
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st
from streamlit.runtime.scriptrunner import add_script_run_ctx

from tfm_osint import history
from tfm_osint.chat_intent import extract_intent
from tfm_osint.config import get_settings
from tfm_osint.graph import run_pipeline
from tfm_osint.llm import get_llm
from tfm_osint.mcp_client import tool_summaries
from tfm_osint.report import (
    render_legend_html,
    render_pdf_bytes,
    render_summary_html,
    report_body,
)

st.set_page_config(page_title="TFM OSINT · Demo", page_icon="🔎", layout="wide")

st.markdown(
    """
    <style>
    /* Ancho responsive: Un ancho fijo dejaba solo un borde de la página visible. min() la limita al viewport
       disponible en cualquier dispositivo. */

    section[data-testid="stSidebar"] { width: min(340px, 88vw) !important; }
    section[data-testid="stSidebar"] > div:first-child {
        width: min(340px, 88vw) !important;
    }
    section[data-testid="stSidebar"] { background-color: rgba(232, 160, 143, 0.2); }

    /* Ancla el pie de página (.sidebar-footnote) al fondo real de la barra lateral,
       haya o no contenido por encima, sin forzar scroll cuando el contenido ya cabe:
       stSidebarContent (el contenedor con scroll real, overflow:auto) se convierte en
       flex-columna y stSidebarUserContent recibe flex: 1 en vez de una altura en
       porcentaje: así solo ocupa el espacio que sobra bajo la cabecera del menú, sin
       calcularlo a mano ni pasarse del alto disponible (lo que antes forzaba una barra
       de scroll incluso con contenido de sobra para caber). */

    div[data-testid="stSidebarContent"] {
        display: flex;
        flex-direction: column;
    }
    div[data-testid="stSidebarUserContent"] {
        display: flex;
        flex-direction: column;
        flex: 1;
        min-height: 0;
    }
    /* Entre stSidebarUserContent y stVerticalBlock, Streamlit mete un div propio sin
       data-testid (su nombre de clase real no es estable entre versiones), hay que
       encadenar el flex a través de él, no solo declararlo en stVerticalBlock. */

    div[data-testid="stSidebarUserContent"] > div {
        display: flex;
        flex-direction: column;
        flex: 1;
        min-height: 0;
    }
    div[data-testid="stSidebarUserContent"] div[data-testid="stVerticalBlock"] {
        display: flex;
        flex-direction: column;
        flex: 1;
        min-height: 0;
    }
    div[data-testid="stSidebarUserContent"] div[data-testid="stVerticalBlock"] > div:has(.sidebar-footnote) {
        margin-top: auto;
    }

    div[data-testid="stRadio"] > div[role="radiogroup"] {
        display: flex;
        flex-direction: column;
        gap: 4px;
        width: 100%;
    }

    div[data-testid="stRadio"] label {
        display: flex !important;
        align-items: center;
        width: 100% !important;
        box-sizing: border-box;
        padding: 10px 14px;
        border-radius: 10px;
        cursor: pointer;
        transition: background-color .15s ease;
    }
    div[data-testid="stRadio"] label:hover { background-color: rgba(232, 160, 143, 0.04); }
    div[data-testid="stRadio"] label > *:first-child { display: none !important; }
    div[data-testid="stRadio"] label p { font-size: 1.02rem; margin: 0; }
    div[data-testid="stRadio"] label:has(input:checked) { background-color: #E8A08F; }
    div[data-testid="stRadio"] label:has(input:checked) p { color: #ffffff; font-weight: 600; }

    .sidebar-footnote {
        padding-top: 1.5rem;
        font-size: 0.72rem;
        line-height: 1.5;
        color: #8a94a6;
    }

    /* Icono girando por CSS puro (@keyframes): el navegador anima el círculo por su
       cuenta, sin que Python espere ni bloquee nada. Solo se usa dentro de fragmentos con
       auto-refresco (`run_every`), nunca en un bucle propio. */
    .tfm-spin {
        display: inline-block;
        width: 13px;
        height: 13px;
        border: 2px solid rgba(31, 111, 235, 0.25);
        border-top-color: #1F6FEB;
        border-radius: 50%;
        animation: tfm-spin-kf 0.8s linear infinite;
        vertical-align: middle;
        margin-right: 8px;
    }
    @keyframes tfm-spin-kf { to { transform: rotate(360deg); } }
    .tfm-notice-info {
        background-color: rgba(31, 111, 235, 0.08);
        border-left: 4px solid #1F6FEB;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

_SECTIONS = [
    "⛑️ Nuevo diagnóstico",
    "🛡️ Simulador SIEM",
    "🛠️ Herramientas MCP",
    "🗂️ Historial",
    "📊 Comparativa",
]


_KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_KAFKA_TOPIC = "osint-events"


def _start_diagnostic_job(target: str, engine: str, provider: str, model: str, query: str) -> None:
    """Lanza el diagnóstico en un hilo aparte y deja su estado en
    ``st.session_state["diagnostic_job"]`` en vez de bloquear el script.

    El hilo se liga a la sesión con `add_script_run_ctx` (forma documentada por Streamlit
    para que escribir en `st.session_state` desde un hilo aparte llegue a la sesión correcta)
    y el resultado se deja en `session_state` para que cualquier sección pueda leerlo en
    cualquier rerun futuro.
    """
    job = {
        "target": target, "engine": engine, "provider": provider, "model": model,
        "query": query, "status": "running", "started_at": time.time(),
        "state": None, "body_text": None, "error": None,
    }
    st.session_state["diagnostic_job"] = job
    # Registro compartido entre procesos (ver history.start_job), es lo que permite que
    # _running_job_notice() detecte este diagnóstico incluso desde otro proceso (p. ej.
    # kafka_consumer.py comprobándolo antes de procesar un evento nuevo).
    job_id = history.start_job(target, "Nuevo diagnóstico")

    def _worker() -> None:
        try:
            state = asyncio.run(run_pipeline(target, provider, model, query))
            body_text = report_body(state)
            history.save_run(state, body_text, query)
        except Exception as exc:  # noqa: BLE001, se muestra en la UI, no debe tumbar el hilo
            st.session_state["diagnostic_job"] = {**job, "status": "error", "error": str(exc)}
        else:
            st.session_state["diagnostic_job"] = {
                **job, "status": "done", "state": state, "body_text": body_text,
            }
        finally:
            history.finish_job(job_id)

    thread = threading.Thread(target=_worker, daemon=True)
    add_script_run_ctx(thread)
    thread.start()


def _spin_icon() -> str:
    """Span con el icono giratorio (`.tfm-spin`, CSS puro, ver el `<style>` global), nunca
    se usa fuera de un `st.fragment(run_every=...)`, para no confundirlo con los intentos
    anteriores de animar con una espera bloqueante."""
    return '<span class="tfm-spin"></span>'


def _info_box_html(inner_html: str) -> str:
    """Caja azul (`.tfm-notice-info`) para envolver un aviso con el icono giratorio.
    ``inner_html`` debe llegar ya escapado en cualquier parte que provenga del usuario
    (objetivo, motor…), ver `html.escape()` en cada punto de uso."""
    return f'<div class="tfm-notice-info">{inner_html}</div>'


def _running_job_notice() -> str | None:
    """Aviso listo para mostrar si YA hay un diagnóstico en curso, en cualquier proceso.

    Consulta ``history.get_active_job()``, una tabla SQLite compartida, no
    ``st.session_state``, para detectar también un diagnóstico disparado por el Simulador
    SIEM y ejecutado en `kafka_consumer.py`, un proceso Python aparte que no comparte
    session_state con Streamlit.
    """
    active = history.get_active_job()
    if active is None:
        return None
    return f'Ya hay un diagnóstico en curso desde "{active["source"]}" ({active["target"]}) — espera a que termine.'


with st.sidebar:
    st.title("TFM · Demo")

    section = st.radio("Navegación", _SECTIONS, label_visibility="collapsed")

    st.markdown(
        "<div class='sidebar-footnote'>"
        "Sistema multiagente (LangGraph + MCP) con motor LLM intercambiable. "
        "Pipeline: planner → collector → analyst → reporter → verifier.<br><br>"
        "</div>",
        unsafe_allow_html=True,
    )

st.title("🔎 Reporte OSINT automatizado con LLMs")
st.header(section)

settings = get_settings()


def _claude_bedrock_label(model: str) -> str:
    """Nombre legible para el motor Claude vía Bedrock, derivado del id de modelo configurado.

    No se fija a "Sonnet": `TFM_BEDROCK_CLAUDE_MODEL` puede apuntar a cualquier variante de
    Claude (Haiku, Sonnet, Opus...) según lo que la cuenta de AWS tenga concedido en "Model
    access", con una etiqueta fija el selector podría mentir sobre qué modelo se usa de
    verdad, y el nombre del motor identifica qué produjo cada informe en la comparativa.
    """
    lowered = model.lower()
    for variant in ("opus", "sonnet", "haiku"):
        if variant in lowered:
            return f"Claude {variant.capitalize()} (Bedrock)"
    return "Claude (Bedrock)"


def _engines() -> dict[str, tuple[str, str]]:
    """Motores LLM seleccionables: nombre legible -> (provider, model).

    "claude" (API directa de Anthropic) no se ofrece aquí a propósito: sin
    ANTHROPIC_API_KEY configurada no serviría de nada mostrarlo en el selector. Los motores de
    Bedrock comparten `provider="bedrock"`; lo que los distingue es el modelo.
    """
    return {
        "Ollama (local)": ("ollama", settings.ollama_model),
        _claude_bedrock_label(settings.bedrock_claude_model): ("bedrock", settings.bedrock_claude_model),
        "Amazon Nova Pro (Bedrock)": ("bedrock", settings.bedrock_nova_model),
        "Qwen3 Next 80B (Bedrock)": ("bedrock", settings.bedrock_qwen_model),
    }



_EVAL_ENGINE_LABELS = {
    "ollama": "Ollama (local)",
    "nova": "Amazon Nova Pro (Bedrock)",
    "qwen": "Qwen3 Next 80B (Bedrock)",
}


def _eval_engine_label(key: str) -> str:
    if key == "haiku":
        return _claude_bedrock_label(settings.bedrock_claude_model)
    return _EVAL_ENGINE_LABELS.get(key, key)


def _latest_eval_results() -> list[dict] | None:
    """Filas de la evaluación formal más reciente (`evaluation/run_eval.py --judge`), o
    ``None`` si todavía no se ha lanzado ninguna. Se relee del disco en cada rerun de
    Streamlit a propósito (sin `st.cache_data`), son pocos KB y así una evaluación nueva se
    refleja sin tener que reiniciar la app."""
    results_dir = Path(__file__).parent / "evaluation" / "results"
    files = sorted(results_dir.glob("eval-*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text(encoding="utf-8"))


def _eval_summary_by_engine(rows: list[dict]) -> dict[str, dict[str, float | None]]:
    """Media de métricas por motor, mismo criterio que run_eval.py::_print_table()."""
    by_engine: dict[str, list[dict]] = {}
    for r in rows:
        if "error" not in r:
            by_engine.setdefault(r["engine"], []).append(r)

    def avg(erows: list[dict], key: str) -> float | None:
        vals = [p[key] for p in erows if key in p]
        return sum(vals) / len(vals) if vals else None

    return {
        engine: {
            "n_casos": len(erows),
            "ioc_recall": avg(erows, "ioc_recall"),
            "hallucination_rate": avg(erows, "hallucination_rate"),
            "judge_media": avg(erows, "judge_media"),
            "cost_usd": avg(erows, "cost_usd"),
            "latency_s": avg(erows, "latency_s"),
        }
        for engine, erows in by_engine.items()
    }


def _best_engine_label() -> str | None:
    """Motor con mejor resultado medio en la última evaluación formal, o ``None`` si aún no
    hay ninguna (en ese caso, el selector se queda en "Ollama (local)" como hasta ahora).

    Criterio: puntuación media del juez primero, tasa de alucinación como desempate.
    `judge_media` integra utilidad/exactitud/accionabilidad/claridad juntas, un informe
    vacío o poco útil puntúa bajo ahí aunque no cite nada erróneo, así que no premia por sí
    solo al motor que simplemente investiga y afirma menos. No se usa coste ni latencia como
    criterio, son datos informativos en la tabla, no el motivo para elegir un motor por
    defecto.
    """
    rows = _latest_eval_results()
    if not rows:
        return None
    summary = _eval_summary_by_engine(rows)
    if not summary:
        return None

    def score(s: dict[str, float | None]) -> tuple[float, float]:
        judge = s["judge_media"] if s["judge_media"] is not None else 0.0
        halluc = s["hallucination_rate"] if s["hallucination_rate"] is not None else 1.0
        return (-judge, halluc)

    best_key = min(summary, key=lambda k: score(summary[k]))
    return _eval_engine_label(best_key)


def _default_engine_index() -> int:
    """Índice del motor por defecto en los selectores de Simulador SIEM/Nuevo diagnóstico: el
    de mejor resultado en la última evaluación formal si existe, si no el primero (Ollama),
    igual que antes de que hubiera ninguna evaluación con la que decidir."""
    labels = list(_engines().keys())
    best = _best_engine_label()
    if best and best in labels:
        return labels.index(best)
    return 0


@st.cache_data(show_spinner="🔍 Descubriendo herramientas MCP…")
def _tool_summaries() -> list[dict[str, str]]:
    """Nombre + descripción de cada herramienta MCP real, cacheado."""
    return asyncio.run(tool_summaries())


@st.cache_data(show_spinner="📄 Generando PDF…")
def _run_pdf_bytes(run_id: int, full_markdown: str) -> bytes:
    """PDF de un diagnóstico del Historial, cacheado por id.

    Sin este cacheado, Streamlit regeneraría el PDF de TODOS los diagnósticos visibles en
    cada recarga de la pestaña Historial (p. ej. al pulsar "Eliminar" en uno distinto), no
    solo del que se pulse, cada recarga ejecuta el script entero de nuevo. `run_id` en la
    firma es lo que hace que el cacheado sea por diagnóstico, no uno global para todos.
    """
    return render_pdf_bytes(full_markdown)


_SIEM_EJEMPLOS = [
    (
        "Firewall perimetral: 1200 paquetes SYN en 30s hacia el puerto 22 desde "
        "185.220.101.45 (nodo de salida Tor conocido) — posible escaneo o fuerza bruta."
    ),
    (
        "Feed de threat intel (OTX): nuevo IOC publicado hoy, dominio "
        "secure-paypal-verify-account.com, categoría phishing."
    ),
    (
        "Buzón de abuse@: un usuario reporta un correo de phishing con enlace a "
        "login-microsoft365-support.net suplantando al departamento de IT."
    ),
    (
        "Certificate Transparency: nuevo certificado emitido para "
        "vpn-corp-update.example-attacker.com, subdominio no reconocido de nuestro dominio."
    ),
]


def _publish_siem_event(target: str, query: str, provider: str, model: str) -> None:
    """Publica un evento en el topic ``osint-events`` de Kafka, mismo formato y broker que
    ``scripts/siem_simulador.py``/``scripts/kafka_produce_test_event.py``.

    Disparo puro: confirma que el *broker* aceptó el evento y no espera nada más, ni a que
    ``kafka_consumer.py`` lo procese ni al resultado del diagnóstico. Es justo el concepto que
    esta sección demuestra: un SIEM real dispara una alerta y sigue, no se queda esperando una
    respuesta síncrona.

    Importa ``aiokafka`` de forma perezosa porque es una dependencia opcional (extra ``kafka``
    en ``pyproject.toml``), sin ella instalada, esta función da un error legible en vez de
    romper la importación de toda la app.
    """
    try:
        from aiokafka import AIOKafkaProducer
    except ImportError as exc:
        raise RuntimeError(
            "Falta el extra 'kafka' (uv sync --extra kafka) para publicar eventos en Kafka."
        ) from exc

    async def _send() -> None:
        producer = AIOKafkaProducer(bootstrap_servers=_KAFKA_BOOTSTRAP_SERVERS)
        await producer.start()
        try:
            event = {"target": target, "query": query, "provider": provider, "model": model}
            await producer.send_and_wait(_KAFKA_TOPIC, json.dumps(event).encode("utf-8"))
        finally:
            await producer.stop()

    asyncio.run(_send())


# --------------------------------------------------------------------------- Simulador SIEM

if section == "🛡️ Simulador SIEM":
    st.caption(
        "🛰️ Simula alertas de seguridad como las que dispararía un SIEM real (firewall, feed "
        "de *threat intel*, correo de *phishing* reportado, Certificate Transparency…)." 
    )
    st.caption(
        "El resultado aparecerá en 🗂️ Historial cuando el consumidor lo procese, no aquí."
    )

    siem_engine = st.selectbox(
        "Motor LLM del diagnóstico", list(_engines().keys()), index=_default_engine_index(),
        key="siem_engine",
    )
    siem_provider, siem_model = _engines()[siem_engine]

    if "siem_alerts" not in st.session_state:
        st.session_state.siem_alerts = []

    with st.expander("💡 Ejemplos de alerta"):
        for ejemplo in _SIEM_EJEMPLOS:
            st.markdown(f"- {ejemplo}")

    with st.form("siem_alert", clear_on_submit=True):
        alert_text = st.text_area(
            "Alerta de seguridad",
            placeholder="Ej: Firewall perimetral: 1200 paquetes SYN en 30s hacia el puerto 22 "
            "desde 185.220.101.45 — posible fuerza bruta.",
            height=100,
        )
        submitted = st.form_submit_button("📡 Publicar alerta")

    if submitted:
        alert_text = alert_text.strip()
        if not alert_text:
            st.error("Escribe una alerta.")
        else:
            entry: dict[str, str] = {"alert": alert_text}
            intent = extract_intent(lambda: get_llm(siem_provider, siem_model), alert_text)
            if intent.needs_clarification or not intent.target:

                entry["status"] = "sin_objetivo"
                entry["detail"] = intent.reply or "No se reconoció ningún objetivo en la alerta."
            else:
                entry["target"] = intent.target
                entry["query"] = intent.instruction
                try:
                    _publish_siem_event(intent.target, intent.instruction, siem_provider, siem_model)
                except Exception as exc:  # noqa: BLE001, mostrar el fallo en el feed, no romper la página
                    entry["status"] = "error"
                    entry["detail"] = str(exc)
                else:
                    entry["status"] = "publicado"
                    # Marca de tiempo para poder distinguir, más abajo, un diagnóstico YA
                    # completado en el Historial de otro anterior con el mismo objetivo:
                    # sin esto, una alerta repetida sobre el mismo target podría darse por
                    # completada usando el resultado de una ejecución previa, no la suya.
                    entry["published_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            st.session_state.siem_alerts.insert(0, entry)


    @st.fragment(run_every=5)
    def _siem_status_fragment() -> None:
        active = history.get_active_job()
        if active is not None:
            if active["source"] == "Simulador SIEM":

                safe_target = html.escape(active["target"])
                st.markdown(
                    _info_box_html(
                        f"{_spin_icon()}Evento recibido → investigando "
                        f"<b>{safe_target}</b>… Si publicas otra alerta ahora, se procesará "
                        "justo después de esta, en orden."
                    ),
                    unsafe_allow_html=True,
                )
            else:
                # El job activo viene de OTRO proceso, el consumidor espera (con un límite,
                # ver kafka_consumer.py::_wait_for_other_job) en vez de descartar de inmediato.
                st.warning(
                    f'⚠️ Ya hay un diagnóstico en curso desde "{active["source"]}" '
                    f'({active["target"]}) — si publicas una alerta ahora, el consumidor '
                    "esperará a que termine y la procesará después (hasta 15 min, después de lo cual se descarta)."
                )

        if not st.session_state.siem_alerts:
            return
        runs = history.list_runs()
        for entry in st.session_state.siem_alerts:
            status = entry["status"]
            if status == "publicado":
                completed = next(
                    (
                        r
                        for r in runs
                        if r.target == entry["target"] and r.created_at > entry["published_at"]
                    ),
                    None,
                )
                if completed is not None:
                    st.success(
                        f"✅ Diagnóstico completado para **{entry['target']}** "
                        f"(#{completed.id}) — consúltalo en 🗂️ Historial."
                    )
                else:
                    st.success(
                        f"📡 **{entry['target']}** — evento publicado en `osint-events`. "
                        f"Instrucción: _{entry['query']}_"
                    )
            elif status == "sin_objetivo":
                st.warning(f"⚠️ Sin objetivo reconocible — {entry['detail']}")
            else:
                st.error(f"✖️ No se pudo publicar: {entry['detail']}")
            st.caption(f"Alerta original: {entry['alert']}")
            st.divider()

    _siem_status_fragment()

# --------------------------------------------------------------------- Nuevo diagnóstico

elif section == "⛑️ Nuevo diagnóstico":
    with st.form("diagnostico"):
        target = st.text_input("Objetivo (dominio, IP, hash…)", placeholder="example.com")
        engine = st.selectbox(
            "Motor LLM", list(_engines().keys()), index=_default_engine_index()
        )
        query = st.text_area(
            "Instrucción (opcional)",
            placeholder="Investiga… (si se deja vacío, se usa un informe estándar)",
        )
        submitted = st.form_submit_button("▶️ Ejecutar diagnóstico")

    job = st.session_state.get("diagnostic_job")

    if submitted:
        target = target.strip()
        if not target:
            st.error("Indica un objetivo.")
        elif (notice := _running_job_notice()) is not None:
            st.warning(notice)
        else:
            provider, model = _engines()[engine]
            _start_diagnostic_job(target, engine, provider, model, query.strip())
            st.rerun()  # refleja "running" ya mismo, sin esperar a la siguiente interacción

    # Se lee de session_state, no de variables locales de este rerun: así el resultado sigue
    # visible aunque el usuario haya cambiado de sección y vuelto mientras corría.
    #
    # El fragmento con auto-refresco solo pinta el aviso de "investigando…", no el informe
    # completo del caso "done" (eso sigue fuera, con rerun natural), si repintara también el
    # informe cada 5s, parpadearía y perdería la posición de scroll mientras se lee.
    @st.fragment(run_every=5)
    def _diagnostico_running_fragment() -> None:
        job = st.session_state.get("diagnostic_job")
        if job and job["status"] == "running":
            safe_target = html.escape(job["target"])
            safe_engine = html.escape(job["engine"])
            st.markdown(
                _info_box_html(
                    f"{_spin_icon()}Investigando <b>{safe_target}</b> con {safe_engine}…"
                ),
                unsafe_allow_html=True,
            )

    _diagnostico_running_fragment()

    if job and job["status"] == "error":
        st.error(f"✖️ El diagnóstico falló: {job['error']}")
    elif job and job["status"] == "done":
        state = job["state"]
        body_text = job["body_text"]
        usage = state["usage"]
        findings = state.get("findings", [])
        n_verified = sum(1 for f in findings if f.verified)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IOCs", len(state.get("iocs", [])))
        c2.metric("Afirmaciones verificadas", f"{n_verified}/{len(findings)}")
        c3.metric("Coste (USD)", f"{usage.cost_usd:.4f}")
        c4.metric("Latencia (s)", usage.latency_s)
        # unsafe_allow_html=True es seguro: este fragmento lo construye nuestro
        # propio código a partir de state["iocs"], nunca a partir del texto del LLM.
        st.markdown(
            render_summary_html(state, include_quick_stats=False),
            unsafe_allow_html=True,
        )
        with st.expander("📖 Leyenda: niveles de riesgo y evidencias"):
            st.markdown(render_legend_html(state), unsafe_allow_html=True)
        st.markdown(body_text)
        if st.button("🧹 Nueva consulta"):
            st.session_state["diagnostic_job"] = None
            st.rerun()

# --------------------------------------------------------------------- Herramientas MCP

elif section == "🛠️ Herramientas MCP":
    st.caption("Herramientas OSINT descubiertas vía MCP (badchars/osint-mcp-server).")
    if st.button("⟳ Recargar herramientas"):
        st.cache_data.clear()

    try:
        tools_data = [
            {"Herramienta": t["name"], "Descripción": t["description"]}
            for t in _tool_summaries()
        ]
    except Exception as exc:  # noqa: BLE001, degradar, no romper la pestaña
        st.error(f"✖️ No se pudieron cargar las herramientas MCP: {exc}")
    else:
        st.write(f"**{len(tools_data)} herramientas disponibles.**")
        row_h, header_h, padding = 35, 38, 3
        table_height = header_h + row_h * len(tools_data) + padding
        st.dataframe(tools_data, width="stretch", hide_index=True, height=table_height)

# --------------------------------------------------------------------- Historial

elif section == "🗂️ Historial":
    runs = history.list_runs()
    if not runs:
        st.info("👀 Aún no hay diagnósticos guardados.")
    for run in runs:
        header = f"#{run.id} · {run.target} · {run.provider} · {run.created_at}"
        with st.expander(header):

            _, download_col, delete_col = st.columns([8, 0.8, 1.2], gap="xxsmall")
            with download_col:
                if run.full_markdown:
                    # Si WeasyPrint/pango no están disponibles, degradar con un aviso en vez
                    # de romper toda la pestaña.
                    try:
                        pdf_bytes = _run_pdf_bytes(run.id, run.full_markdown)
                    except Exception as exc:  # noqa: BLE001, degradar, no romper el Historial
                        st.caption(f"✖️ PDF no disponible: {exc}")
                    else:
                        st.download_button(
                            "📥 PDF",
                            data=pdf_bytes,
                            file_name=f"informe_{run.target}_{run.id}.pdf",
                            mime="application/pdf",
                            key=f"download_{run.id}",
                        )
                else:

                    st.caption("PDF no disponible para este diagnóstico (anterior a esta función).")
            with delete_col:
                if st.button("🗑️ Eliminar", key=f"delete_{run.id}"):
                    history.delete_run(run.id)
                    st.rerun()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("IOCs", run.n_iocs)
            c2.metric("Verificadas", f"{run.n_verified}/{run.n_findings}")
            c3.metric("Coste (USD)", f"{run.cost_usd:.4f}")
            c4.metric("Latencia (s)", run.latency_s)
            if run.summary_html:
                # unsafe_allow_html=True seguro: guardado en save_run() a partir de
                # state["iocs"] estructurado, nunca del texto del LLM (ver history.py).
                st.markdown(run.summary_html, unsafe_allow_html=True)
            if run.legend_html:
                with st.expander("📖 Leyenda: niveles de riesgo y evidencias"):
                    st.markdown(run.legend_html, unsafe_allow_html=True)
            st.markdown(run.markdown)

# --------------------------------------------------------------------------- Comparativa

elif section == "📊 Comparativa":
    st.caption(
        "Resultado de la última evaluación formal (`evaluation/run_eval.py --judge`): "
        "métricas automáticas (recall de IOCs, tasa de alucinación) más el juicio de un LLM "
        "independiente de los 4 motores evaluados sobre cada informe generado."
    )
    eval_rows = _latest_eval_results()

    if not eval_rows:
        st.info(
            "👀 Todavía no se ha lanzado ninguna evaluación formal. Ejecuta desde la terminal:\n\n"
            "`python evaluation/run_eval.py --engines ollama haiku nova qwen --judge`"
        )
    else:
        summary = _eval_summary_by_engine(eval_rows)
        n_casos = len({r["case"] for r in eval_rows if "case" in r})
        best = _best_engine_label()

        st.caption(
            f"Basado en {n_casos} caso(s) del dataset "
            "(`evaluation/dataset/cases.json`) — amplíalo para una comparación más robusta."
        )

        table_rows = [
            {
                "Motor": f"⭐ {_eval_engine_label(key)}"
                if _eval_engine_label(key) == best
                else _eval_engine_label(key),
                "Casos": s["n_casos"],
                "Recall de IOCs": f"{s['ioc_recall']:.0%}" if s["ioc_recall"] is not None else "—",
                "Tasa de alucinación": (
                    f"{s['hallucination_rate']:.0%}" if s["hallucination_rate"] is not None else "—"
                ),
                "Juez (1-5)": f"{s['judge_media']:.2f}" if s["judge_media"] is not None else "—",
                "Coste medio (USD)": f"{s['cost_usd']:.4f}",
                "Latencia media (s)": f"{s['latency_s']:.1f}",
            }
            for key, s in summary.items()
        ]
        st.dataframe(table_rows, hide_index=True, width="stretch")

        if best:
            st.success(
                f"✅ Motor con mejor resultado: **{best}** — usado por defecto en "
                "los selectores de motor (criterio: puntuación del juez, tasa de "
                "alucinación como desempate)."
            )

        # Filas con error (p. ej. un motor sin credenciales configuradas), visibles aparte,
        # no mezcladas silenciosamente con las métricas de arriba.
        error_rows = [r for r in eval_rows if "error" in r]
        if error_rows:
            with st.expander(f"⚠️ {len(error_rows)} caso(s) con error"):
                for r in error_rows:
                    st.caption(f"{r.get('engine', '?')} · {r.get('case', '?')}: {r['error']}")

    st.divider()
    st.caption(
        "Para una comparativa más amplia (30-50 ejecuciones reales por motor, sin juez "
        "formal pero con mucho más volumen) — ver la memoria del TFM."
    )
