"""Persistencia ligera del historial de diagnósticos del frontend de demo (MVP2).

No forma parte del pipeline ni de la evaluación cuantitativa (`evaluation/`); solo
guarda lo necesario para listar, ver y borrar diagnósticos pasados desde `app.py`.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from tfm_osint.config import PROJECT_ROOT
from tfm_osint.report.render import render_legend_html, render_markdown, render_summary_html
from tfm_osint.state import OSINTState

HISTORY_DIR = PROJECT_ROOT / "history"
DB_PATH = HISTORY_DIR / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    -- El texto del informe (report_body(state): LLM + anexo de verificación), NO el
    -- documento completo de render_markdown(): ese incrusta HTML (el resumen visual) que
    -- Streamlit no renderiza aquí (se muestra con st.markdown() normal, sin
    -- unsafe_allow_html); saldría como texto crudo. Ver report/render.py::report_body().
    markdown TEXT NOT NULL,
    n_iocs INTEGER NOT NULL DEFAULT 0,
    n_findings INTEGER NOT NULL DEFAULT 0,
    n_verified INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    latency_s REAL NOT NULL DEFAULT 0
);
"""

# Columnas añadidas después de la creación inicial de la tabla: CREATE TABLE IF NOT EXISTS
# no las añade a una base de datos ya existente, así que se migran a mano en _connect().
# summary_html/legend_html: fragmentos HTML calculados una vez al guardar, para pintarlos con
# unsafe_allow_html=True sin renderizar el Markdown completo (con texto del LLM) como HTML.
# full_markdown: el documento completo de render_markdown(state), ya escapado, para exportar
# un diagnóstico pasado a PDF sin tener que reconstruirlo a partir de piezas sueltas.
_MIGRATIONS: dict[str, str] = {
    "summary_html": "ALTER TABLE runs ADD COLUMN summary_html TEXT NOT NULL DEFAULT ''",
    "legend_html": "ALTER TABLE runs ADD COLUMN legend_html TEXT NOT NULL DEFAULT ''",
    "full_markdown": "ALTER TABLE runs ADD COLUMN full_markdown TEXT NOT NULL DEFAULT ''",
    "tool_calls": "ALTER TABLE runs ADD COLUMN tool_calls INTEGER NOT NULL DEFAULT 0",
}

# Tabla aparte para saber si hay un diagnóstico en curso ahora mismo, sea cual sea el
# proceso que lo lanzó, a diferencia de `runs` (solo diagnósticos ya terminados), esto es
# lo único que Streamlit (`app.py`) y `kafka_consumer.py` comparten de verdad entre sí: dos
# procesos de Python distintos, sin `st.session_state` en común.
_ACTIVE_JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS active_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL
);
"""

# Margen por encima del peor caso observado en la evaluación formal antes de considerar
# huérfano un registro de active_jobs, protege contra un proceso que muere sin llegar a su
# `finally` (kill -9, crash).
_STALE_JOB_SECONDS = 1200


@dataclass
class RunRecord:
    id: int
    created_at: str
    target: str
    provider: str
    model: str
    query: str
    markdown: str
    n_iocs: int
    n_findings: int
    n_verified: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_s: float
    summary_html: str = ""
    legend_html: str = ""
    full_markdown: str = ""
    tool_calls: int = 0


@contextmanager
def _connect():
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(_SCHEMA)
        conn.execute(_ACTIVE_JOB_SCHEMA)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
        for column, ddl in _MIGRATIONS.items():
            if column not in existing:
                conn.execute(ddl)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_run(state: OSINTState, markdown: str, query: str = "") -> int:
    """Guarda un diagnóstico completado y devuelve el id asignado.

    ``markdown``: el texto del informe para mostrar en Streamlit, usar
    ``report.report_body(state)``, no ``report.render_markdown(state)`` (ver comentario
    en el esquema de la tabla, más arriba).
    """
    usage = state["usage"]
    findings = state.get("findings", [])
    n_verified = sum(1 for f in findings if f.verified)
    summary_html = render_summary_html(state, include_quick_stats=False)
    legend_html = render_legend_html(state)
    full_markdown = render_markdown(state)
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO runs
               (created_at, target, provider, model, query, markdown,
                n_iocs, n_findings, n_verified, input_tokens, output_tokens,
                cost_usd, latency_s, summary_html, legend_html, full_markdown, tool_calls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(UTC).isoformat(timespec="seconds"),
                state["target"],
                usage.provider,
                usage.model,
                query,
                markdown,
                len(state.get("iocs", [])),
                len(findings),
                n_verified,
                usage.input_tokens,
                usage.output_tokens,
                usage.cost_usd,
                usage.latency_s,
                summary_html,
                legend_html,
                full_markdown,
                usage.tool_calls,
            ),
        )
        return cur.lastrowid


def list_runs() -> list[RunRecord]:
    """Devuelve los diagnósticos guardados, más recientes primero."""
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
    return [RunRecord(**dict(row)) for row in rows]


def delete_run(run_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))


def start_job(target: str, source: str) -> int:
    """Registra el inicio de un diagnóstico en ``active_jobs``, visible para CUALQUIER
    proceso que use este módulo (Streamlit, ``kafka_consumer.py``), no solo el que lo lanzó.
    ``source`` es solo descriptivo (p. ej. "Nuevo diagnóstico", "Simulador SIEM") para poder
    identificar el origen en el aviso. Devuelve el id de la fila, a pasar a ``finish_job()``
    cuando termine, SIEMPRE en un ``finally``, tanto si el diagnóstico acaba bien como si
    falla, para no dejar el registro huérfano.
    """
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO active_jobs (target, source, started_at) VALUES (?, ?, ?)",
            (target, source, datetime.now(UTC).isoformat(timespec="seconds")),
        )
        return cur.lastrowid


def finish_job(job_id: int) -> None:
    """Borra el registro de ``start_job()``."""
    with _connect() as conn:
        conn.execute("DELETE FROM active_jobs WHERE id = ?", (job_id,))


def get_active_job() -> dict[str, str] | None:
    """El diagnóstico en curso ahora mismo, de cualquier origen y cualquier proceso, o
    ``None`` si no hay ninguno. De paso, limpia cualquier registro más viejo de
    ``_STALE_JOB_SECONDS``, un proceso que muere sin pasar por ``finish_job()`` (kill -9,
    crash) dejaría, si no, el sistema bloqueado para siempre creyendo que sigue habiendo un
    diagnóstico en marcha que en realidad ya no existe.
    """
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM active_jobs ORDER BY id DESC").fetchall()
        now = datetime.now(UTC)
        result: dict[str, str] | None = None
        for row in rows:
            started_at = datetime.fromisoformat(row["started_at"])
            if (now - started_at).total_seconds() > _STALE_JOB_SECONDS:
                conn.execute("DELETE FROM active_jobs WHERE id = ?", (row["id"],))
                continue
            if result is None:
                result = {
                    "target": row["target"],
                    "source": row["source"],
                    "started_at": row["started_at"],
                }
    return result
