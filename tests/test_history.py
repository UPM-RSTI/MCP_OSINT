"""Pruebas de la migración de esquema y la persistencia del historial (SQLite temporal)."""

import sqlite3

from tfm_osint import history as history_module
from tfm_osint.state import Usage


def _fake_state() -> dict:
    return {"target": "example.com", "usage": Usage(provider="ollama", model="qwen2.5:7b")}


def test_migration_adds_new_columns_without_losing_existing_rows(tmp_path, monkeypatch):
    # Simula una base de datos de una versión anterior (solo el esquema base, sin
    # full_markdown/tool_calls) con una fila ya guardada, la migración debe añadir las
    # columnas nuevas sin perder esa fila, mismo patrón que ya se usaba para
    # summary_html/legend_html.
    db_path = tmp_path / "history.db"
    conn = sqlite3.connect(db_path)
    conn.execute(history_module._SCHEMA)
    conn.execute(
        "INSERT INTO runs (created_at, target, provider, model, markdown) "
        "VALUES ('2026-01-01T00:00:00', 'old.example.com', 'ollama', 'qwen2.5:7b', 'texto')"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(history_module, "DB_PATH", db_path)
    runs = history_module.list_runs()

    assert len(runs) == 1
    assert runs[0].target == "old.example.com"
    assert runs[0].full_markdown == ""  # valor por defecto, no se pierde ni rompe la lectura
    assert runs[0].tool_calls == 0


def test_save_run_stores_full_escaped_markdown(tmp_path, monkeypatch):
    # El documento completo (ya escapado por render_markdown()) debe quedar disponible para
    # poder exportarlo a PDF más tarde desde el Historial sin volver a ejecutar el pipeline.
    # Ver report/render.py::render_markdown y el botón "Descargar PDF" en app.py.
    monkeypatch.setattr(history_module, "DB_PATH", tmp_path / "history.db")

    run_id = history_module.save_run(_fake_state(), "cuerpo del informe", "investiga esto")
    runs = history_module.list_runs()

    assert runs[0].id == run_id
    assert "example.com" in runs[0].full_markdown
    assert "## Metadatos de ejecución" in runs[0].full_markdown
