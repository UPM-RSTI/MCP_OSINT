"""Interfaz de línea de comandos (Typer)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from tfm_osint import history
from tfm_osint.config import get_settings
from tfm_osint.graph import run_pipeline
from tfm_osint.report import render_markdown, render_pdf, report_body

app = typer.Typer(help="Reporte automatizado de eventos OSINT de ciberseguridad con LLMs.")
console = Console()


@app.command()
def report(
    target: str = typer.Option(..., "--target", "-t", help="Objetivo (dominio, IP, hash…)."),
    provider: str = typer.Option(None, "--provider", "-p", help="LLM: claude | ollama | bedrock."),
    model: str = typer.Option(
        None,
        "--model",
        "-m",
        help="Id de modelo. Con --provider bedrock, elige entre varios motores "
        "(p. ej. Claude Sonnet o Amazon Nova Pro) — sin esto, usa TFM_BEDROCK_CLAUDE_MODEL.",
    ),
    query: str = typer.Option("", "--query", "-q", help="Instrucción en lenguaje natural."),
    out: Path = typer.Option(None, "--out", "-o", help="Ruta de salida (.md o .pdf)."),  # noqa: B008, patrón estándar de Typer, no un default mutable real
) -> None:
    """Genera un informe OSINT sobre TARGET."""
    settings = get_settings()
    provider = (provider or settings.llm_provider).lower()
    if not model:
        model = {
            "claude": settings.claude_model,
            "ollama": settings.ollama_model,
            "bedrock": settings.bedrock_claude_model,
        }.get(provider, settings.ollama_model)

    console.print(f"[bold cyan]Investigando[/] {target} con [bold]{provider}[/] ({model})…")
    state = asyncio.run(run_pipeline(target, provider, model, query))

    markdown = render_markdown(state)
    # report_body(), no "markdown": el historial se muestra en Streamlit con st.markdown()
    # normal (sin unsafe_allow_html), "markdown" trae embebido el HTML del resumen visual
    # (pensado para el .md/.pdf exportado, más abajo), que ahí saldría como texto crudo.
    run_id = history.save_run(state, report_body(state), query)

    _print_summary(state)
    console.print(f"[dim]Guardado en el historial (id {run_id}) — visible en la app con "
                  f"`streamlit run app.py` → 🗂️ Historial.[/]")

    if out is None:
        console.rule("Informe")
        console.print(markdown)
        return

    if out.suffix.lower() == ".pdf":
        render_pdf(markdown, out)
    else:
        out.write_text(markdown, encoding="utf-8")
    console.print(f"[green]Informe guardado en[/] {out}")


@app.command()
def tools() -> None:
    """Lista las herramientas OSINT descubiertas vía MCP."""
    from tfm_osint.mcp_client import load_tools

    discovered = asyncio.run(load_tools())
    table = Table(title=f"{len(discovered)} herramientas OSINT (MCP)")
    table.add_column("Herramienta", style="cyan")
    table.add_column("Descripción")
    for t in discovered:
        first = (t.description or "").strip().splitlines()
        table.add_row(t.name, (first[0] if first else "")[:70])
    console.print(table)


def _print_summary(state) -> None:
    u = state["usage"]
    table = Table(title="Resumen de ejecución")
    table.add_column("Métrica", style="cyan")
    table.add_column("Valor", justify="right")
    findings = state.get("findings", [])
    verified = sum(1 for f in findings if f.verified)
    table.add_row("IOCs", str(len(state.get("iocs", []))))
    table.add_row("Afirmaciones verificadas", f"{verified}/{len(findings)}")
    table.add_row("Llamadas a herramientas", str(u.tool_calls))
    table.add_row("Tokens (in/out)", f"{u.input_tokens}/{u.output_tokens}")
    table.add_row("Coste (USD)", f"{u.cost_usd:.4f}")
    table.add_row("Latencia (s)", f"{u.latency_s}")
    console.print(table)


if __name__ == "__main__":
    app()
