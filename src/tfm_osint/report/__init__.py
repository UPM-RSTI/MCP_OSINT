"""Renderizado de informes (Markdown y PDF)."""

from tfm_osint.report.render import (
    render_legend_html,
    render_markdown,
    render_pdf,
    render_pdf_bytes,
    render_summary_html,
    report_body,
    top_risk,
)

__all__ = [
    "render_legend_html",
    "render_markdown",
    "render_pdf",
    "render_pdf_bytes",
    "render_summary_html",
    "report_body",
    "top_risk",
]
