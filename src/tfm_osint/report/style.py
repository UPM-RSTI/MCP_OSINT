"""Identidad visual compartida de los informes PDF y de las insignias de riesgo reutilizadas
tanto en el PDF como en las vistas de Streamlit.

``RISK_STYLES``/``RISK_ORDER`` son el único origen de verdad de los colores de riesgo:
``report/render.py`` los usa para construir HTML con estilos en línea, ya que en Streamlit no
hay una hoja de estilos `<head>` a la que enlazar una clase CSS.
"""

from __future__ import annotations

RISK_STYLES: dict[str, dict[str, str]] = {
    "info": {
        "emoji": "⚪", "label": "Info", "ink": "#16233a", "bg": "#eef1f4", "border": "#c7cdd6",
        "desc": "dato informativo, sin riesgo asociado.",
    },
    "low": {
        "emoji": "🟢", "label": "Bajo", "ink": "#16233a", "bg": "#e3f7e3", "border": "#0ca30c",
        "desc": "riesgo mínimo, no requiere acción.",
    },
    "medium": {
        "emoji": "🟡", "label": "Medio", "ink": "#16233a", "bg": "#fef3d9", "border": "#fab219",
        "desc": "riesgo moderado, conviene vigilarlo.",
    },
    "high": {
        "emoji": "🟠", "label": "Alto", "ink": "#16233a", "bg": "#fce4da", "border": "#ec835a",
        "desc": "riesgo significativo, revisar con prioridad.",
    },
    "critical": {
        "emoji": "🔴", "label": "Crítico", "ink": "#16233a", "bg": "#f9dcdc", "border": "#d03b3b",
        "desc": "riesgo muy alto, requiere atención inmediata.",
    },
}

# De más a menos grave, usado para elegir el "riesgo global" (el primero presente).
RISK_ORDER = ["critical", "high", "medium", "low", "info"]

# Las 5 dimensiones de un análisis de riesgo (MAGERIT/ENS): a qué propiedad de seguridad
# concreta afecta un IOC/afirmación. Sin color propio (a diferencia de RISK_STYLES): el color
# de cada celda de la matriz sale del nivel de riesgo en esa dimensión, no de la dimensión.
DIMENSION_LABELS: dict[str, dict[str, str]] = {
    "disponibilidad": {
        "label": "Disponibilidad",
        "desc": "el servicio o dato deja de estar accesible cuando hace falta.",
    },
    "confidencialidad": {
        "label": "Confidencialidad",
        "desc": "información que debería ser privada queda expuesta.",
    },
    "integridad": {
        "label": "Integridad",
        "desc": "un dato o sistema puede ser modificado sin autorización.",
    },
    "trazabilidad": {
        "label": "Trazabilidad",
        "desc": "no queda registro fiable de quién hizo qué y cuándo.",
    },
    "autenticidad": {
        "label": "Autenticidad",
        "desc": "no se puede verificar que algo (un remitente, un servidor) es quien dice ser.",
    },
}
DIMENSION_ORDER = ["confidencialidad", "integridad", "disponibilidad", "autenticidad", "trazabilidad"]

# CSS de página para los documentos PDF completos generados vía render_pdf().
REPORT_CSS = """
@page { size: A4; margin: 2.2cm 2cm; }
* { box-sizing: border-box; }
body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1a2233;
       line-height: 1.5; font-size: 10.5pt; }
h1 { font-size: 20pt; color: #16233a; margin: 0 0 4px; line-height: 1.15; }
h2 { font-size: 14pt; color: #16233a; margin: 22px 0 8px; padding-bottom: 4px;
     border-bottom: 2px solid #2563c9; }
h3 { font-size: 11.5pt; color: #2b3446; margin: 14px 0 4px; }
p { margin: 6px 0; }
strong { color: #16233a; }
code { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 9pt;
       background: #f1f4f8; padding: 1px 4px; border-radius: 3px;
       overflow-wrap: anywhere; word-break: break-word; }
pre { background: #f1f4f8; padding: 10px 12px; border-radius: 6px; overflow-x: auto;
      font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 8.5pt; line-height: 1.4; }
pre code { background: none; padding: 0; overflow-wrap: normal; word-break: normal; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 9pt;
        table-layout: fixed; }
tr { break-inside: avoid; }
th, td { border: 1px solid #d3dae4; padding: 5px 8px; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; word-break: break-word; }
th { background: #eef2f7; color: #16233a; font-size: 8pt; text-transform: uppercase;
     letter-spacing: .03em; }
hr { border: none; border-top: 1px solid #dbe1ea; margin: 20px 0; }
ul { margin: 6px 0; padding-left: 20px; }
li { margin: 3px 0; }
img { max-width: 100%; display: block; margin: 14px auto 4px; }
p em { color: #5a6577; font-size: 9pt; }
"""
