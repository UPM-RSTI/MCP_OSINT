"""Ejecuta el pipeline sobre el dataset y produce las métricas de evaluación.

Por defecto (fase 1, gratuita): proveedor Ollama local y SIN LLM-as-judge, de modo que no
hace falta ninguna clave de pago.

    python evaluation/run_eval.py                                    # ollama, sin juez (gratis)
    python evaluation/run_eval.py --engines ollama haiku nova qwen --judge   # comparativa completa

Resultados en evaluation/results/ (JSON detallado + CSV agregado) y por consola.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json

# Importes del paquete de evaluación (mismo directorio).
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from tfm_osint.config import get_settings
from tfm_osint.graph import run_pipeline

sys.path.insert(0, str(Path(__file__).parent))
from judge import judge_report
from metrics import compute_metrics

DATASET = Path(__file__).parent / "dataset" / "cases.json"
RESULTS_DIR = Path(__file__).parent / "results"
console = Console()


def _engines() -> dict[str, tuple[str, str]]:
    """Motores evaluables: nombre corto -> (provider, model).

    Mismo conjunto de motores que `app.py::_engines()`, pero definido aquí en vez de
    importado desde `app.py`, `app.py` llama a `st.set_page_config()` en tiempo de import,
    lo que rompería un script de terminal como este.
    """
    settings = get_settings()
    return {
        "ollama": ("ollama", settings.ollama_model),
        "haiku": ("bedrock", settings.bedrock_claude_model),
        "nova": ("bedrock", settings.bedrock_nova_model),
        "qwen": ("bedrock", settings.bedrock_qwen_model),
    }


def load_cases() -> list[dict]:
    return json.loads(DATASET.read_text(encoding="utf-8"))["cases"]


async def eval_case(case: dict, engine: str, provider: str, model: str, use_judge: bool) -> dict:
    state = await run_pipeline(case["target"], provider, model, case.get("query", ""))
    metrics = compute_metrics(state, case.get("expected_iocs", []))
    row = {
        "case": case["id"],
        "engine": engine,
        "provider": provider,
        "model": model,
        **metrics.as_dict(),
    }
    if use_judge:
        from tfm_osint.report import render_markdown

        score = judge_report(render_markdown(state), case["target"], case.get("expected_facts", []))
        row.update(
            {
                "judge_media": score.media,
                "judge_utilidad": score.utilidad,
                "judge_exactitud": score.exactitud,
                "judge_accionabilidad": score.accionabilidad,
                "judge_claridad": score.claridad,
            }
        )
    return row


async def main_async(engine_keys: list[str], use_judge: bool) -> None:
    engines = _engines()
    cases = load_cases()
    rows: list[dict] = []

    for key in engine_keys:
        if key not in engines:
            console.print(f"[red]Motor desconocido:[/] {key!r} — usa uno de {list(engines)}")
            continue
        provider, model = engines[key]
        for case in cases:
            console.print(f"[cyan]{key}[/] ({provider}/{model}) · {case['id']} → {case['target']}")
            try:
                rows.append(await eval_case(case, key, provider, model, use_judge))
            except Exception as exc:  # noqa: BLE001, un caso no debe abortar el barrido
                console.print(f"[red]  fallo:[/] {exc}")
                rows.append({"case": case["id"], "engine": key, "error": str(exc)})

    _write_results(rows)
    _print_table(rows)


def _write_results(rows: list[dict]) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    (RESULTS_DIR / f"eval-{stamp}.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    fields = sorted({k for r in rows for k in r})
    with (RESULTS_DIR / f"eval-{stamp}.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    console.print(f"[green]Resultados guardados en[/] {RESULTS_DIR}/eval-{stamp}.[json|csv]")


def _avg(erows: list[dict], key: str) -> str:
    vals = [p[key] for p in erows if key in p]
    return f"{sum(vals) / len(vals):.3f}" if vals else "—"


def _print_table(rows: list[dict]) -> None:
    table = Table(title="Comparativa de motores (media por motor)")
    for col in ["engine", "ioc_recall", "hallucination_rate", "judge_media", "cost_usd", "latency_s"]:
        table.add_column(col)
    by_engine: dict[str, list[dict]] = {}
    for r in rows:
        if "error" not in r:
            by_engine.setdefault(r["engine"], []).append(r)
    for engine, erows in by_engine.items():
        table.add_row(
            engine,
            _avg(erows, "ioc_recall"),
            _avg(erows, "hallucination_rate"),
            _avg(erows, "judge_media"),
            _avg(erows, "cost_usd"),
            _avg(erows, "latency_s"),
        )
    console.print(table)


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluación del pipeline OSINT.")
    # Fase 1 (gratuita): Ollama local y sin juez por defecto.
    p.add_argument(
        "--engines",
        nargs="+",
        default=["ollama"],
        help="ollama haiku nova qwen (combina varios, p. ej. --engines ollama haiku nova qwen)",
    )
    p.add_argument(
        "--judge",
        action="store_true",
        help="Activa el LLM-as-judge (DeepSeek V3.2 vía Bedrock — requiere AWS_BEARER_TOKEN_BEDROCK).",
    )
    args = p.parse_args()
    asyncio.run(main_async(args.engines, use_judge=args.judge))


if __name__ == "__main__":
    main()
