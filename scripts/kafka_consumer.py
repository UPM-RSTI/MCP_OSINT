"""Prueba de concepto: dispara el pipeline OSINT automáticamente al consumir un evento de
Kafka, en vez de solo bajo petición del usuario (CLI/Streamlit).

Alcance deliberadamente acotado, un consumidor secuencial simple para demostrar que la
arquitectura es extensible a un disparo por evento sin tocar el pipeline en sí (el punto de
entrada es el mismo `run_pipeline()` que ya usan `app.py`/`cli.py`). No es un sistema de
streaming en producción: sin cola con concurrencia real, sin límite de tasa, sin deduplicación
de objetivos ya investigados.

Requiere el extra [kafka] (`uv sync --extra kafka`) y un broker Kafka accesible en
KAFKA_BOOTSTRAP_SERVERS (por defecto localhost:9092) con el topic `osint-events` ya creado:

    /opt/homebrew/opt/kafka/bin/kafka-server-start /opt/homebrew/etc/kafka/server.properties
    /opt/homebrew/opt/kafka/bin/kafka-topics --create --topic osint-events \
        --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1

Uso:
    uv run python scripts/kafka_consumer.py

Cada mensaje del topic es un JSON: {"target": "example.com", "query"?: "...",
"provider"?: "...", "model"?: "..."}, target es obligatorio, el resto usa el motor por
defecto de este script (Claude Haiku 4.5 vía Bedrock) si no se especifica.
"""

from __future__ import annotations

import asyncio
import json
import os

from aiokafka import AIOKafkaConsumer

from tfm_osint import history
from tfm_osint.config import get_settings
from tfm_osint.graph import run_pipeline
from tfm_osint.report import report_body

BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "osint-events"
GROUP_ID = "tfm-osint-consumer"


# Cuánto esperar (sondeando cada _POLL_INTERVAL_S) a que se libere un diagnóstico en curso en
# OTRO proceso antes de descartar el evento. Entre dos eventos del propio consumidor esto
# nunca hace falta, `main()` los procesa de forma estrictamente secuencial; solo aplica
# cuando el job en curso lo lanzó otro proceso (Streamlit, "Nuevo diagnóstico"), que no
# comparte la cola de Kafka. Límite generoso por encima del peor caso observado en la
# evaluación formal, para no esperar eternamente si ese otro proceso se queda colgado.
_MAX_WAIT_FOR_OTHER_JOB_S = 900
_POLL_INTERVAL_S = 5


async def _wait_for_other_job(target: str) -> bool:
    """Espera a que se libere cualquier diagnóstico en curso en otro proceso.

    `asyncio.sleep()`, no `time.sleep()`, no bloquea el *event loop*, así que los
    *heartbeats* del consumidor de Kafka se siguen mandando con normalidad durante la espera.

    Devuelve ``True`` si quedó libre a tiempo, ``False`` si se agotó
    ``_MAX_WAIT_FOR_OTHER_JOB_S`` (el evento se descarta, como antes).
    """
    waited = 0
    warned = False
    while True:
        active = history.get_active_job()
        if active is None:
            return True
        if not warned:
            print(
                f"[kafka] evento para {target!r} en espera: ya hay un diagnóstico en curso "
                f"desde {active['source']!r} ({active['target']!r}) — se procesará en cuanto "
                "termine.",
                flush=True,
            )
            warned = True
        if waited >= _MAX_WAIT_FOR_OTHER_JOB_S:
            return False
        await asyncio.sleep(_POLL_INTERVAL_S)
        waited += _POLL_INTERVAL_S


def _run_pipeline_in_own_loop(target: str, provider: str, model: str, query: str) -> object:
    """Ejecuta `run_pipeline()` en su propio *event loop* nuevo, pensado para lanzarse en un
    hilo aparte vía `asyncio.to_thread()`, no en el hilo/loop principal.

    `nodes/reporter.py::reporter_node()` y el camino de reserva de
    `nodes/_common.py::structured()` llaman a `llm.invoke()` de forma síncrona. Para la CLI,
    Streamlit o `run_eval.py` eso no importa, cada uno tiene su propio `asyncio.run()`
    aislado. Pero aquí el consumidor de Kafka necesita que su *event loop* esté libre para
    mandar *heartbeats* al coordinador de forma continua; si `run_pipeline()` se ejecuta en
    ese mismo *loop*, cada llamada síncrona al LLM lo bloquea por completo y el consumidor
    deja de mandar *heartbeats*. Aislar el *pipeline* en un hilo de verdad, con su propio
    *event loop*, resuelve esto sin tocar el código del *pipeline*.
    """
    return asyncio.run(run_pipeline(target, provider, model, query))


async def _handle_event(raw: bytes) -> None:
    """Procesa un evento; nunca propaga la excepción, un evento mal formado o un fallo del
    pipeline no debe tumbar el consumidor (mismo principio que ya aplica `run_eval.py` por
    caso: un fallo puntual no debe abortar el resto del barrido/consumo)."""
    job_id: int | None = None
    try:
        event = json.loads(raw)
        target = (event.get("target") or "").strip()
        if not target:
            print(f"[kafka] evento sin 'target', descartado: {raw!r}", flush=True)
            return

        # Mismo guard de "un diagnóstico a la vez" que ya respeta app.py: espera (con
        # límite, ver `_wait_for_other_job`) a que el otro proceso termine y procesa el
        # evento después, en vez de descartarlo de inmediato.
        if not await _wait_for_other_job(target):
            print(
                f"[kafka] evento para {target!r} descartado: seguía habiendo un diagnóstico "
                f"en curso tras esperar {_MAX_WAIT_FOR_OTHER_JOB_S}s.",
                flush=True,
            )
            return

        settings = get_settings()
        provider = event.get("provider") or "bedrock"
        model = event.get("model") or settings.bedrock_claude_model
        query = event.get("query") or ""

        print(f"[kafka] evento recibido → investigando {target!r} con {provider}/{model}…", flush=True)
        job_id = history.start_job(target, "Simulador SIEM")
        # asyncio.to_thread(), no `await run_pipeline(...)` directo, ver el docstring de
        # `_run_pipeline_in_own_loop` para el motivo real (heartbeats de Kafka bloqueados).
        state = await asyncio.to_thread(_run_pipeline_in_own_loop, target, provider, model, query)
        body = report_body(state)
        run_id = history.save_run(state, body, query)

        n_iocs = len(state.get("iocs", []))
        usage = state["usage"]
        print(
            f"[kafka] diagnóstico #{run_id} completado para {target!r}: "
            f"{n_iocs} IOC(s), {usage.latency_s}s, ${usage.cost_usd:.4f} "
            "— ya visible en el Historial.",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001, un evento no debe tumbar el consumidor
        print(f"[kafka] fallo procesando evento {raw!r}: {exc}", flush=True)
    finally:
        if job_id is not None:
            history.finish_job(job_id)


async def main() -> None:
    consumer = AIOKafkaConsumer(
        TOPIC,
        bootstrap_servers=BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        auto_offset_reset="latest",  # solo eventos nuevos, no reprocesar el historial del topic
    )
    await consumer.start()
    print(f"[kafka] escuchando '{TOPIC}' en {BOOTSTRAP_SERVERS} (Ctrl+C para salir)…", flush=True)
    try:
        async for msg in consumer:
            await _handle_event(msg.value)
    finally:
        await consumer.stop()


if __name__ == "__main__":
    asyncio.run(main())
