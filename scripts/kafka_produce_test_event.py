"""Publica un único evento OSINT de prueba en el topic `osint-events`, para probar a mano que
`kafka_consumer.py` dispara el pipeline solo, sin tocar Streamlit ni la CLI.

Uso:
    uv run python scripts/kafka_produce_test_event.py --target example.com
    uv run python scripts/kafka_produce_test_event.py --target 8.8.8.8 --query "¿riesgo?" \
        --provider bedrock --model eu.anthropic.claude-haiku-4-5-20251001-v1:0
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

from aiokafka import AIOKafkaProducer

BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "osint-events"


async def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", required=True, help="Objetivo a investigar (dominio, IP…).")
    p.add_argument("--query", default="", help="Instrucción opcional.")
    p.add_argument("--provider", default="", help="Proveedor (por defecto, el del consumidor).")
    p.add_argument("--model", default="", help="Modelo (por defecto, el del consumidor).")
    args = p.parse_args()

    event = {"target": args.target}
    if args.query:
        event["query"] = args.query
    if args.provider:
        event["provider"] = args.provider
    if args.model:
        event["model"] = args.model

    producer = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS)
    await producer.start()
    try:
        await producer.send_and_wait(TOPIC, json.dumps(event).encode("utf-8"))
        print(f"[kafka] evento publicado en '{TOPIC}': {event}")
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
