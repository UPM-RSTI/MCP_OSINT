"""Simulador manual de SIEM, en versión de consola: equivalente a la sección "🛡️ Simulador
SIEM" del frontend, reutilizando exactamente el mismo componente de extracción de objetivo.

Pide alertas de seguridad en texto libre por consola, con la pinta de una alerta real de un
SIEM, un feed de threat intel o un correo de phishing reportado, y usa
`chat_intent.py::extract_intent()` para identificar el objetivo (dominio, IP…). En vez de
invocar `run_pipeline()` directamente, publica el resultado en el topic `osint-events` de
Kafka, para que sea `kafka_consumer.py`, corriendo aparte, sin saber de dónde viene el
evento, quien dispare el diagnóstico. El esquema completo queda así:

    alerta en texto libre → extract_intent() → osint-events → kafka_consumer.py → grafo → Historial

No modifica `app.py` ni `chat_intent.py`, reutiliza `extract_intent()` tal cual.

Requiere Kafka arrancado y `scripts/kafka_consumer.py` corriendo aparte en otra terminal.

Uso interactivo (una alerta por línea, Enter en vacío para salir):
    uv run python scripts/siem_simulador.py

Una sola alerta, sin modo interactivo:
    uv run python scripts/siem_simulador.py --alert "Firewall: 1200 SYN en 30s hacia el \
puerto 22 desde 185.220.101.45, posible fuerza bruta"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

from aiokafka import AIOKafkaProducer

from tfm_osint.chat_intent import extract_intent
from tfm_osint.config import get_settings
from tfm_osint.llm import get_llm

BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "osint-events"

# Alertas de ejemplo con la pinta de fuentes reales (SIEM, feed de threat intel, phishing
# reportado, Certificate Transparency), solo como referencia rápida en el modo interactivo.
_EJEMPLOS = [
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


def _print_ejemplos() -> None:
    print("Ejemplos de alerta que puedes pegar tal cual:")
    for i, ejemplo in enumerate(_EJEMPLOS, 1):
        print(f"  {i}. {ejemplo}")
    print()


async def _publish(
    producer: AIOKafkaProducer, target: str, query: str, provider: str, model: str
) -> None:
    event = {"target": target, "query": query, "provider": provider, "model": model}
    await producer.send_and_wait(TOPIC, json.dumps(event).encode("utf-8"))
    print(f"  → publicado en '{TOPIC}': {event}")


async def _process_alert(
    alert: str, provider: str, model: str, producer: AIOKafkaProducer
) -> None:
    """Identifica el objetivo de una alerta y, si lo hay, publica el evento en Kafka.

    Reutiliza `extract_intent()` sin modificarlo, patrón "regex primero, LLM de respaldo",
    así que la mayoría de alertas con un dominio o IP reconocible ni siquiera necesitan una
    llamada al LLM.
    """
    intent = extract_intent(lambda: get_llm(provider, model), alert)
    if intent.needs_clarification or not intent.target:
        # Filtro "blando" heredado gratis de extract_intent(): si no reconoce un objetivo
        # claro, no se publica nada.
        print(f"  (sin objetivo reconocible, no se publica evento) — {intent.reply}")
        return
    print(f"  objetivo identificado: {intent.target!r} — instrucción: {intent.instruction!r}")
    await _publish(producer, intent.target, intent.instruction, provider, model)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--alert", default="", help="Una sola alerta; si se omite, modo interactivo.")
    parser.add_argument(
        "--provider", default="bedrock", help="Proveedor para extract_intent() (por defecto, bedrock)."
    )
    parser.add_argument("--model", default="", help="Modelo (por defecto, el Claude Haiku configurado).")
    args = parser.parse_args()

    settings = get_settings()
    model = args.model or settings.bedrock_claude_model

    producer = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP_SERVERS)
    await producer.start()
    try:
        if args.alert:
            await _process_alert(args.alert, args.provider, model, producer)
            return

        print("=== Simulador de alerta de SIEM ===")
        print("Pega una alerta de seguridad en texto libre y pulsa Enter.")
        print("extract_intent() identifica el objetivo y lo publica en Kafka.\n")
        _print_ejemplos()
        while True:
            try:
                alert = input("Alerta> ").strip()
            except EOFError:
                break
            if not alert:
                break
            await _process_alert(alert, args.provider, model, producer)
            print()
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
