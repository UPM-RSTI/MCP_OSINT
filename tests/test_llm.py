"""Pruebas de lógica pura de llm.py (sin instanciar ningún cliente LLM real).

Las ramas de get_llm() por proveedor solo se pueden verificar de verdad con una llamada real
a cada API, no con mocks. Lo que sí se presta a test unitario es la lógica determinista que
no depende de red, como esta.
"""

from tfm_osint.llm import _bedrock_region_for


def test_bedrock_region_for_uses_override_for_known_model():
    # Qwen3 Next 80B A3B no está disponible en eu-north-1, necesita us-east-1 aunque el
    # resto de la cuenta esté configurada para eu-north-1.
    assert _bedrock_region_for("qwen.qwen3-next-80b-a3b", "eu-north-1") == "us-east-1"


def test_bedrock_region_for_falls_back_to_default_for_unknown_model():
    assert _bedrock_region_for("eu.anthropic.claude-haiku-4-5-20251001-v1:0", "eu-north-1") == "eu-north-1"
