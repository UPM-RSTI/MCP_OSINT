"""Pruebas de nodes/_common.py::structured() (lógica pura + fallback, sin red).

Cubre el caso en que el camino de reserva (JSON en texto libre) devuelve una clave mal
capitalizada, `model_validate` la rechazaría por un campo "ausente" que en realidad estaba
mal escrito. `_normalize_top_level_keys()` corrige esto antes de validar.
"""

from langchain_core.messages import AIMessage
from pydantic import BaseModel

from tfm_osint.nodes._common import _normalize_top_level_keys, structured
from tfm_osint.state import Usage


class _Item(BaseModel):
    value: str


class _ItemList(BaseModel):
    items: list[_Item]


def test_normalize_top_level_keys_fixes_case_mismatch():
    fixed = _normalize_top_level_keys({"ITEMS": [{"value": "x"}]}, _ItemList)
    assert fixed == {"items": [{"value": "x"}]}


def test_normalize_top_level_keys_leaves_correct_keys_unchanged():
    data = {"items": [{"value": "x"}]}
    assert _normalize_top_level_keys(data, _ItemList) == data


def test_normalize_top_level_keys_leaves_unknown_keys_unchanged():
    # Una clave que no coincide con el esquema ni siquiera sin distinguir mayúsculas no debe
    # tocarse, solo se corrige mayúsculas/minúsculas, no se inventa un mapeo.
    fixed = _normalize_top_level_keys({"otracosa": 1}, _ItemList)
    assert fixed == {"otracosa": 1}


def test_normalize_top_level_keys_ignores_non_dict_input():
    assert _normalize_top_level_keys([1, 2, 3], _ItemList) == [1, 2, 3]


class _FakeLLM:
    """LLM falso: with_structured_output() falla, y el camino de reserva devuelve JSON con
    la clave en mayúsculas distintas al esquema."""

    def with_structured_output(self, schema, include_raw=True):
        raise NotImplementedError("modelo simulado sin salida estructurada nativa")

    def invoke(self, prompt: str) -> AIMessage:
        return AIMessage(
            content='{"ITEMS": [{"value": "x"}]}',
            usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        )


def test_structured_fallback_survives_key_case_mismatch():
    # Sin _normalize_top_level_keys(), esto lanzaría ValidationError: 'items' Field required.
    result = structured(_FakeLLM(), _ItemList, "prompt de prueba")
    assert result.items == [_Item(value="x")]


def test_structured_fallback_accumulates_usage():
    usage = Usage(provider="bedrock", model="qwen.qwen3-next-80b-a3b")
    structured(_FakeLLM(), _ItemList, "prompt de prueba", usage=usage)
    assert usage.input_tokens == 1
    assert usage.output_tokens == 1
