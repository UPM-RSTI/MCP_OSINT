"""Pruebas del reconocimiento determinista de objetivos en alertas SIEM (sin red ni LLM)."""

from tfm_osint import chat_intent as chat_intent_module
from tfm_osint.chat_intent import (
    _DEFAULT_CLARIFICATION_REPLY,
    ChatIntent,
    extract_intent,
    extract_target_regex,
)


def test_extracts_domain_from_natural_message():
    # Caso de uso principal: texto libre de alerta con instrucción + dominio mezclados.
    msg = "investiga example.com y dime si tiene certificados sospechosos"
    assert extract_target_regex(msg) == "example.com"


def test_extracts_subdomain():
    # Un dominio con varios niveles (subdominio + TLD compuesto) debe reconocerse entero.
    msg = "quiero un informe sobre mail.example.co.uk"
    assert extract_target_regex(msg) == "mail.example.co.uk"


def test_extracts_ipv4():
    msg = "revisa la IP 8.8.8.8 por favor"
    assert extract_target_regex(msg) == "8.8.8.8"


def test_extracts_md5_hash():
    msg = "he encontrado este hash: 5d41402abc4b2a76b9719d911017c592"
    assert extract_target_regex(msg) == "5d41402abc4b2a76b9719d911017c592"


def test_extracts_sha256_hash():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert extract_target_regex(f"analiza {h}") == h


def test_prioritizes_hash_over_domain_pattern():
    # Un hash no debe confundirse con un dominio aunque el mensaje también mencione uno.
    h = "44d88612fea8a8f36de82e1278abb02f"
    msg = f"compara este hash {h} con lo que sepas de example.com"
    assert extract_target_regex(msg) == h


def test_ignores_common_spanish_abbreviations():
    # "p.ej" no debe reconocerse como dominio (etiqueta de un solo carácter).
    msg = "hazme un informe de seguridad, p.ej. sobre riesgos generales"
    assert extract_target_regex(msg) is None


def test_returns_none_when_nothing_found():
    # Sin esto, un mensaje ambiguo lanzaría el pipeline sobre un objetivo inventado en vez
    # de pedir aclaración (ver extract_intent(), que recurre al LLM solo cuando esto pasa).
    assert extract_target_regex("hazme un informe de seguridad") is None


def test_chat_intent_defaults():
    # Documenta los valores por defecto del esquema: útil porque extract_intent() los
    # asume implícitamente (p. ej. needs_clarification=False salvo que se marque explícito).
    intent = ChatIntent()
    assert intent.target == ""
    assert intent.needs_clarification is False
    assert intent.reply == ""


def test_extract_intent_skips_llm_when_regex_already_found_a_target():
    # El caso más frecuente (y el más barato): si el regex ya reconoce el objetivo, la
    # fábrica get_llm ni siquiera debe invocarse, no debe pagarse el coste de instanciar
    # el cliente LLM cuando no hace falta.
    calls = []
    intent = extract_intent(lambda: calls.append(1), "investiga example.com por favor")
    assert intent.target == "example.com"
    assert calls == []


def test_extract_intent_falls_back_to_llm_when_regex_fails(monkeypatch):
    # Rama antes sin ningún test: un mensaje ambiguo para el regex ("mi empresa") debe
    # recurrir al LLM, que aquí sí reconoce un objetivo.
    fake_result = ChatIntent(target="empresa.com", instruction="", needs_clarification=False)
    monkeypatch.setattr(chat_intent_module, "structured", lambda *a, **k: fake_result)

    intent = extract_intent(lambda: object(), "investiga mi empresa por posibles filtraciones")

    assert intent.target == "empresa.com"
    assert intent.needs_clarification is False
    # instruction vacía del LLM se rellena con el mensaje original tal cual.
    assert intent.instruction == "investiga mi empresa por posibles filtraciones"


def test_extract_intent_needs_clarification_when_llm_finds_nothing_either(monkeypatch):
    # Aunque el LLM no marque needs_clarification, un target vacío debe forzarlo, no se
    # debe lanzar el pipeline sin un objetivo claro.
    fake_result = ChatIntent(target="", instruction="", needs_clarification=False)
    monkeypatch.setattr(chat_intent_module, "structured", lambda *a, **k: fake_result)

    intent = extract_intent(lambda: object(), "hazme un informe de seguridad")

    assert intent.needs_clarification is True


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeLLM:
    """LLM falso con `.invoke()`, para probar `_generate_natural_reply` (llm.invoke() normal,
    no `structured()`), ver el comentario junto a `_INTENT_PROMPT` sobre por qué la redacción
    de la respuesta natural es una segunda llamada aparte, más simple para el modelo local."""

    def __init__(self, reply: str) -> None:
        self._reply = reply

    def invoke(self, prompt: str) -> _FakeMessage:
        return _FakeMessage(self._reply)


def test_extract_intent_uses_the_second_calls_natural_reply(monkeypatch):
    # La nota para el analista debe sonar natural, no soltar siempre la misma plantilla,
    # la extracción (structured()) solo decide que hace falta aclarar; la redacción de la
    # frase es responsabilidad de la segunda llamada (`_generate_natural_reply`, un
    # `llm.invoke()` normal).
    fake_result = ChatIntent(target="", needs_clarification=True)
    monkeypatch.setattr(chat_intent_module, "structured", lambda *a, **k: fake_result)
    fake_llm = _FakeLLM("¡Hola! Soy un asistente de informes OSINT — ¿sobre qué dominio, IP o "
                         "hash quieres que investigue?")

    intent = extract_intent(lambda: fake_llm, "hola")

    assert intent.reply.startswith("¡Hola!")
    assert intent.reply != _DEFAULT_CLARIFICATION_REPLY


def test_extract_intent_falls_back_to_default_reply_when_second_call_fails(monkeypatch):
    # Red de seguridad: si toca pedir aclaración pero la segunda llamada no da una respuesta
    # utilizable, ya sea porque vuelve vacía o porque falla del todo (red, API), el usuario
    # no debe quedarse sin respuesta. Dos disparadores distintos, misma protección; un solo
    # test basta.
    fake_result = ChatIntent(target="", instruction="", needs_clarification=False)
    monkeypatch.setattr(chat_intent_module, "structured", lambda *a, **k: fake_result)

    class _BoomLLM:
        def invoke(self, prompt: str):
            raise RuntimeError("el LLM no responde")

    for fake_llm in (_FakeLLM(""), _BoomLLM()):
        intent = extract_intent(lambda llm=fake_llm: llm, "hazme un informe de seguridad")
        assert intent.reply == _DEFAULT_CLARIFICATION_REPLY


def test_extract_intent_asks_for_clarification_when_llm_call_fails(monkeypatch):
    # Si el LLM de respaldo falla (red, API, modelo local caído), se debe pedir aclaración
    # en vez de romperse, antes sin ningún test pese a ser la rama de error.
    def _boom(*args, **kwargs):
        raise RuntimeError("el LLM no responde")

    monkeypatch.setattr(chat_intent_module, "structured", _boom)

    intent = extract_intent(lambda: object(), "un mensaje cualquiera sin objetivo claro")

    assert intent.needs_clarification is True
    assert intent.target == ""
    assert intent.instruction == "un mensaje cualquiera sin objetivo claro"
    assert intent.reply == _DEFAULT_CLARIFICATION_REPLY  # nunca se deja al usuario sin respuesta
