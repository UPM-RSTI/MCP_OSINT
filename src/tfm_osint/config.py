"""Carga de configuración del sistema (entorno + servers.json)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVERS_FILE = PROJECT_ROOT / "mcp_servers" / "servers.json"


class Settings(BaseSettings):
    """Configuración leída de variables de entorno / .env."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM
    llm_provider: str = Field(default="claude", alias="TFM_LLM_PROVIDER")
    claude_model: str = Field(default="claude-opus-4-8", alias="TFM_CLAUDE_MODEL")
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen2.5:7b", alias="OLLAMA_MODEL")

    bedrock_api_key: str | None = Field(default=None, alias="AWS_BEARER_TOKEN_BEDROCK")
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")

    bedrock_claude_model: str = Field(default="", alias="TFM_BEDROCK_CLAUDE_MODEL")
    bedrock_nova_model: str = Field(default="", alias="TFM_BEDROCK_NOVA_MODEL")

    # 4º motor del pipeline principal: mismo linaje que Ollama (Qwen), pero grande y en la
    # nube. Necesita us-east-1 (ver `llm.py::_bedrock_region_for()`), no eu-north-1.
    bedrock_qwen_model: str = Field(default="qwen.qwen3-next-80b-a3b", alias="TFM_BEDROCK_QWEN_MODEL")

    # Motor evaluador (LLM-as-judge): de un proveedor distinto a los motores comparados
    # para no favorecer a ninguno por compartir familia/entrenamiento.
    bedrock_judge_model: str = Field(default="deepseek.v3.2", alias="TFM_BEDROCK_JUDGE_MODEL")

    # Corta el bucle ReAct del collector si no termina en este tiempo.
    collector_timeout_s: int = Field(default=180, alias="TFM_COLLECTOR_TIMEOUT_S")

    # Timeout HTTP de cada petición individual a Ollama (sin esto, el valor por defecto de
    # la librería es None/sin límite, y una petición colgada bloquea el hilo indefinidamente).
    ollama_http_timeout_s: int = Field(default=90, alias="TFM_OLLAMA_HTTP_TIMEOUT_S")

    # Claves OSINT (todas opcionales). Los alias son los nombres exactos que lee
    # badchars/osint-mcp-server; sin ellas ya funcionan 21 herramientas públicas.
    shodan_api_key: str | None = Field(default=None, alias="SHODAN_API_KEY")
    vt_api_key: str | None = Field(default=None, alias="VT_API_KEY")
    st_api_key: str | None = Field(default=None, alias="ST_API_KEY")
    censys_api_id: str | None = Field(default=None, alias="CENSYS_API_ID")
    censys_api_secret: str | None = Field(default=None, alias="CENSYS_API_SECRET")

    def osint_env(self) -> dict[str, str]:
        """Variables OSINT presentes, para inyectar en el entorno del servidor MCP."""
        mapping = {
            "SHODAN_API_KEY": self.shodan_api_key,
            "VT_API_KEY": self.vt_api_key,
            "ST_API_KEY": self.st_api_key,
            "CENSYS_API_ID": self.censys_api_id,
            "CENSYS_API_SECRET": self.censys_api_secret,
        }
        return {k: v for k, v in mapping.items() if v}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def load_server_config(path: Path = SERVERS_FILE) -> dict[str, dict]:
    """Devuelve los servidores MCP habilitados desde servers.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("servers", {})
    return {name: cfg for name, cfg in servers.items() if cfg.get("enabled", False)}
