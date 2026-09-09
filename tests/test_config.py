"""Pruebas de la carga de configuración de servidores MCP."""

import json

from tfm_osint.config import load_server_config


def test_load_server_config_filters_disabled(tmp_path):
    # mcp_client.py asume que load_server_config() ya excluye los servidores marcados
    # enabled=False, si esto se rompe, un servidor deshabilitado en servers.json se
    # intentaría lanzar igualmente.
    path = tmp_path / "servers.json"
    path.write_text(
        json.dumps(
            {
                "servers": {
                    "a": {"enabled": True, "command": "npx"},
                    "b": {"enabled": False, "command": "npx"},
                }
            }
        ),
        encoding="utf-8",
    )
    servers = load_server_config(path)
    assert "a" in servers
    assert "b" not in servers
