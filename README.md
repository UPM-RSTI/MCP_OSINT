# TFM: Aplicación de LLMs para el Reporte Automatizado de Eventos OSINT (Ciberseguridad)

Sistema **multiagente** basado en modelos de lenguaje que recolecta **eventos OSINT de
ciberseguridad** (indicadores de compromiso, infraestructura maliciosa, filtraciones,
certificados, DNS, exposición en Shodan…) a través de servidores **MCP (Model Context
Protocol)**, los correla y genera **informes de inteligencia automatizados**.

La orquestación de agentes usa **LangGraph**; el LLM es **intercambiable** entre varios
motores: un modelo local (Ollama) y tres motores vía Amazon Bedrock (Claude Haiku 4.5, Amazon
Nova Pro, Qwen3 Next 80B), lo que permite comparar coste, calidad y privacidad.

## Arquitectura

```
Consulta ─▶ [Planner] ─▶ [Recolector OSINT] ⇄ MCP ─▶ [Analista] ─▶ [Redactor] ─▶ [Verificador] ─▶ Informe (.md/.pdf)
                                   │
                    Ollama local  ó  Claude / Nova / Qwen3 vía Bedrock  (LLM intercambiable)
```

`run_pipeline()` (`src/tfm_osint/graph.py`) es el único punto de entrada, usado por igual desde
la CLI, el frontend de Streamlit, la evaluación formal y la prueba de concepto de disparo por
evento (Kafka).

## Instalación

```bash
uv sync --extra dev --extra pdf --extra frontend --extra notebook --extra kafka
cp .env.example .env          # rellena las claves que vayas a usar (todas opcionales salvo un motor)
# Modelo local (opcional, para el experimento comparativo):
#   ollama serve  &&  ollama pull qwen2.5:7b
```

> `uv sync --extra X` a solas reconcilia el entorno solo con los extras de esa llamada: pasa
> siempre todos los que quieras conservar juntos, como arriba.
> Alternativa sin `uv`: `pip install -e ".[dev,pdf,frontend,notebook,kafka]"`.

Los servidores MCP se lanzan vía `npx` (requiere **Node.js** instalado).

### Fuentes OSINT (servidor MCP)

El servidor MCP confirmado es **[`badchars/osint-mcp-server`](https://github.com/badchars/osint-mcp-server)**
(MIT, TypeScript, transporte stdio), lanzado con `npx -y osint-mcp-server`. De sus 37
herramientas, **21 funcionan sin ninguna clave de API**:

> DNS · WHOIS/RDAP · crt.sh (certificate transparency) · GeoIP · BGP/ASN · Wayback Machine ·
> HackerTarget · descubrimiento de tenant Microsoft 365.

Las 16 restantes son **opcionales** y se activan con claves en `.env` (`SHODAN_API_KEY`,
`VT_API_KEY`, `ST_API_KEY`, `CENSYS_API_ID` + `CENSYS_API_SECRET`) para Shodan, VirusTotal,
SecurityTrails y Censys.

La configuración vive en `mcp_servers/servers.json`; `openosint` (Python) queda como segundo
servidor opcional deshabilitado. Confirma las herramientas descubiertas con
`python -m tfm_osint.mcp_client --list`.

## Uso

### CLI

```bash
# Listar las herramientas OSINT descubiertas por MCP
python -m tfm_osint.mcp_client --list

# Generar un informe sobre un objetivo (motor por defecto: TFM_LLM_PROVIDER en .env)
tfm-osint report --target ejemplo.com --provider bedrock --out informe.pdf

# Mismo objetivo con el modelo local
tfm-osint report --target ejemplo.com --provider ollama
```

### Frontend de demostración (Streamlit)

```bash
uv run streamlit run app.py
```

Cinco secciones: **⛑️ Nuevo diagnóstico** (formulario clásico), **🛡️ Simulador SIEM** (pega una
alerta de seguridad en texto libre; el sistema identifica el objetivo y dispara el diagnóstico
vía Kafka, ver más abajo), **🛠️ Herramientas MCP** (catálogo en vivo), **🗂️ Historial**
(diagnósticos pasados, exportables a PDF) y **📊 Comparativa** (resultados de la evaluación
formal).

### Evaluación formal (métricas + LLM-as-judge)

```bash
# Comparativa completa a 4 motores + juez (requiere credenciales de Bedrock)
uv run python evaluation/run_eval.py --engines ollama haiku nova qwen --judge

# Análisis y gráficas de resultados
jupyter notebook notebooks/analisis_resultados.ipynb
```

### Prueba de concepto: disparo automático por evento (Kafka)

Demuestra que el sistema puede reaccionar solo a un evento externo ya identificado (o a una
alerta de SIEM en texto libre), sin intervención del usuario.

```bash
# 1. Arrancar Kafka (Homebrew, KRaft nativo) y el consumidor, cada uno en su terminal
/opt/homebrew/opt/kafka/bin/kafka-server-start /opt/homebrew/etc/kafka/server.properties
uv run python scripts/kafka_consumer.py

# 2. Publicar un evento, tres formas:
uv run python scripts/kafka_produce_test_event.py --target ejemplo.com   # evento ya identificado
uv run python scripts/siem_simulador.py --alert "..."                    # alerta en texto libre
#   ...o desde el propio frontend, sección "🛡️ Simulador SIEM"
```

El diagnóstico aparece en el historial igual que si se hubiera lanzado desde la CLI o Streamlit,
sin cola de producción real, límite de tasa ni deduplicación (alcance deliberadamente
acotado a una prueba de concepto).

## Ética y legalidad (OSINT)

Este proyecto es una herramienta de **investigación de seguridad defensiva** con fines
académicos. Cumple los siguientes principios:

- **Solo fuentes públicas.** No se realiza intrusión, escaneo activo agresivo ni acceso a
  datos no públicos. Las consultas se limitan a APIs y bases de datos abiertas
  (certificate transparency, DNS, WHOIS/RDAP, Wayback, GeoIP, BGP…).
- **Uso autorizado.** Empléese únicamente sobre objetivos propios o para los que se cuente
  con autorización explícita.
- **Respeto de los Términos de Servicio** y de los límites de tasa de cada fuente
  (rate-limiting incorporado).
- **Sin persistencia de datos personales** más allá de lo necesario para el informe.

### Protección de datos (RGPD)

Aunque el sistema solo consulta fuentes ya públicas, algunas de ellas (en particular WHOIS/RDAP)
pueden exponer incidentalmente datos personales de un registrante (nombre, email, teléfono) en
registradores o regiones que no aplican redacción por defecto; el *pipeline* no filtra ni redacta
este dato si la fuente lo devuelve, lo reproduce en el informe y lo persiste en el historial local
igual que cualquier otro campo de evidencia. La base jurídica habitual para este tipo de
investigación (fuentes ya públicas, sin intrusión, sobre objetivos propios o autorizados) es el
**interés legítimo** (art. 6.1.f RGPD), el mismo que aplican en la práctica los equipos de
seguridad y CERTs.

Dos puntos concretos a tener en cuenta:

- **Transferencias internacionales.** Los motores Claude Haiku 4.5 y Amazon Nova Pro corren en
  `eu-north-1` (Estocolmo) vía Amazon Bedrock, dentro de la UE. **Qwen3 Next 80B corre
  obligatoriamente en `us-east-1`**: cualquier dato personal que acabe en el *prompt* viaja a
  EE. UU. si se usa ese motor en concreto. Ollama (modelo local) no transfiere nada fuera de
  la máquina.
- **Retención.** El historial local (`history.db`) no expira automáticamente; el borrado es
  manual desde la sección Historial de la interfaz.

## Estructura

- `src/tfm_osint/`: núcleo (config, LLM, cliente MCP, estado, grafo, nodos, informe, CLI,
  extracción de intención del chat/SIEM, historial).
- `app.py`: frontend de demostración (Streamlit), ver "Uso" arriba.
- `scripts/`: prueba de concepto de disparo por evento (Kafka): `kafka_consumer.py`,
  `kafka_produce_test_event.py`, `siem_simulador.py`.
- `mcp_servers/servers.json`: configuración de servidores MCP.
- `evaluation/`: dataset con ground-truth, métricas y LLM-as-judge.
- `notebooks/analisis_resultados.ipynb`: tablas y gráficas comparativas de la evaluación.
- `tests/`: pruebas (116, `pytest`).
