# AGENTS.md

## Project shape
- This is a Django/DRF + Channels SOC automation platform; `ASP/settings.py` uses SQLite at `Docker/DB/db.sqlite3`, Redis cache, and imports plugin config modules directly.
- Runtime work is mostly outside HTTP views: `Core.apps.CoreConfig.ready()` calls `Core.bootstrap.get_or_start_background_services()`, but only when `ASP_START_BACKGROUND_SERVICES=1` is set.
- Main data flow: SIEM/webhook alert -> Redis Stream named after a module -> `Lib.moduleengine.ModuleEngine` loads `MODULES/*.py` -> module creates `Alert`/`Artifact` and correlates into `Case` in SIRP -> queued analysis/playbooks enrich/update SIRP records.
- Domain model hierarchy is central: `Case` is the investigation view, `Alert` is detection fact, `Artifact` is the pivot atom, `Enrichment` is appendable structured context; see `ARCHITECTURE.md` and `PLUGINS/SIRP/sirpcoremodel.py`.

## Local workflows
- Install/sync dependencies with uv: `uv sync` (Python `>=3.12,<3.14` from `pyproject.toml`).
- Start Redis Stack for streams/cache: `Push-Location Docker/RedisStack; docker compose up -d; Pop-Location`.
- Start Django with background services: `uv run python manage.py runserver 127.0.0.1:7000 --noreload`; `manage.py` sets the background env flag for runserver workers.
- If running ASGI/uvicorn directly, set `ASP_START_BACKGROUND_SERVICES=1` yourself if modules/playbook polling must run; `Docker/Uvicorn/uvicorn.toml` points at `ASP.asgi:application` on port 7000.
- Start MCP tools server separately: `uv run python PLUGINS/MCP/mcpserver.py --host 127.0.0.1 --port 7001`; it persists the SSE UUID in `Docker/mcp_uuid`.
- Manual/integration tests live in `TEST/`; `TEST/test_knowledge_keyword_search.py` uses real SIRP data and can mutate a knowledge record depending on CONFIG constants.

## Extension patterns
- New streaming modules go in `MODULES/<Rule-Name>.py` and must expose `class Module(BaseModule)`. `ModuleEngine` imports by file path, so hyphenated filenames are allowed.
- A module’s filename becomes `self.module_name`; this is also the Redis stream name and prompt/resource lookup key used by `BaseAPI` under `DATA/MODULES/<module_name>/`.
- Module `run()` should read exactly one stream message via `self.read_stream_message()` unless in debug mode (`debug_message_id`); see `MODULES/Mail-01-User-Report-Phishing-Mail.py`.
- Build SIRP records with Pydantic models/enums (`AlertModel`, `ArtifactModel`, `CaseModel`, `Severity`, etc.) and persist via `PLUGINS.SIRP.sirpapi` entity classes (`Alert.create`, `Case.update`).
- Use `Correlation.generate_correlation_uid(...)` for alert grouping, then `Case.get_by_correlation_uid(...)` to append alerts or create a new case.
- New playbooks go in `PLAYBOOKS/*.py` and must expose `class Playbook(BasePlaybook)` with `NAME` and optional `DESC`; `PlaybookLoader` imports them as Python modules, so use import-safe filenames.
- Playbooks receive SIRP context through `self._playbook_model`; use `self.param_source_row_id`, `self.param_user_input`, `update_playbook_status(...)`, and `send_notice(...)` rather than reading pending jobs directly.
- For LangGraph implementations, inherit `LanggraphModule` or `LanggraphPlaybook`; both use `BaseAgentState` and a `MemorySaver` checkpointer keyed by `self.module_name`.

## SIRP/MCP/plugin conventions
- `PLUGINS/SIRP/sirpapi.py` is the domain boundary over Nocoly worksheet rows. Prefer adding business logic there instead of in MCP wrappers, matching `ARCHITECTURE.md` MCP principles.
- `BaseWorksheetEntity.get/list(..., lazy_load=False)` loads relations; use `lazy_load=True` when only IDs/basic fields are needed to avoid expensive related fetches.
- Partial updates are model-based: instantiate a model with `row_id` plus fields to change, then call `Entity.update(model)`; avoid raw worksheet field lists unless working in low-level Nocoly code.
- MCP tools are plain annotated functions in `PLUGINS/MCP/llmfunc.py`; add them to `REGISTERED_MCP_TOOLS` so `mcpserver.py` registers them.
- External settings are Python modules such as `PLUGINS/Redis/CONFIG.py`, `PLUGINS/SIRP/CONFIG.py`, and `PLUGINS/LLM/CONFIG.py`; examples exist beside them and may contain environment-specific hosts.
- Logs use `Lib.log.logger` and write through Django logging to `Docker/Log/django.log`; preserve the existing bilingual English/Chinese style when touching user-facing descriptions.

