# API Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add maintainable Swagger/OpenAPI documentation for the full backend HTTP API and add lightweight documentation-site guidance for HTTP and realtime integration.

**Architecture:** Use `drf-spectacular` to generate OpenAPI 3 schema from Django REST Framework views and serializers, served by the backend at `/api/schema/`, `/api/docs/`, and `/api/redoc/`. Use sidecar-packaged Swagger UI/Redoc assets for self-hosted deployments. Keep WebSocket protocol documentation in VitePress because OpenAPI does not describe websocket message flows.

**Tech Stack:** Django, Django REST Framework, SimpleJWT, custom API key auth, drf-spectacular, drf-spectacular-sidecar, VitePress.

---

### Task 1: Add OpenAPI dependencies and backend settings

**Files:**
- Modify: `backend/pyproject.toml`
- Modify: `backend/asp/settings.py`

- [ ] **Step 1: Add dependencies**

Add these dependencies to `backend/pyproject.toml`:

```toml
"drf-spectacular>=0.29.0",
"drf-spectacular-sidecar>=2026.1.1",
```

- [ ] **Step 2: Configure installed apps and DRF schema class**

Update `backend/asp/settings.py`:

```python
INSTALLED_APPS = [
    # Third party
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "corsheaders",
]

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}
```

- [ ] **Step 3: Add OpenAPI settings**

Add `SPECTACULAR_SETTINGS` in `backend/asp/settings.py`:

```python
SPECTACULAR_SETTINGS = {
    "TITLE": "Agentic SOC Platform API",
    "DESCRIPTION": "HTTP API for Agentic SOC Platform. External integrations should prefer API keys for automation.",
    "VERSION": "0.5.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
    "COMPONENT_SPLIT_REQUEST": True,
    "SECURITY": [
        {"bearerAuth": []},
        {"apiKeyAuth": []},
    ],
}
```

- [ ] **Step 4: Sync dependencies**

Run:

```powershell
Set-Location -Path 'C:\Code\agentic-soc-platform\backend'
uv sync
```

Expected: dependencies resolve and install without errors.

---

### Task 2: Add schema views and authentication extensions

**Files:**
- Create: `backend/apps/common/openapi.py`
- Modify: `backend/asp/urls.py`

- [ ] **Step 1: Define authentication extensions**

Create `backend/apps/common/openapi.py`:

```python
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ApiKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "apps.accounts.authentication.ApiKeyAuthentication"
    name = "apiKeyAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Use the format: Api-Key <key>",
        }
```

- [ ] **Step 2: Ensure extensions load**

Import the module from `backend/apps/common/apps.py` inside `ready()`:

```python
class CommonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.common"

    def ready(self):
        from . import openapi  # noqa: F401
```

- [ ] **Step 3: Register schema routes**

Update `backend/asp/urls.py`:

```python
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

urlpatterns = [
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]
```

- [ ] **Step 4: Validate schema route import**

Run:

```powershell
Set-Location -Path 'C:\Code\agentic-soc-platform\backend'
.\.venv\Scripts\python.exe manage.py check
```

Expected: `System check identified no issues`.

---

### Task 3: Add schema tags and minimal APIView annotations

**Files:**
- Modify: `backend/apps/common/openapi.py`
- Modify: `backend/apps/common/views.py`
- Modify: APIView-heavy modules as needed: `backend/apps/agent_api/views.py`, `backend/apps/settings/views.py`, `backend/apps/settings/custom_views.py`, `backend/apps/dashboard/views.py`, `backend/apps/webhook/views.py`, `backend/apps/attachments/views.py`, `backend/apps/preferences/views.py`

- [ ] **Step 1: Add preprocessing hook for business tags**

Add a hook in `backend/apps/common/openapi.py`:

```python
def assign_business_tags(endpoints):
    tag_map = (
        ("/api/auth/", "Auth"),
        ("/api/auth/users", "Users"),
        ("/api/auth/api-keys", "API Keys"),
        ("/api/cases", "Cases"),
        ("/api/alerts", "Alerts"),
        ("/api/artifacts", "Artifacts"),
        ("/api/comments", "Comments"),
        ("/api/attachments", "Attachments"),
        ("/api/settings", "Settings"),
        ("/api/dashboard", "Dashboard"),
        ("/api/agent/v1", "Agent API"),
        ("/api/webhook", "Webhooks"),
        ("/api/user-table-preferences", "Preferences"),
        ("/api/saved-table-filters", "Preferences"),
        ("/api/health", "System"),
        ("/api/metadata", "Metadata"),
    )
    for path, path_regex, method, callback in endpoints:
        for prefix, tag in tag_map:
            if path.startswith(prefix):
                callback.cls._spectacular_annotation = getattr(callback.cls, "_spectacular_annotation", {})
                callback.cls._spectacular_annotation["tags"] = [tag]
                break
    return endpoints
```

- [ ] **Step 2: Wire preprocessing hook**

Add to `SPECTACULAR_SETTINGS`:

```python
"PREPROCESSING_HOOKS": [
    "apps.common.openapi.assign_business_tags",
],
```

- [ ] **Step 3: Annotate APIViews that lack serializers**

For high-warning APIViews, use `extend_schema` with `OpenApiTypes.OBJECT` where exact schemas are not yet serializer-backed:

```python
from drf_spectacular.utils import OpenApiResponse, extend_schema
from drf_spectacular.types import OpenApiTypes


@extend_schema(
    responses={200: OpenApiResponse(response=OpenApiTypes.OBJECT)},
)
def get(self, request):
    ...
```

- [ ] **Step 4: Generate schema**

Run:

```powershell
Set-Location -Path 'C:\Code\agentic-soc-platform\backend'
.\.venv\Scripts\python.exe manage.py spectacular --file $env:TEMP\asp-openapi.yaml
```

Expected: command exits successfully. Warnings are acceptable in the first implementation phase.

---

### Task 4: Add docs-site HTTP API and realtime guide

**Files:**
- Create: `asp-doc/docs/zh/asp/integrations/api/index.md`
- Create: `asp-doc/docs/en/asp/integrations/api/index.md`
- Modify: `asp-doc/docs/.vitepress/config/zh.ts`
- Modify: `asp-doc/docs/.vitepress/config/en.ts`

- [ ] **Step 1: Add Chinese guide**

Create `asp-doc/docs/zh/asp/integrations/api/index.md`:

```markdown
# API 集成

ASP 后端提供实时生成的 OpenAPI 文档，用于外部系统集成和调试。

## 文档入口

- Swagger UI: `/api/docs/`
- Redoc: `/api/redoc/`
- OpenAPI Schema: `/api/schema/`

## 认证

自动化集成推荐使用 API Key：

```http
Authorization: Api-Key <key>
```

交互式用户也可以使用 JWT：

```http
Authorization: Bearer <access_token>
```

## Realtime API

WebSocket 地址为 `/ws/events/`。连接时携带访问令牌，连接成功后服务端发送 `realtime.connected`。

客户端可以发送：

- `comments.subscribe`
- `comments.unsubscribe`

服务端可能返回：

- `comments.subscribed`
- `comments.unsubscribed`
- `realtime.error`
```

- [ ] **Step 2: Add English guide**

Create `asp-doc/docs/en/asp/integrations/api/index.md` with equivalent English content.

- [ ] **Step 3: Link guide in sidebars**

Add API page under Integrations in both VitePress configs:

```ts
{text: 'API', link: 'api/'},
```

---

### Task 5: Validate and commit

**Files:**
- All files above

- [ ] **Step 1: Backend checks**

Run:

```powershell
Set-Location -Path 'C:\Code\agentic-soc-platform\backend'
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py spectacular --file $env:TEMP\asp-openapi.yaml
```

Expected: `check` passes and schema generation exits successfully.

- [ ] **Step 2: Documentation check**

Do not run VitePress build unless explicitly requested. Inspect the sidebar and guide files for valid links and consistent zh/en content.

- [ ] **Step 3: Commit**

Commit backend and docs changes:

```powershell
Set-Location -Path 'C:\Code\agentic-soc-platform'
git add backend asp-doc docs/superpowers/plans/2026-07-22-api-documentation.md
git commit -m "feat: add API documentation endpoints" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Self-review

- Spec coverage: backend Swagger/OpenAPI endpoints, local UI assets, JWT/API key auth docs, websocket docs-site guidance, no generated schema artifact, and non-breaking response behavior are covered.
- Placeholder scan: no TODO/TBD placeholders remain.
- Type consistency: route names, dependency names, and settings keys match drf-spectacular conventions.
