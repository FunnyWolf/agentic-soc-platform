# ASP Backend

Django backend for Agentic SOC Platform.

## Development

Run commands from the `backend` directory:

```powershell
uv sync
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
```

For websocket development, also run the ASGI server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn asp.asgi:application --host 127.0.0.1 --port 8001
```

## Admin user

ASP admin users are Django superusers and are maintained from the backend command line:

```powershell
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py changepassword <admin-username>
```

## Documentation

Product, deployment, and operations documentation lives in the docs site:

- https://asp.viperrtp.com/asp/quick-start/deployment/
- https://asp.viperrtp.com/asp/quick-start/first-login/
- https://asp.viperrtp.com/asp/settings/users/

Runtime API documentation is served by the backend:

- Swagger UI: `/api/docs/`
- Redoc: `/api/redoc/`
- OpenAPI schema: `/api/schema/`
