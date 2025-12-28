# Webhook Forwarder Service

This is a standalone FastAPI service that listens for webhooks from various sources (like Splunk, Kibana) and forwards them to a Redis stream.

## Installation

This service has its own dependencies, listed in `requirements.txt`. It is recommended to use a dedicated virtual environment.

1.  Navigate to the project root directory.
2.  Install the dependencies:
    ```bash
    pip install -r PLUGINS/Forwarder/requirements.txt
    ```

## Running the Service

You can run the service using `uvicorn`. From the project root directory, execute the following command:

```bash
uvicorn PLUGINS.Forwarder.main:app --host 0.0.0.0 --port 8001 --reload
```

-   `--host 0.0.0.0`: Makes the service accessible from outside its container/machine.
-   `--port 8001`: Runs on port 8001 (configurable in `PLUGINS/Forwarder/CONFIG.py`).
-   `--reload`: Automatically restarts the server when code changes are detected. Ideal for development.

## API Endpoints

-   `GET /`: A simple health check endpoint.
-   `POST /api/v1/webhook/splunk`: Accepts Splunk alert webhooks.
-   `POST /api/v1/webhook/kibana`: Accepts Kibana (Elasticsearch) alert webhooks.
-   `POST /api/v1/webhook/nocolymail`: Accepts NocolyMail webhooks.
