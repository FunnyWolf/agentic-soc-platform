from __future__ import annotations

import time
from typing import Any

import httpx
from rich.console import Console

from . import __version__
from .config import redact_secret
from .errors import (
    CliError,
    EXIT_AUTH,
    EXIT_NETWORK,
    EXIT_NOT_FOUND,
    EXIT_PERMISSION,
    EXIT_SERVER,
    EXIT_USAGE,
)


class AspClient:
    def __init__(
        self,
        *,
        api_url: str,
        api_key: str | None = None,
        verbose: bool = False,
        console: Console | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = _normalize_base_url(api_url)
        self.api_key = api_key
        self.verbose = verbose
        self.console = console or Console(stderr=True)
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/api/health/", authenticated=False)

    def version(self) -> dict[str, Any]:
        return self.request("GET", "/api/agent/v1/version/")

    def request(self, method: str, path: str, *, authenticated: bool = True, json: Any = None, files: Any = None) -> dict[str, Any]:
        if authenticated and not self.api_key:
            raise CliError("missing_api_key", "API key is required", {}, EXIT_AUTH)

        headers = {
            "Accept": "application/json",
            "User-Agent": f"asp-cli/{__version__}",
        }
        if authenticated and self.api_key:
            headers["Authorization"] = f"Api-Key {self.api_key}"

        url = f"{self.base_url}{path}"
        started = time.perf_counter()
        try:
            response = httpx.request(method, url, headers=headers, json=json, files=files, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise CliError("network_error", f"Unable to reach ASP server: {exc}", {"url": _redact_url(url)}, EXIT_NETWORK) from exc

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        if self.verbose:
            self.console.print(f"{method} {path} -> {response.status_code} ({elapsed_ms}ms)", style="dim")

        if response.status_code >= 400:
            self._raise_http_error(response, path)

        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise CliError("invalid_response", "Server returned non-JSON response", {"status_code": response.status_code}, EXIT_SERVER) from exc
        if not isinstance(payload, dict):
            raise CliError("invalid_response", "Server response must be a JSON object", {"status_code": response.status_code}, EXIT_SERVER)
        return payload

    def _raise_http_error(self, response: httpx.Response, path: str) -> None:
        message = _response_message(response)
        details = {"status_code": response.status_code, "path": path}
        if response.status_code == 400:
            raise CliError("bad_request", message, details, EXIT_USAGE)
        if response.status_code == 401:
            raise CliError("authentication_failed", message, details, EXIT_AUTH)
        if response.status_code == 403:
            raise CliError("permission_denied", message, details, EXIT_PERMISSION)
        if response.status_code == 404:
            raise CliError("not_found", message, details, EXIT_NOT_FOUND)
        raise CliError("server_error", message, details, EXIT_SERVER)


def _normalize_base_url(api_url: str) -> str:
    base = api_url.strip().rstrip("/")
    if base.endswith("/api"):
        base = base[:-4]
    if not base:
        raise CliError("missing_api_url", "ASP API URL is required", {}, EXIT_USAGE)
    return base


def _response_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
        error = payload.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return error["message"]
    return f"HTTP {response.status_code}"


def _redact_url(url: str) -> str:
    return url.replace(redact_secret(url), "****") if "asp_" in url else url
