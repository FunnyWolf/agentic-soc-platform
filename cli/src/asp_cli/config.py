from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import CliError, EXIT_CONFIG

GLOBAL_SETTINGS_PATH = Path.home() / ".asp" / "settings.json"
LOCAL_SETTINGS_DIR = ".asp"
SETTINGS_FILENAME = "settings.json"
SUPPORTED_KEYS = {"api_url", "api_key"}


@dataclass(frozen=True)
class ResolvedConfig:
    api_url: str | None
    api_key: str | None
    sources: dict[str, str]
    global_path: Path
    local_path: Path | None

    @property
    def has_auth(self) -> bool:
        return bool(self.api_url and self.api_key)


def resolve_config(*, cwd: Path | None = None, api_url: str | None = None, api_key: str | None = None) -> ResolvedConfig:
    cwd = (cwd or Path.cwd()).resolve()
    global_settings = read_settings(GLOBAL_SETTINGS_PATH)
    local_path = find_local_settings(cwd)
    local_settings = read_settings(local_path) if local_path else {}
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}

    _merge(values, sources, global_settings, "global")
    if local_path:
        _merge(values, sources, local_settings, "local")
    _merge(
        values,
        sources,
        {
            "api_url": os.environ.get("ASP_API_URL"),
            "api_key": os.environ.get("ASP_API_KEY"),
        },
        "env",
    )
    _merge(values, sources, {"api_url": api_url, "api_key": api_key}, "flags")

    return ResolvedConfig(
        api_url=_clean(values.get("api_url")),
        api_key=_clean(values.get("api_key")),
        sources=sources,
        global_path=GLOBAL_SETTINGS_PATH,
        local_path=local_path,
    )


def auth_settings_path(*, local: bool, cwd: Path | None = None) -> Path:
    if local:
        return (cwd or Path.cwd()).resolve() / LOCAL_SETTINGS_DIR / SETTINGS_FILENAME
    return GLOBAL_SETTINGS_PATH


def save_auth(*, api_url: str, api_key: str, local: bool = False, cwd: Path | None = None) -> Path:
    path = auth_settings_path(local=local, cwd=cwd)
    settings = read_settings(path)
    settings["api_url"] = api_url.rstrip("/")
    settings["api_key"] = api_key
    write_settings(path, settings)
    return path


def clear_auth(*, local: bool = False, cwd: Path | None = None) -> Path:
    path = auth_settings_path(local=local, cwd=cwd)
    settings = read_settings(path)
    settings.pop("api_url", None)
    settings.pop("api_key", None)
    write_settings(path, settings)
    return path


def set_config_value(key: str, value: str, *, local: bool = False, cwd: Path | None = None) -> Path:
    if key not in SUPPORTED_KEYS:
        raise CliError("invalid_config_key", f"Unsupported config key: {key}", {"supported": sorted(SUPPORTED_KEYS)}, EXIT_CONFIG)
    path = auth_settings_path(local=local, cwd=cwd)
    settings = read_settings(path)
    settings[key] = value.rstrip("/") if key == "api_url" else value
    write_settings(path, settings)
    return path


def get_config_value(key: str, *, cwd: Path | None = None, api_url: str | None = None, api_key: str | None = None) -> tuple[str | None, str | None]:
    if key not in SUPPORTED_KEYS:
        raise CliError("invalid_config_key", f"Unsupported config key: {key}", {"supported": sorted(SUPPORTED_KEYS)}, EXIT_CONFIG)
    config = resolve_config(cwd=cwd, api_url=api_url, api_key=api_key)
    return getattr(config, key), config.sources.get(key)


def read_settings(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise CliError("invalid_config", f"Invalid JSON in settings file: {path}", {"path": str(path)}, EXIT_CONFIG) from exc
    if not isinstance(payload, dict):
        raise CliError("invalid_config", f"Settings file must contain a JSON object: {path}", {"path": str(path)}, EXIT_CONFIG)
    return payload


def write_settings(path: Path, settings: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(settings, handle, indent=2, sort_keys=True)
        handle.write("\n")
    _restrict_permissions(path)


def find_local_settings(cwd: Path) -> Path | None:
    git_root = find_git_root(cwd)
    if git_root is None:
        candidate = cwd / LOCAL_SETTINGS_DIR / SETTINGS_FILENAME
        return candidate if candidate.exists() else None

    current = cwd
    while True:
        candidate = current / LOCAL_SETTINGS_DIR / SETTINGS_FILENAME
        if candidate.exists():
            return candidate
        if current == git_root:
            return None
        current = current.parent


def find_git_root(cwd: Path) -> Path | None:
    current = cwd
    while True:
        if (current / ".git").exists():
            return current
        if current == current.parent:
            return None
        current = current.parent


def redact_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def _merge(values: dict[str, Any], sources: dict[str, str], incoming: dict[str, Any], source: str) -> None:
    for key in SUPPORTED_KEYS:
        value = _clean(incoming.get(key))
        if value:
            values[key] = value
            sources[key] = source


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        return
