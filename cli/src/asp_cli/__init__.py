from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _source_version() -> str | None:
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject_path.exists():
        return None

    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project_version = pyproject.get("project", {}).get("version")
    if not isinstance(project_version, str):
        raise RuntimeError("Missing project.version in cli pyproject.toml")
    return project_version


try:
    __version__ = _source_version() or version("asp-cli")
except PackageNotFoundError as exc:
    raise RuntimeError("Cannot resolve asp-cli package version") from exc
