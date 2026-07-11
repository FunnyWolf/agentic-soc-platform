from __future__ import annotations

import json
from enum import Enum
from typing import Any

from rich.console import Console
from rich.table import Table

from .errors import CliError


class OutputFormat(str, Enum):
    human = "human"
    json = "json"


def emit_success(
    console: Console,
    *,
    output: OutputFormat,
    operation: str,
    data: Any,
    meta: dict[str, Any] | None = None,
    human: str | None = None,
) -> None:
    if output == OutputFormat.json:
        payload = {
            "data": data,
            "meta": {
                "operation": operation,
                **(meta or {}),
            },
        }
        console.print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if human is not None:
        console.print(human)
        return
    console.print(data)


def emit_error(console: Console, *, output: OutputFormat, error: CliError, operation: str | None = None) -> None:
    if output == OutputFormat.json:
        payload = {
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
            },
            "meta": {
                "operation": operation,
            },
        }
        console.print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    console.print(f"Error: {error.message}", style="bold red")


def key_value_table(title: str, rows: list[tuple[str, Any]]) -> Table:
    table = Table(title=title, show_header=False)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value")
    for key, value in rows:
        table.add_row(key, "" if value is None else str(value))
    return table
