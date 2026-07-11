from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_AUTH = 4
EXIT_PERMISSION = 5
EXIT_NOT_FOUND = 6
EXIT_CONFLICT = 7
EXIT_VERSION = 8
EXIT_NETWORK = 70
EXIT_SERVER = 75


@dataclass
class CliError(Exception):
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    exit_code: int = EXIT_USAGE

    def __str__(self) -> str:
        return self.message
