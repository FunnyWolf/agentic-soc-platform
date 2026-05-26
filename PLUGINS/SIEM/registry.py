from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, List

import yaml

from Lib.configs import DATA_DIR
from Lib.log import logger
from PLUGINS.SIEM.models import SchemaFieldInfo, IndexInfo


@lru_cache(maxsize=1)
def _load_yaml_configs() -> Dict[str, IndexInfo]:
    registry: Dict[str, IndexInfo] = {}

    index_dir = Path(DATA_DIR) / "PLUGINS" / "SIEM"

    if not index_dir.exists():
        return registry

    for yaml_file in index_dir.glob("*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as file:
                data = yaml.safe_load(file) or {}

            fields = [SchemaFieldInfo(**field) for field in data.get("fields", [])]
            index_info = IndexInfo(
                name=data["name"],
                backend=data["backend"],
                description=data["description"],
                fields=fields,
            )
            registry[index_info.name] = index_info
        except Exception as exc:
            logger.exception(f"Error loading YAML file {yaml_file}: {exc}")

    return registry


def list_indices() -> List[IndexInfo]:
    return list(_load_yaml_configs().values())


def get_index_info(index_name: str) -> IndexInfo:
    registry = _load_yaml_configs()
    if index_name not in registry:
        raise ValueError(f"Index {index_name} not found.")
    return registry[index_name]


def get_default_agg_fields(index_name: str) -> List[str]:
    index_info = get_index_info(index_name)
    return [field.name for field in index_info.fields if field.is_key_field]


def get_backend_type(index_name: str) -> str:
    return get_index_info(index_name).backend
