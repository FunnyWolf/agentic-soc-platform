from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Literal

import yaml
from pydantic import BaseModel


class FieldInfo(BaseModel):
    name: str
    type: str
    description: str
    is_key_field: bool = False


class IndexInfo(BaseModel):
    name: str
    backend: Literal["ELK", "Splunk"]
    description: str
    fields: List[FieldInfo]


def _load_yaml_configs() -> Dict[str, IndexInfo]:
    registry = {}
    indexs_dir = Path(__file__).parent / "Indexs"

    if not indexs_dir.exists():
        return registry

    for yaml_file in indexs_dir.glob("*.yaml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            fields = [FieldInfo(**field) for field in data.get('fields', [])]
            index_info = IndexInfo(
                name=data['name'],
                backend=data['backend'],
                description=data['description'],
                fields=fields
            )
            registry[index_info.name] = index_info
        except Exception as e:
            print(f"Failed to load {yaml_file}: {e}")

    return registry


def get_default_agg_fields(index_name: str) -> List[str]:
    registry = _load_yaml_configs()
    if index_name not in registry:
        return []
    result = [f.name for f in registry[index_name].fields if f.is_key_field]
    return result


def get_backend_type(index_name: str) -> str:
    registry = _load_yaml_configs()
    if index_name in registry:
        return registry[index_name].backend
    return "ELK"
