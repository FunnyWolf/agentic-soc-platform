from functools import lru_cache
from pathlib import Path

import yaml

from integrations.siem.models import IndexInfo, SchemaFieldInfo
from asp import settings

CUSTOM_REGISTRY_DIR = Path(settings.CUSTOM_DIR) / "data" / "siem"


def default_registry_dirs():
    return [CUSTOM_REGISTRY_DIR]


def _iter_overlaid_yaml_files(*directories):
    paths_by_name = {}
    for directory in directories:
        directory = Path(directory)
        if not directory.exists():
            continue
        for yaml_file in sorted(directory.glob("*.yaml")):
            paths_by_name[yaml_file.name] = yaml_file
    return [paths_by_name[name] for name in sorted(paths_by_name)]


def _load_yaml_file(yaml_file):
    with open(yaml_file, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    fields = [SchemaFieldInfo(**field) for field in data.get("fields", [])]
    index_info = IndexInfo(
        name=data["name"],
        backend=data["backend"],
        description=data["description"],
        fields=fields,
    )
    if index_info.backend not in {"ELK", "Splunk"}:
        raise ValueError(f"Unsupported SIEM backend in {yaml_file}: {index_info.backend}")
    return index_info


@lru_cache(maxsize=1)
def _load_yaml_configs():
    registry = {}
    for yaml_file in _iter_overlaid_yaml_files(*default_registry_dirs()):
        index_info = _load_yaml_file(yaml_file)
        registry[index_info.name] = index_info
    return registry


def scan_registry_configs():
    indices = []
    errors = []
    for yaml_file in _iter_overlaid_yaml_files(*default_registry_dirs()):
        try:
            index_info = _load_yaml_file(yaml_file)
        except Exception as exc:
            errors.append({"path": str(yaml_file), "error": f"{type(exc).__name__}: {exc}"})
            continue
        fields = [field.model_dump() for field in index_info.fields]
        indices.append({
            "name": index_info.name,
            "backend": index_info.backend,
            "description": index_info.description,
            "path": str(yaml_file),
            "field_count": len(fields),
            "key_field_count": sum(1 for field in index_info.fields if field.is_key_field),
            "fields": fields,
        })
    return indices, errors


def reload_registry():
    _load_yaml_configs.cache_clear()


def list_indices():
    return list(_load_yaml_configs().values())


def get_index_info(index_name):
    registry = _load_yaml_configs()
    if index_name not in registry:
        raise ValueError(f"Index {index_name} not found.")
    return registry[index_name]


def get_default_agg_fields(index_name):
    index_info = get_index_info(index_name)
    return [field.name for field in index_info.fields if field.is_key_field]


def get_backend_type(index_name):
    return get_index_info(index_name).backend
