import logging
import os
import socket
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from apps.agentic.runtime.base import BaseModule
from apps.agentic.runtime.loader import discover_script_class, iter_overlaid_python_scripts
from apps.common.redis_stream import RedisStreamClient, RedisStreamMessageDecodeError

AGENTIC_MODULE_CONSUMER_GROUP = "agentic-modules"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModuleDefinition:
    name: str
    stream_name: str
    thread_num: int
    path: Path
    module_class: type


def default_custom_module_scripts_dir():
    return Path(settings.CUSTOM_DIR) / "modules"


def default_module_script_dirs():
    return [default_custom_module_scripts_dir()]


def default_consumer_name(module_name):
    safe_name = module_name.replace(" ", "-").lower()
    return f"{socket.gethostname()}-{os.getpid()}-{safe_name}"


def _definition_from_script(path):
    definition = discover_script_class(path, class_name="Module", base_class=BaseModule)
    if definition is None:
        return None
    stream_name = getattr(definition.script_class, "STREAM_NAME", "")
    if not stream_name:
        return None
    return ModuleDefinition(
        name=definition.name,
        stream_name=stream_name,
        thread_num=getattr(definition.script_class, "THREAD_NUM", 1),
        path=definition.path,
        module_class=definition.script_class,
    )


def scan_module_definitions(*, scripts_dir=None, scripts_dirs=None):
    if scripts_dirs is not None and scripts_dir is not None:
        raise ValueError("Use scripts_dir or scripts_dirs, not both.")
    paths = (
        iter_overlaid_python_scripts(*(scripts_dirs or default_module_script_dirs()))
        if scripts_dir is None
        else iter_overlaid_python_scripts(scripts_dir)
    )
    definitions = []
    errors = []
    for path in paths:
        try:
            definition = _definition_from_script(path)
        except Exception as exc:
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            continue
        if definition is not None:
            definitions.append(definition)
    return definitions, errors


def discover_module_definitions(*, scripts_dir=None, scripts_dirs=None):
    definitions, _errors = scan_module_definitions(scripts_dir=scripts_dir, scripts_dirs=scripts_dirs)
    return definitions


def run_module_once(definition, *, redis_client=None, block_ms=None, consumer_name=None):
    redis_client = redis_client or RedisStreamClient()
    group = AGENTIC_MODULE_CONSUMER_GROUP
    consumer = consumer_name or default_consumer_name(definition.name)
    try:
        message = redis_client.read_message(
            definition.stream_name,
            group=group,
            consumer=consumer,
            block_ms=block_ms,
        )
    except RedisStreamMessageDecodeError as exc:
        logger.exception(
            "Invalid Redis module message consumed module=%s stream=%s message_id=%s",
            definition.name,
            exc.stream,
            exc.message_id,
        )
        return True
    if message is None:
        return False

    try:
        module = definition.module_class()
        module.run(message["data"])
    except Exception:
        logger.exception(
            "Agentic module failed after consuming Redis message module=%s stream=%s message_id=%s",
            definition.name,
            definition.stream_name,
            message["message_id"],
        )
    return True


def run_all_modules_once(*, redis_client=None, block_ms=None, scripts_dir=None):
    redis_client = redis_client or RedisStreamClient()
    any_processed = False
    for definition in discover_module_definitions(scripts_dir=scripts_dir):
        processed = run_module_once(definition, redis_client=redis_client, block_ms=block_ms)
        any_processed = any_processed or processed
    return any_processed
