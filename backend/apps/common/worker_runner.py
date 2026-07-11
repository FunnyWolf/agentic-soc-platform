import logging
import time
from dataclasses import dataclass

from django.core.management.base import CommandError

from apps.common.logging import configure_process_file_logging

SLEEP_ALWAYS = "always"
SLEEP_WHEN_IDLE = "when_idle"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkerIterationResult:
    processed: bool = False
    message: str = ""


def add_worker_arguments(parser, *, interval_help="Seconds between worker iterations."):
    parser.add_argument("--once", action="store_true", help="Run one worker iteration and exit.")
    parser.add_argument("--interval", type=float, help=interval_help)


def _coerce_result(result):
    if isinstance(result, WorkerIterationResult):
        return result
    if isinstance(result, bool):
        return WorkerIterationResult(processed=result)
    return WorkerIterationResult(processed=bool(result))


def _resolve_interval(options, default_interval):
    interval = options.get("interval")
    if interval is None:
        interval = default_interval() if callable(default_interval) else default_interval
    if interval <= 0:
        raise CommandError("--interval must be greater than 0.")
    return interval


def _styled(command, style_name, message):
    styler = getattr(command.style, style_name, None)
    return styler(message) if styler else message


def _worker_label(worker_name):
    return worker_name if worker_name.endswith("worker") else f"{worker_name} worker"


def _refresh_runtime_config_cache():
    from apps.settings.runtime_config import invalidate

    invalidate()


def _run_once_or_raise(worker_label, run_once):
    try:
        _refresh_runtime_config_cache()
        return _coerce_result(run_once())
    except CommandError:
        raise
    except Exception as exc:
        raise CommandError(f"{worker_label} iteration failed: {type(exc).__name__}: {exc}") from exc


def _should_sleep(result, sleep_policy):
    if sleep_policy == SLEEP_ALWAYS:
        return True
    if sleep_policy == SLEEP_WHEN_IDLE:
        return not result.processed
    raise ValueError(f"unsupported worker sleep policy: {sleep_policy}")


def run_worker(
    command,
    *,
    options,
    worker_name,
    run_once,
    default_interval,
    sleep_policy=SLEEP_WHEN_IDLE,
    started_message=None,
    stopped_message=None,
    sleep_seconds=None,
    log_role=None,
):
    worker_label = _worker_label(worker_name)
    if sleep_policy not in {SLEEP_ALWAYS, SLEEP_WHEN_IDLE}:
        raise ValueError(f"unsupported worker sleep policy: {sleep_policy}")
    if log_role and not configure_process_file_logging(log_role):
        raise CommandError(f"unsupported worker log role: {log_role}")
    interval = _resolve_interval(options, default_interval)

    if options["once"]:
        result = _run_once_or_raise(worker_label, run_once)
        command.stdout.write(result.message or f"{worker_label} completed one iteration")
        return

    command.stdout.write(_styled(command, "SUCCESS", started_message or f"{worker_label} started"))
    try:
        while True:
            try:
                result = _run_once_or_raise(worker_label, run_once)
                if result.message:
                    command.stdout.write(result.message)
                if _should_sleep(result, sleep_policy):
                    current_sleep_seconds = sleep_seconds() if sleep_seconds else interval
                    if current_sleep_seconds <= 0:
                        raise CommandError("worker sleep interval must be greater than 0.")
                    time.sleep(current_sleep_seconds)
            except Exception as exc:
                logger.exception("%s iteration failed", worker_label)
                command.stderr.write(_styled(command, "ERROR", f"{worker_label} failed: {type(exc).__name__}: {exc}"))
                time.sleep(interval)
    except KeyboardInterrupt:
        command.stdout.write(_styled(command, "WARNING", stopped_message or f"{worker_label} stopped."))
