from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from django.conf import settings
from django.db import close_old_connections
from rest_framework.exceptions import APIException


class OperationTimeoutError(APIException):
    status_code = 504
    default_detail = "Operation timed out."
    default_code = "operation_timeout"


_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="asp-operation")


def _run_with_db_cleanup(func, args, kwargs):
    close_old_connections()
    try:
        return func(*args, **kwargs)
    finally:
        close_old_connections()


def run_with_operation_timeout(operation: str, func, *args, timeout_seconds: float | None = None, **kwargs):
    timeout = float(timeout_seconds if timeout_seconds is not None else settings.SYNC_OPERATION_TIMEOUT_SECONDS)
    future = _executor.submit(_run_with_db_cleanup, func, args, kwargs)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError as exc:
        future.cancel()
        raise OperationTimeoutError(f"{operation} timed out after {timeout:g} seconds.") from exc
