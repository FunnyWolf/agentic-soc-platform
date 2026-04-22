import os
import threading

from Lib.log import logger

_background_services_lock = threading.Lock()
_background_services_status = "not_started"
_background_services_source = None
_background_monitor_instance = None


def get_background_services_source() -> str:
    return os.environ.get("ASP_BACKGROUND_SERVICES_SOURCE", "unknown")


def should_start_background_services() -> bool:
    return os.environ.get("ASP_START_BACKGROUND_SERVICES") == "1"


def get_background_monitor_instance():
    return _background_monitor_instance


def get_or_start_background_services():
    global _background_services_status
    global _background_services_source
    global _background_monitor_instance

    source = get_background_services_source()

    if not should_start_background_services():
        logger.debug(f"Skipping background services bootstrap from source={source}")
        return None

    if _background_monitor_instance is not None:
        logger.debug(
            f"Background services already started from source={_background_services_source}, "
            f"current_source={source}, status={_background_services_status}"
        )
        return _background_monitor_instance

    with _background_services_lock:
        if _background_monitor_instance is not None:
            logger.debug(
                f"Background services already started from source={_background_services_source}, "
                f"current_source={source}, status={_background_services_status}"
            )
            return _background_monitor_instance

        from Lib.montior import MainMonitor

        _background_services_status = "starting"
        _background_services_source = source
        logger.info(f"Bootstrapping background services from source={source}")
        try:
            monitor = MainMonitor()
            monitor.start()
            _background_monitor_instance = monitor
            _background_services_status = "started"
            logger.info(f"Background services started from source={source}")
            return _background_monitor_instance
        except Exception:
            _background_services_status = "failed"
            logger.exception(f"Failed to bootstrap background services from source={source}")
            raise
