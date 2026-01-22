# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import threading
import time
import uuid
from enum import Enum
from typing import Optional, Callable, Dict, Any

from Lib.log import logger


class ThreadStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreadInfo:
    def __init__(self, thread_id: str, thread_obj: threading.Thread):
        self.thread_id = thread_id
        self.thread_obj = thread_obj
        self.status = ThreadStatus.PENDING
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.result: Any = None
        self.exception: Optional[Exception] = None

    def get_duration(self) -> Optional[float]:
        if self.start_time is None:
            return None
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    def is_alive(self) -> bool:
        return self.thread_obj.is_alive()


class ThreadModuleManager:
    def __init__(self, exception_handler: Optional[Callable[[str, Exception], None]] = None):
        self._threads: Dict[str, ThreadInfo] = {}
        self._lock = threading.Lock()
        self._exception_handler = exception_handler or self._default_exception_handler
        self._next_auto_id = 0

    def _default_exception_handler(self, thread_id: str, exception: Exception) -> None:
        logger.error(f"[Thread {thread_id}] Exception occurred: {type(exception).__name__}")
        logger.exception(exception)

    def _generate_thread_id(self) -> str:
        with self._lock:
            self._next_auto_id += 1
            return f"thread_{self._next_auto_id}"

    def _run_task(self, thread_id: str, task_obj) -> None:
        thread_info = self._threads[thread_id]
        thread_info.status = ThreadStatus.RUNNING
        thread_info.start_time = time.time()

        try:
            result = task_obj.execute()
            thread_info.result = result
            thread_info.status = ThreadStatus.COMPLETED
        except Exception as e:
            thread_info.exception = e
            thread_info.status = ThreadStatus.FAILED
            self._exception_handler(thread_id, e)
        finally:
            thread_info.end_time = time.time()

    def start_task(self, task_obj, thread_id: Optional[str] = None) -> str:
        if thread_id is None:
            thread_id = str(uuid.uuid1())

        thread = threading.Thread(
            target=self._run_task,
            args=(thread_id, task_obj),
            name=thread_id,
            daemon=False
        )

        with self._lock:
            thread_info = ThreadInfo(thread_id, thread)
            self._threads[thread_id] = thread_info

        thread.start()
        return thread_id

    def get_thread_status(self, thread_id: str) -> Optional[ThreadStatus]:
        with self._lock:
            thread_info = self._threads.get(thread_id)
            if thread_info:
                return thread_info.status
            return None

    def get_thread_info(self, thread_id: str) -> Optional[ThreadInfo]:
        with self._lock:
            return self._threads.get(thread_id)

    def get_result(self, thread_id: str) -> Any:
        with self._lock:
            thread_info = self._threads.get(thread_id)
            if thread_info and thread_info.status == ThreadStatus.COMPLETED:
                return thread_info.result
            return None

    def get_exception(self, thread_id: str) -> Optional[Exception]:
        with self._lock:
            thread_info = self._threads.get(thread_id)
            if thread_info:
                return thread_info.exception
            return None

    def wait_for_thread(self, thread_id: str, timeout: Optional[float] = None) -> bool:
        with self._lock:
            thread_info = self._threads.get(thread_id)
            if not thread_info:
                return False
            thread_obj = thread_info.thread_obj

        thread_obj.join(timeout=timeout)
        return not thread_obj.is_alive()

    def wait_for_all_threads(self, timeout: Optional[float] = None) -> bool:
        with self._lock:
            threads_copy = list(self._threads.values())

        start_time = time.time()
        for thread_info in threads_copy:
            remaining_timeout = None
            if timeout is not None:
                elapsed = time.time() - start_time
                remaining_timeout = max(0, timeout - elapsed)

            if not self.wait_for_thread(thread_info.thread_id, timeout=remaining_timeout):
                return False
        return True

    def get_active_thread_count(self) -> int:
        with self._lock:
            return sum(1 for info in self._threads.values() if info.is_alive())

    def get_all_threads_info(self) -> Dict[str, ThreadInfo]:
        with self._lock:
            return dict(self._threads)

    def get_thread_count(self) -> int:
        with self._lock:
            return len(self._threads)

    def set_exception_handler(self, handler: Callable[[str, Exception], None]) -> None:
        self._exception_handler = handler


thread_module_manager = ThreadModuleManager()
