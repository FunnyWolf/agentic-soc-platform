# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import threading
import time
import uuid
from enum import Enum
from typing import Optional, Callable, Dict, Protocol

from Lib.log import logger


class TaskExecutable(Protocol):
    def execute(self) -> object:
        ...


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
        self.result: object = None
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

    def _run_task(self, thread_id: str, task_obj: TaskExecutable, on_finished: Optional[Callable] = None,
                  callback_context: Optional[Dict[str, str]] = None) -> None:
        thread_info = self._threads[thread_id]
        thread_info.status = ThreadStatus.RUNNING
        thread_info.start_time = time.time()

        try:
            result = task_obj.execute()
            thread_info.result = result
            thread_info.status = ThreadStatus.COMPLETED
            logger.info(f"[Thread {thread_id}] Task completed successfully.")
        except Exception as e:
            thread_info.exception = e
            thread_info.status = ThreadStatus.FAILED
            self._exception_handler(thread_id, e)
            logger.error(f"[Thread {thread_id}] Task failed with exception.")
        finally:
            thread_info.end_time = time.time()
            if on_finished:
                try:
                    on_finished(
                        thread_id=thread_id,
                        task_obj=task_obj,
                        result=thread_info.result,
                        exception=thread_info.exception,
                        context=callback_context,
                    )
                except Exception as callback_exception:
                    logger.error(f"[Thread {thread_id}] on_finished callback failed: {type(callback_exception).__name__}")
                    logger.exception(callback_exception)

    def start_task(self, task_obj: TaskExecutable, thread_id: Optional[str] = None,
                   on_finished: Optional[Callable] = None, callback_context: Optional[Dict[str, str]] = None) -> str:
        if thread_id is None:
            thread_id = str(uuid.uuid1())

        thread = threading.Thread(
            target=self._run_task,
            args=(thread_id, task_obj, on_finished, callback_context),
            name=thread_id,
            daemon=False
        )

        with self._lock:
            thread_info = ThreadInfo(thread_id, thread)
            self._threads[thread_id] = thread_info

        thread.start()
        return thread_id


thread_module_manager = ThreadModuleManager()
