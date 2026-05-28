# -*- coding: utf-8 -*-

import importlib
import threading
import time
import uuid
from typing import Callable, Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler

from Lib.baseplaybook import BasePlaybook
from Lib.log import logger
from Lib.moduleengine import ModuleEngine
from Lib.playbookloader import PlaybookLoader
from Lib.threadmodulemanager import thread_module_manager
from Lib.xcache import Xcache
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from Lib.analysis import run_case_analysis
from PLUGINS.SIRP.sirpapi import Playbook, Case
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel


class MainMonitor(object):
    @staticmethod
    def on_playbook_task_finished(thread_id: str, task_obj: BasePlaybook, result: object,
                                  exception: Optional[Exception], context: Optional[Dict[str, str]] = None):
        context = context or {}
        playbook_row_id = context.get("playbook_row_id")
        if not isinstance(playbook_row_id, str) or playbook_row_id == "":
            logger.error(f"[Thread {thread_id}] Missing playbook_row_id in callback context.")
            return

        try:
            playbook_current = Playbook.get(playbook_row_id, lazy_load=True)
        except Exception as e:
            logger.error(f"[Thread {thread_id}] Failed to load playbook for fallback status update.")
            logger.exception(e)
            return

        # Business code has already written a terminal state; do not overwrite.
        if playbook_current.job_status != PlaybookJobStatus.RUNNING:
            logger.info(
                f"[Thread {thread_id}] Skip fallback status update, current status: {playbook_current.job_status}, "
                f"row_id: {playbook_row_id}"
            )
            return

        fallback_status = PlaybookJobStatus.SUCCESS if exception is None else PlaybookJobStatus.FAILED
        if exception is None:
            remark = f"source=thread_fallback; thread_id={thread_id}; message=Task finished without explicit business status update."
        else:
            remark = (
                f"source=thread_fallback; thread_id={thread_id}; "
                f"exception={type(exception).__name__}; message={exception}"
            )

        model_tmp = PlaybookModel(row_id=playbook_row_id)
        model_tmp.job_status = fallback_status
        model_tmp.remark = remark
        Playbook.update(model_tmp)

        logger.info(
            f"[Thread {thread_id}] Applied fallback status update: {fallback_status}, row_id: {playbook_row_id}"
        )

    MainScheduler: BackgroundScheduler

    def __init__(self):
        self._background_threads: Dict[str, list] = {}
        self.engine = ModuleEngine()
        self.redis_stream_api = RedisStreamAPI()
        self.MainScheduler = BackgroundScheduler(timezone='Asia/Shanghai')

    @staticmethod
    def run_task_in_loop(task_func: Callable, task_name: str, retry_interval: int = 5, exec_interval: int = None):
        """
        Run a task function in an infinite loop with error handling

        Args:
            task_func: The function to run
            task_name: Name of the task for logging
            retry_interval: Seconds to wait between retries on error
            exec_interval: Seconds to wait between executions (defaults to retry_interval if None)
        """
        # If exec_interval is not specified, use retry_interval
        if exec_interval is None:
            exec_interval = retry_interval

        while True:
            try:
                task_func()
                # Wait for the specified execution interval before running again
                time.sleep(exec_interval)
            except Exception as e:
                logger.error(f"Error in {task_name}")
                logger.exception(e)
                time.sleep(retry_interval)

    def start_background_task(self, task_func: Callable, task_name: str, retry_interval: int = 5,
                              exec_interval: int = None, thread_count: int = 1):
        """
        Start a background task in one or more separate threads

        Args:
            task_func: The function to run
            task_name: Name of the task for logging
            retry_interval: Seconds to wait between retries on error
            exec_interval: Seconds to wait between executions (defaults to retry_interval if None)
            thread_count: Number of threads to spawn for this task
        """
        if task_name not in self._background_threads:
            self._background_threads[task_name] = []

        for i in range(thread_count):
            suffix = f"#{i}" if thread_count > 1 else ""
            thread_name = f"{task_name}{suffix}"
            thread = threading.Thread(
                target=self.run_task_in_loop,
                args=(task_func, thread_name, retry_interval, exec_interval),
                daemon=True,
                name=thread_name,
            )
            self._background_threads[task_name].append(thread)
            thread.start()
            logger.info(f"Started background task: {thread_name}")

    def start(self):
        logger.info("Starting background services...")
        logger.info("Load PlaybookLoader module config")
        PlaybookLoader.load_all_playbook_config()

        delay_time = 3

        # Start background tasks
        self.start_background_task(self.subscribe_pending_playbook, "subscribe_pending_playbook", delay_time)
        self.start_background_task(self.subscribe_case_analysis_scheduler, "subscribe_case_analysis_scheduler", delay_time)
        self.start_background_task(self.subscribe_case_analysis_queue, "subscribe_case_analysis_queue", delay_time, thread_count=3)

        # engine
        self.engine.start()
        logger.info("Background services started.")

    @staticmethod
    def subscribe_pending_playbook():
        models = Playbook.list_pending_playbooks()

        for model in models:
            module_config = Xcache.get_module_config_by_name(model.name)
            model_tmp = PlaybookModel(row_id=model.row_id)
            if module_config is None:
                PlaybookLoader.load_all_playbook_config()  # try again
                module_config = Xcache.get_module_config_by_name(model.name)
            if module_config is None:
                logger.error(f"PlaybookLoader module config not found:  {model.name}")
                model_tmp.job_status = PlaybookJobStatus.FAILED
                model_tmp.remark = f"PlaybookLoader module config not found:  {model.name}"
                Playbook.update(model_tmp)
                continue

            load_path = module_config.get("load_path")

            try:
                class_intent = importlib.import_module(load_path)
                playbook_intent: BasePlaybook = class_intent.Playbook()
                playbook_intent._playbook_model = model
            except Exception as E:
                logger.exception(E)
                model_tmp.job_status = PlaybookJobStatus.FAILED
                model_tmp.remark = str(E)
                Playbook.update(model_tmp)
                continue

            job_id = str(uuid.uuid1())
            model_tmp.job_status = PlaybookJobStatus.RUNNING
            model_tmp.job_id = job_id
            Playbook.update(model_tmp)

            try:
                thread_module_manager.start_task(
                    playbook_intent,
                    thread_id=job_id,
                    on_finished=MainMonitor.on_playbook_task_finished,
                    callback_context={
                        "playbook_row_id": model.row_id,
                    },
                )
            except Exception as e:
                model_tmp.job_status = PlaybookJobStatus.FAILED
                model_tmp.remark = f"Failed to create playbook job. exception={type(e).__name__}; message={e}"
                Playbook.update(model_tmp)
                continue

            logger.info(f"Create playbook job success: {job_id}")

    @staticmethod
    def subscribe_case_analysis_scheduler():
        # Periodically move due cases into the analysis queue.
        # 周期性扫描到点案件，并将其送入分析队列。
        promoted_row_ids = Case.promote_due_analysis_cases()
        if promoted_row_ids:
            logger.info(f"Queued {len(promoted_row_ids)} case(s) for scheduled analysis.")

    def subscribe_case_analysis_queue(self):
        # Consume one queue message and hand it to the analysis runner.
        # 每次消费一条队列消息，并交给分析执行器处理。
        message = self.redis_stream_api.read_stream_message_with_id(
            stream_name=Case.ANALYSIS_STREAM_NAME,
            consumer_name="case-analysis-worker",
        )
        queue_message_id = message.get("message_id")
        payload = message.get("data", {})
        case_row_id = payload.get("case_row_id")
        trigger = payload.get("trigger", "unknown")

        if not case_row_id:
            logger.error("Case analysis queue message missing case_row_id.")
            return

        run_case_analysis(case_row_id, trigger, queue_message_id=queue_message_id)
