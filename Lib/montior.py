# -*- coding: utf-8 -*-

import importlib
import threading
import time
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler

from Lib.baseplaybook import BasePlaybook
from Lib.log import logger
from Lib.moduleengine import ModuleEngine
from Lib.playbookloader import PlaybookLoader
from Lib.threadmodulemanager import thread_module_manager
from Lib.xcache import Xcache
from PLUGINS.Embeddings.embeddings_qdrant import get_qdrant_embeddings_api, SIRP_KNOWLEDGE_COLLECTION
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIRP.sirpapi import Playbook, Knowledge, Case
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, KnowledgeAction, PlaybookModel


class MainMonitor(object):
    MainScheduler: BackgroundScheduler
    _background_threads = {}

    def __init__(self):
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

    def start_background_task(self, task_func: Callable, task_name: str, retry_interval: int = 5, exec_interval: int = None):
        """
        Start a background task in a separate thread

        Args:
            task_func: The function to run
            task_name: Name of the task for logging
            retry_interval: Seconds to wait between retries on error
            exec_interval: Seconds to wait between executions (defaults to retry_interval if None)
        """
        thread = threading.Thread(
            target=self.run_task_in_loop,
            args=(task_func, task_name, retry_interval, exec_interval),
            daemon=True,
            name=task_name
        )
        self._background_threads[task_name] = thread
        thread.start()
        logger.info(f"Started background task: {task_name}")

    def start(self):
        logger.info("Starting background services...")
        logger.info("Load PlaybookLoader module config")
        PlaybookLoader.load_all_playbook_config()

        delay_time = 3

        # Start background tasks
        self.start_background_task(self.subscribe_pending_playbook, "subscribe_pending_playbook", delay_time)
        self.start_background_task(self.subscribe_knowledge_action, "subscribe_knowledge_action", delay_time)
        self.start_background_task(self.subscribe_case_analysis_cooldown, "subscribe_case_analysis_cooldown", delay_time)

        # engine
        # self.engine.start()
        logger.info("Background services started.")

    @staticmethod
    def subscribe_pending_playbook():
        models = Playbook.list_pending_playbooks()

        for model in models:
            module_config = Xcache.get_module_config_by_name_and_type(model.type, model.name)
            model_tmp = PlaybookModel(row_id=model.row_id)
            if module_config is None:
                PlaybookLoader.load_all_playbook_config()  # try again
                module_config = Xcache.get_module_config_by_name_and_type(model.type, model.name)
            if module_config is None:
                logger.error(f"PlaybookLoader module config not found: {model.type} - {model.name}")
                model_tmp.job_status = PlaybookJobStatus.FAILED
                model_tmp.remark = f"PlaybookLoader module config not found: {model.type} - {model.name}"
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

            job_id = thread_module_manager.start_task(playbook_intent)
            if not job_id:
                model_tmp.job_status = PlaybookJobStatus.FAILED
                model_tmp.remark = "Failed to create playbook job."
                Playbook.update(model_tmp)
                continue
            else:
                logger.info(f"Create playbook job success: {job_id}")
                model_tmp.job_status = PlaybookJobStatus.RUNNING
                model_tmp.job_id = job_id
                Playbook.update(model_tmp)

    @staticmethod
    def subscribe_knowledge_action():
        models = Knowledge.list_undone_action_records()
        if models:
            for model in models:
                payload_content = f"# {model.title}\n\n{model.body}"
                if model.action == KnowledgeAction.STORE:
                    logger.info(f"Knowledge storing,row_id: {model.row_id}")
                    try:
                        doc_id = get_qdrant_embeddings_api().add_document(SIRP_KNOWLEDGE_COLLECTION, model.row_id, payload_content, {"row_id": model.row_id})
                    except Exception as E:
                        logger.exception(E)

                    model.action = KnowledgeAction.DONE
                    model.using = True
                    logger.info(f"Knowledge stored,row_id: {model.row_id}")
                elif model.action == KnowledgeAction.REMOVE:
                    logger.info(f"Knowledge removing,row_id: {model.row_id}")
                    try:
                        result = get_qdrant_embeddings_api().delete_document(SIRP_KNOWLEDGE_COLLECTION, model.row_id)
                    except Exception as E:
                        logger.exception(E)

                    model.action = KnowledgeAction.DONE
                    model.using = False
                    logger.info(f"Knowledge removed,row_id: {model.row_id}")
                else:
                    logger.error(f"Unknown knowledge action: {model.action}")
                    continue

                # update status to Done
                row_id = Knowledge.update(model)

    @staticmethod
    def subscribe_case_analysis_cooldown():
        promoted_row_ids = Case.promote_due_analysis_cases()
        if promoted_row_ids:
            logger.info(f"Queued {len(promoted_row_ids)} case(s) for analysis after cooldown.")
