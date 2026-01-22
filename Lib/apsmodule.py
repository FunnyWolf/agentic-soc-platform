# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import threading
import time
import uuid

from apscheduler.events import EVENT_JOB_ADDED, EVENT_JOB_REMOVED, EVENT_JOB_MODIFIED, EVENT_JOB_EXECUTED, \
    EVENT_JOB_ERROR, EVENT_JOB_MISSED, EVENT_JOB_SUBMITTED, EVENT_JOB_MAX_INSTANCES
from apscheduler.schedulers.background import BackgroundScheduler

from Lib.log import logger
from Lib.xcache import Xcache


class APSModule(object):
    """处理post python模块请求,单例模式运行
    EVENT_JOB_ADDED | EVENT_JOB_REMOVED | EVENT_JOB_MODIFIED |EVENT_JOB_EXECUTED |
    EVENT_JOB_ERROR | EVENT_JOB_MISSED |EVENT_JOB_SUBMITTED | EVENT_JOB_MAX_INSTANCES
    """
    _instance_lock = threading.Lock()

    def __init__(self):

        self.ModuleJobsScheduler = BackgroundScheduler()
        self.ModuleJobsScheduler.add_listener(self.deal_result)
        self.ModuleJobsScheduler.start()

    def __new__(cls, *args, **kwargs):
        if not hasattr(APSModule, "_instance"):
            with APSModule._instance_lock:
                if not hasattr(APSModule, "_instance"):
                    APSModule._instance = object.__new__(cls)
        return APSModule._instance

    def putin_post_python_module_queue(self, post_module_intent=None):
        try:
            # 存储uuid
            module_uuid = str(uuid.uuid1())

            logger.info(f"模块放入列表: uuid: {module_uuid}")
            self.ModuleJobsScheduler.add_job(func=post_module_intent.run, max_instances=1, id=module_uuid)

            # 放入缓存队列,用于后续删除任务,存储结果等

            req = {
                'uuid': module_uuid,
                # 'module': post_module_intent,   # 对象无法存储到缓存中
                'time': int(time.time()),
            }
            Xcache.create_module_task(req)

            return module_uuid
        except Exception as E:
            logger.exception(E)
            return None

    def deal_result(self, event=None):
        flag = False
        if event.code == EVENT_JOB_ADDED:
            pass
        elif event.code == EVENT_JOB_REMOVED:
            pass
        elif event.code == EVENT_JOB_MODIFIED:
            pass
        elif event.code == EVENT_JOB_EXECUTED:  # 执行完成
            flag = self.store_executed_result(event.job_id)
        elif event.code == EVENT_JOB_ERROR:
            flag = self.store_error_result(event.job_id, event.exception)
        elif event.code == EVENT_JOB_MISSED:
            pass
        elif event.code == EVENT_JOB_SUBMITTED:
            pass
        elif event.code == EVENT_JOB_MAX_INSTANCES:
            pass
        else:
            pass
        return flag

    @staticmethod
    def store_executed_result(job_id=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=job_id)
        if req is None:
            logger.warning("缓存中无对应实例,模块已中途退出")
            return False
        Xcache.del_module_task_by_uuid(task_uuid=job_id)  # 清理缓存信息
        logger.info(f"模块执行完成: uuid: {job_id}")

    @staticmethod
    def store_error_result(job_id=None, exception=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=job_id)
        Xcache.del_module_task_by_uuid(task_uuid=job_id)  # 清理缓存信息
        logger.exception(exception)

    def delete_job_by_uuid(self, job_id=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=job_id)
        Xcache.del_module_task_by_uuid(task_uuid=job_id)  # 清理缓存信息
        logger.info(f"多模块实例手动删除:{job_id}")
        return True


aps_module = APSModule()
