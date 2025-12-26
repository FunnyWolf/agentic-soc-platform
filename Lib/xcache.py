# -*- coding: utf-8 -*-
# @File  : xcache.py
# @Date  : 2021/2/25
# @Desc  :

from django.core.cache import cache

from Lib.configs import EXPIRE_MINUTES
from Lib.log import logger


class Xcache(object):
    XCACHE_TOKEN = "XCACHE_TOKEN"
    XCACHE_MODULES_TASK_LIST = "XCACHE_MODULES_TASK_LIST"
    XCACHE_MODULES_CONFIG = "XCACHE_MODULES_CONFIG"
    XCACHE_SIRP_OPTIONSET = "XCACHE_SIRP_OPTIONSET"
    XCACHE_SIRP_FIELDS = "XCACHE_SIRP_FIELDS"

    def __init__(self):
        pass

    @staticmethod
    def set_sirp_fields(worksheet_id, fields, expire=60):
        key = f"{Xcache.XCACHE_SIRP_FIELDS}-{worksheet_id}"
        cache.set(key, fields, expire)

    @staticmethod
    def get_sirp_fields(worksheet_id):
        key = f"{Xcache.XCACHE_SIRP_FIELDS}-{worksheet_id}"
        fields = cache.get(key)
        return fields

    @staticmethod
    def set_sirp_optionset(optionset, expire=60):
        key = f"{Xcache.XCACHE_SIRP_OPTIONSET}"
        cache.set(key, optionset, expire)

    @staticmethod
    def get_sirp_optionset():
        key = f"{Xcache.XCACHE_SIRP_OPTIONSET}"
        optionset = cache.get(key)
        return optionset

    @staticmethod
    def alive_token(token):
        key = f"{Xcache.XCACHE_TOKEN}-{token}"
        cache_user = cache.get(key)
        return cache_user

    @staticmethod
    def set_token_user(token, user, expire=EXPIRE_MINUTES):
        key = f"{Xcache.XCACHE_TOKEN}-{token}"
        cache.set(key, user, expire)

    @staticmethod
    def clean_all_token():
        re_key = f"{Xcache.XCACHE_TOKEN}-*"
        keys = cache.keys(re_key)
        for key in keys:
            cache.delete(key)

    @staticmethod
    def get_module_task_by_uuid(task_uuid):
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{task_uuid}"
        req = cache.get(key)
        return req

    @staticmethod
    def list_module_tasks():
        re_key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_*"
        keys = cache.keys(re_key)
        reqs = []
        for key in keys:
            reqs.append(cache.get(key))
        return reqs

    @staticmethod
    def create_module_task(req):
        """Task Queue"""
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{req.get('uuid')}"
        cache.set(key, req, None)
        return True

    @staticmethod
    def del_module_task_by_uuid(task_uuid):
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{task_uuid}"
        cache.delete(key)

    @staticmethod
    def get_module_task_length():
        re_key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_*"
        keys = cache.keys(re_key)
        return len(keys)

    @staticmethod
    def list_module_configs():
        modules_config = cache.get(Xcache.XCACHE_MODULES_CONFIG)
        if modules_config is None:
            return None
        else:
            return modules_config

    @staticmethod
    def update_module_configs(all_modules_config):
        cache.set(Xcache.XCACHE_MODULES_CONFIG, all_modules_config, None)
        return True

    @staticmethod
    def get_module_config(loadpath):
        modules_config = cache.get(Xcache.XCACHE_MODULES_CONFIG)
        try:
            for config in modules_config:
                if config.get("loadpath") == loadpath:
                    return config
            return None
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def get_module_config_by_name_and_type(type, name):
        modules_config = cache.get(Xcache.XCACHE_MODULES_CONFIG)
        try:
            for config in modules_config:
                if config.get("NAME") == name and config.get("TYPE") == type:
                    return config
            return None
        except Exception as E:
            logger.exception(E)
            return None
