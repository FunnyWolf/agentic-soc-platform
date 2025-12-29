import importlib
import os

from Lib.configs import BASE_DIR
from Lib.log import logger
from Lib.xcache import Xcache


class Playbook(object):
    """Task Adder"""

    def __init__(self):
        pass

    @staticmethod
    def get_playbook_intent(modulename, module_files_dir):
        if modulename == "__init__" or modulename == "__pycache__" or modulename == '':  # Special handling for __init__.py
            return None
        try:
            class_intent = importlib.import_module(f'{module_files_dir}.{modulename}')
            module_intent = class_intent.Playbook
            return module_intent
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def gen_playbook_config(modulename, module_files_dir="PLAYBOOKS"):
        module_intent = Playbook.get_playbook_intent(modulename, module_files_dir)

        if module_intent is None:
            return None

        if module_intent.TYPE is None or module_intent.NAME is None:
            return None

        try:
            one_module_config = {
                "TYPE": module_intent.TYPE,  # Processor
                "NAME": module_intent.NAME,
                "load_path": f'{module_files_dir}.{modulename}',
            }
            return one_module_config
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def load_all_playbook_config():
        all_modules_config = []
        # post module
        module_count = 0
        module_filenames = os.listdir(os.path.join(BASE_DIR, 'PLAYBOOKS'))
        for module_filename in module_filenames:
            module_name = module_filename.split(".")[0]
            one_module_config = Playbook.gen_playbook_config(module_name, 'PLAYBOOKS')
            if one_module_config is not None:
                all_modules_config.append(one_module_config)
                module_count += 1

        Xcache.update_module_configs(all_modules_config)

        logger.info(f"Built-in playbooks loaded, loaded {module_count} playbooks")
