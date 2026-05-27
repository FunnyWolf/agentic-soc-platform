import importlib
from pathlib import Path

from Lib.configs import BASE_DIR
from Lib.log import logger
from Lib.xcache import Xcache


class PlaybookLoader:
    PLAYBOOKS_PACKAGE = "PLAYBOOKS"
    IGNORE_MODULE_NAMES = {"", "__init__", "__pycache__"}

    @classmethod
    def _is_valid_module_name(cls, module_name):
        return module_name not in cls.IGNORE_MODULE_NAMES

    @classmethod
    def _load_playbook_class(cls, module_name):
        if not cls._is_valid_module_name(module_name):
            return None
        try:
            return importlib.import_module(f'{cls.PLAYBOOKS_PACKAGE}.{module_name}').Playbook
        except Exception as exc:
            logger.exception(exc)
            return None

    @classmethod
    def _build_playbook_config(cls, module_name):
        playbook_class = cls._load_playbook_class(module_name)
        if playbook_class is None:
            return None

        playbook_name = getattr(playbook_class, 'NAME', None)
        playbook_desc = getattr(playbook_class, 'DESC', None)
        if not playbook_name:
            return None

        return {
            "NAME": playbook_name,
            "DESC": playbook_desc,
            "load_path": f'{cls.PLAYBOOKS_PACKAGE}.{module_name}',
        }

    @classmethod
    def _iter_playbook_modules(cls):
        playbooks_dir = Path(BASE_DIR) / cls.PLAYBOOKS_PACKAGE
        if not playbooks_dir.exists():
            return

        for module_file in sorted(playbooks_dir.glob('*.py')):
            if cls._is_valid_module_name(module_file.stem):
                yield module_file.stem

    @classmethod
    def load_all_playbook_config(cls):
        all_modules_config = []
        for module_name in cls._iter_playbook_modules():
            module_config = cls._build_playbook_config(module_name)
            if module_config is None:
                continue
            all_modules_config.append(module_config)

        Xcache.update_module_configs(all_modules_config)

        logger.info(f"Built-in playbooks loaded, loaded {len(all_modules_config)} playbooks")

    @classmethod
    def list_playbook_config(cls):
        all_modules_config = Xcache.list_module_configs()
        return all_modules_config
