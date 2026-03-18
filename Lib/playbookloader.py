import importlib
from pathlib import Path

from Lib.configs import BASE_DIR
from Lib.log import logger
from Lib.xcache import Xcache
from PLUGINS.SIRP.sirpapi import Playbook, Case, Alert, Artifact
from PLUGINS.SIRP.sirpmodel import PlaybookModel, PlaybookJobStatus


class PlaybookLoader:
    PLAYBOOKS_PACKAGE = "PLAYBOOKS"
    IGNORE_MODULE_NAMES = {"", "__init__", "__pycache__"}

    @classmethod
    def _is_valid_module_name(cls, module_name):
        return module_name not in cls.IGNORE_MODULE_NAMES

    @classmethod
    def _load_playbook_class(cls, module_name, module_package):
        if not cls._is_valid_module_name(module_name):
            return None
        try:
            return importlib.import_module(f'{module_package}.{module_name}').Playbook
        except Exception as exc:
            logger.exception(exc)
            return None

    @classmethod
    def _build_playbook_config(cls, module_name, module_package, playbook_type):
        playbook_class = cls._load_playbook_class(module_name, module_package)
        if playbook_class is None:
            return None

        playbook_name = getattr(playbook_class, 'NAME', None)
        playbook_desc = getattr(playbook_class, 'DESC', None)
        if not playbook_name:
            return None

        return {
            "TYPE": playbook_type,
            "NAME": playbook_name,
            "DESC": playbook_desc,
            "load_path": f'{module_package}.{module_name}',
        }

    @classmethod
    def _iter_playbook_modules(cls):
        playbooks_dir = Path(BASE_DIR) / cls.PLAYBOOKS_PACKAGE
        if not playbooks_dir.exists():
            return

        type_dirs = sorted(path for path in playbooks_dir.iterdir() if path.is_dir() and cls._is_valid_module_name(path.name))
        for type_dir in type_dirs:
            playbook_type = type_dir.name
            module_package = f'{cls.PLAYBOOKS_PACKAGE}.{type_dir.name}'
            for module_file in sorted(type_dir.glob('*.py')):
                if cls._is_valid_module_name(module_file.stem):
                    yield module_file.stem, module_package, playbook_type

    @classmethod
    def load_all_playbook_config(cls):
        all_modules_config = []
        for module_name, module_package, playbook_type in cls._iter_playbook_modules():
            module_config = cls._build_playbook_config(module_name, module_package, playbook_type)
            if module_config is None:
                continue
            all_modules_config.append(module_config)

        Xcache.update_module_configs(all_modules_config)

        logger.info(f"Built-in playbooks loaded, loaded {len(all_modules_config)} playbooks")

    @classmethod
    def list_playbook_config(cls):
        all_modules_config = Xcache.list_module_configs()
        return all_modules_config

    @classmethod
    def run_playbook_job(cls, type, name, user_input=None, source_rowid=None, id=None):
        if source_rowid is None:
            if id is None:
                raise Exception("id is required when source_rowid is None")
            else:
                if type == "CASE":
                    record = Case.get_by_id(id)
                    source_rowid = record.rowid
                elif type == "ALERT":
                    record = Alert.get_by_id(id)
                    source_rowid = record.rowid
                elif type == "ARTIFACT":
                    record = Artifact.get_by_id(id)
                    source_rowid = record.rowid

        model = PlaybookModel()
        model.source_rowid = source_rowid
        model.job_status = PlaybookJobStatus.PENDING
        model.type = type
        model.name = name
        model.user_input = user_input
        rowid = Playbook.create(model)
        return rowid
