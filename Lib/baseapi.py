import os
import sys
from abc import ABC

from langchain_core.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate

from Lib.configs import DATA_DIR
from Lib.log import logger


class BaseAPI(ABC):

    def __init__(self):
        self.logger = logger

    @staticmethod
    def _get_main_script_name():
        """
        Get the filename of the main execution script (without the extension).
        sys.argv[0] always points to the script that was originally started, regardless of which module the current code is running in.
        """
        try:
            # 1. Get the full path of the main execution script
            script_path = sys.argv[0]

            # 2. Extract the file name from the full path
            script_filename = os.path.basename(script_path)

            # 3. Separate the file name and extension
            script_name, _ = os.path.splitext(script_filename)

            return script_name
        except IndexError as e:
            raise RuntimeError("Unable to get the name of the main execution script, sys.argv[0] does not exist.") from e
        except Exception as e:
            raise RuntimeError(f"An error occurred while getting the name of the main execution script: {e}") from e

    @property
    def module_name(self):
        """Get the module loading path"""
        module_name = self.__module__.split(".")[-1]
        if module_name == "__main__":
            return self._get_main_script_name()
        else:
            return module_name

    def _get_md_file_path(self, filename: str, lang=None) -> str:
        """
        Get the file path based on the workbook name.
        """

        if os.path.isfile(filename):  # "/root/asf/ES-Rule-21-Phishing_user_report_mail/senior_phishing_expert.md"
            template_path = filename
        else:
            if filename.endswith('.md'):  # "senior_phishing_expert.md"
                fname = filename
            else:
                if lang is not None:
                    fname = f"{filename}_{lang}.md"  # "senior_phishing_expert_en"
                else:
                    fname = f"{filename}.md"  # "senior_phishing_expert"

            if os.path.isfile(os.path.join(DATA_DIR, fname)):  # "ES-Rule-21-Phishing_user_report_mail/senior_phishing_expert.md"
                template_path = os.path.join(DATA_DIR, fname)
            else:
                template_path = os.path.join(DATA_DIR, self.module_name, fname)

        return template_path

    def _get_file_path(self, filename: str):
        """
        Get the file path based on the workbook name.
        """

        if os.path.isfile(filename):  # "/root/asf/ES-Rule-21-Phishing_user_report_mail/senior_phishing_expert.md"
            return filename
        else:
            if os.path.join(DATA_DIR, self.module_name, filename):  # "ES-Rule-21-Phishing_user_report_mail/senior_phishing_expert.md"
                template_path = os.path.join(DATA_DIR, self.module_name, filename)
                return template_path
            else:
                raise Exception("File not exist")

    def _read_template_content(self, filename: str, lang=None) -> tuple[str, str]:
        template_path = self._get_md_file_path(filename, lang=lang)
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return template_path, f.read()
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def load_system_prompt_template(self, filename, lang=None):
        """Load system prompt template"""
        template_path, content = self._read_template_content(filename, lang=lang)
        try:
            system_prompt_template: SystemMessagePromptTemplate = SystemMessagePromptTemplate.from_template(content)
            logger.debug(f"Loaded system prompt template from: {template_path}")
            return system_prompt_template
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def load_human_prompt_template(self, filename, lang=None):
        template_path, content = self._read_template_content(filename, lang=lang)
        try:
            human_prompt_template: HumanMessagePromptTemplate = HumanMessagePromptTemplate.from_template(content)
            logger.debug(f"Loaded human prompt template from: {template_path}")
            return human_prompt_template
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def run(self):
        raise NotImplementedError
