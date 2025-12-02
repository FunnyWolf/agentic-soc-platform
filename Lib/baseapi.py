import os
import sys
from abc import ABC

from langchain_core.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate

from Lib.configs import DATA_DIR
from Lib.log import logger


class BaseAPI(ABC):

    def __init__(self):
        self.logger = logger

    class _TemplateWrapper:
        """ 隐藏在内部的模板包装类，只做一件事：提供 .format()。"""

        def __init__(self, content: str):
            self._content = content

        def format(self, **kwargs) -> str:
            """ 实现你想要的 .format() 方法。 """
            return self._content.format(**kwargs)

    @staticmethod
    def _get_main_script_name():
        """
        获取主执行脚本的文件名（不含扩展名）。
        无论当前代码在哪个模块中运行，sys.argv[0]始终指向最初启动的脚本。
        """
        try:
            # 1. 获取主执行脚本的完整路径
            script_path = sys.argv[0]

            # 2. 从完整路径中提取文件名
            script_filename = os.path.basename(script_path)

            # 3. 分离文件名和扩展名
            script_name, _ = os.path.splitext(script_filename)

            return script_name
        except IndexError as e:
            raise RuntimeError("无法获取主执行脚本名称，sys.argv[0]不存在。") from e
        except Exception as e:
            raise RuntimeError(f"获取主执行脚本名称时发生错误: {e}") from e

    @property
    def module_name(self):
        """获取模块加载路径"""
        module_name = self.__module__.split(".")[-1]
        if module_name == "__main__":
            return self._get_main_script_name()
        else:
            return module_name

    def _get_md_file_path(self, filename: str, lang=None) -> str:
        """
        根据 workbook 名称获取文件路径。
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

    def load_markdown_template(self, filename: str) -> _TemplateWrapper:
        """
        根据 workbook 名称读取内容，并返回一个支持 .format() 的对象。
        """

        template_path = self._get_md_file_path(filename)
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # 返回内部嵌套类的实例
                return self._TemplateWrapper(content)

        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def load_system_prompt_template(self, filename, lang=None):
        """加载系统提示模板"""
        template_path = self._get_md_file_path(filename, lang=lang)
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                system_prompt_template: SystemMessagePromptTemplate = SystemMessagePromptTemplate.from_template(f.read())
                logger.debug(f"Loaded system prompt template from: {template_path}")
                return system_prompt_template
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def load_human_prompt_template(self, filename, lang=None):
        template_path = self._get_md_file_path(filename, lang=lang)
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                human_prompt_template: HumanMessagePromptTemplate = HumanMessagePromptTemplate.from_template(f.read())
                logger.debug(f"Loaded human prompt template from: {template_path}")
                return human_prompt_template
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def run(self):
        raise NotImplementedError
