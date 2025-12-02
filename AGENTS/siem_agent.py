import json
from typing import Annotated

from langchain_core.tools import tool

from PLUGINS.Mock.SIEM import SIEMMock


class SIEMAgent(object):

    @staticmethod
    @tool("siem_search")
    def search(
            natural_query: Annotated[str, "自然语言的搜索请求 (e.g., '10.10.10.10 在2025-11-29 10:10:10 至 2025-11-29 10:10:20 之间 ftp 协议的网络请求日志')"]
    ) -> Annotated[str, "返回的日志列表,每条日志是一个字典对象,如果查找失败则返回 None,查找不到时返回空列表"]:
        """
        Search for security logs using Natural Language descriptions.
        The backend will automatically translate your description into the correct query syntax
        and retrieve relevant logs.
        """
        logs = SIEMMock.search(natural_query)
        if logs is None:
            return "None"
        return json.dumps(logs)
