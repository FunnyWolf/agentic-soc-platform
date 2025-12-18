import re

import httpx
import urllib3
from langchain_core.messages import AIMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

from Lib.log import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from PLUGINS.LLM.CONFIG import LLM_CONFIGS


class LLMAPI(object):
    """
    一个通用的 LLM API 客户端。
    它会自动从 CONFIG.py 读取配置并初始化对应的后端。
    支持通过 tag 动态选择模型配置。
    在遇到错误时，它会直接抛出异常。
    """

    def __init__(self, temperature: float = 0.0):
        """
        初始化 LLM API 客户端。
        从 CONFIG.py 中的 LLM_CONFIGS 加载配置列表。
        """
        if not LLM_CONFIGS or not isinstance(LLM_CONFIGS, list):
            raise ValueError("LLM_CONFIGS in CONFIG.py is missing, empty, or not a list.")

        self.configs = LLM_CONFIGS
        self.default_config = self.configs[0]
        self.temperature = temperature
        self.alive = False

    def get_model(self, tag: str | list[str] | None = None, **kwargs) -> ChatOpenAI | ChatOllama:
        """
        根据 tag 获取并返回相应的 LangChain ChatModel 实例。

        Args:
            tag (str | list[str], optional):
                - str: 查找包含此标签的第一个配置。
                - list[str]: 查找同时包含所有这些标签的第一个配置。
                - None: 使用列表中的第一个默认配置。
            **kwargs: 允许在调用时覆盖模型参数 (e.g., temperature, model).

        Raises:
            ValueError: 如果找不到匹配指定标签(或标签列表)的配置。
            ValueError: 如果配置中的 client_type 不支持。

        Returns:
            ChatOpenAI | ChatOllama: LangChain 的聊天模型实例。
        """
        selected_config = None

        if tag is None:
            selected_config = self.default_config
        else:
            for config in self.configs:
                config_tags = set(config.get("tags", []))

                # 如果 tag 是一个列表，检查所有必需的标签是否存在
                if isinstance(tag, list):
                    required_tags = set(tag)
                    if required_tags.issubset(config_tags):
                        selected_config = config
                        break
                # 如果 tag 是一个字符串，检查该标签是否存在
                elif isinstance(tag, str):
                    if tag in config_tags:
                        selected_config = config
                        break

        if selected_config is None:
            raise ValueError(f"No LLM configuration found matching tag(s): '{tag}'")
        logger.debug(f"Using LLM configuration: {selected_config}")
        # 准备模型参数
        params = {
            "temperature": self.temperature,
            "model": selected_config.get("model"),
        }
        # 更新kwargs，允许在运行时覆盖默认值
        params.update(kwargs)

        client_type = selected_config.get("type")

        if client_type == 'openai':
            params.update({
                "base_url": selected_config.get("base_url"),
                "api_key": selected_config.get("api_key"),
                "http_client": httpx.Client(proxy=selected_config.get("proxy")) if selected_config.get("proxy") else None,
            })
            return ChatOpenAI(**params)

        elif client_type == 'ollama':
            params.update({
                "base_url": selected_config.get("base_url"),
            })
            # Ollama doesn't use api_key or http_client in the same way
            return ChatOllama(**params)
        else:
            raise ValueError(f"Unsupported client_type: {client_type}")

    def is_alive(self) -> bool:
        """
        测试与默认模型的基本连通性。
        成功则返回 True，否则直接抛出异常 (例如: ConnectionError, ValueError)。
        """
        model = self.get_model()  # 使用默认配置
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "When you receive 'ping', you must reply with 'pong'."),
            ("human", "ping"),
        ]

        # 任何网络或API错误都会在这里自然地作为异常抛出
        ai_msg = chain.invoke(messages)

        if "pong" not in ai_msg.lower():
            # 即使连接成功，但响应不符合预期，也视为失败
            self.alive = False
            raise ValueError(f"Model liveness check failed. Expected 'pong', got: {ai_msg}")

        self.alive = True
        return True

    def is_support_function_calling(self, tag: str = None) -> bool:
        """
        测试指定（或默认）模型是否支持函数调用（Tool Calling）能力。
        成功则返回 True，否则直接抛出异常。
        """

        def test_func(x: str) -> str:
            """A test function that returns the input string."""
            return x

        model = self.get_model(tag=tag)
        model_with_tools = model.bind_tools([test_func])
        test_messages = [
            ("system", "When user says test, call test_func with 'hello' as argument."),
            ("human", "test"),
        ]

        response = model_with_tools.invoke(test_messages)

        if not response.tool_calls:
            raise ValueError("Model responded but did not use the requested tool.")

        return True

    @staticmethod
    def extract_think(message: AIMessage) -> AIMessage:
        """
        检查 AIMessage 的 content 开头是否存在 <think>...</think> 标签。
        Langchain Bug的临时解决方案
        如果存在，它会:
        1. 提取 <think> 标签内的内容。
        2. 将提取的内容存入 message.additional_kwargs['reasoning_content']。
        3. 从 message.content 中移除 <think>...</think> 标签块。
        4. 返回一个新的、经过修改的 AIMessage 对象。

        如果不存在，则原样返回原始的 message 对象。

        Args:
            message: 要处理的 LangChain AIMessage 对象。

        Returns:
            一个处理过的 AIMessage 对象，或者在没有匹配项时返回原始对象。
        """
        # 确保 content 是字符串类型
        if not isinstance(message.content, str):
            return message

        # 正则表达式匹配开头的 <think> 标签，并捕获其中的内容。
        # re.DOTALL 标志让 '.' 可以匹配包括换行符在内的任意字符。
        # `^`      - 匹配字符串的开头
        # `<think>`- 匹配字面上的 <think>
        # `(.*?)`  - 非贪婪地捕获所有字符，直到下一个模式
        # `</think>`- 匹配字面上的 </think>
        # `\s*`    - 匹配 think 标签后的任何空白字符（包括换行符）
        pattern = r"^<think>(.*?)</think>\s*"

        match = re.match(pattern, message.content, re.DOTALL)

        if match:
            # 提取捕获组1的内容，即<think>标签内部的文本
            reasoning_content = match.group(1).strip()

            # 从原始 content 中移除整个匹配到的 <think>...</think> 部分
            new_content = message.content[match.end():]

            # 创建 additional_kwargs 的一个副本以进行修改
            # 这样做是为了避免直接修改可能在其他地方被引用的原始字典
            updated_kwargs = message.additional_kwargs.copy()
            updated_kwargs['reasoning_content'] = reasoning_content

            # 返回一个新的 AIMessage 实例，因为 LangChain 的消息对象是不可变的
            message.additional_kwargs = updated_kwargs
            message.content = new_content
            return message
        else:
            # 如果没有匹配项，则返回原始消息
            return message
