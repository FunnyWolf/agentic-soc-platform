import httpx
import urllib3
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from Lib.log import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from PLUGINS.LLM.CONFIG import LLM_CONFIGS


class LLMAPI(object):
    """
    A general-purpose LLM API client.
    It automatically reads the configuration from CONFIG.py and initializes the corresponding backend.
    Supports dynamic selection of model configurations through tags.
    It throws exceptions directly when it encounters an error.
    """

    def __init__(self, temperature: float = 0.0):
        """
        Initializes the LLM API client.
        Loads the configuration list from LLM_CONFIGS in CONFIG.py.
        """
        if not LLM_CONFIGS or not isinstance(LLM_CONFIGS, list):
            raise ValueError("LLM_CONFIGS in CONFIG.py is missing, empty, or not a list.")

        self.configs = LLM_CONFIGS
        self.temperature = temperature
        self.alive = False

    def get_model(self, tag: str | list[str] | None = None, **kwargs) -> ChatOpenAI:
        """
        Gets and returns the corresponding LangChain ChatModel instance based on the tag.

        Args:
            tag (str | list[str], optional):
                - str: Find the first configuration that contains this tag.
                - list[str]: Find the first configuration that contains all of these tags.
                - None: Use the first default configuration in the list.
            **kwargs: Allows overriding model parameters at call time (e.g., temperature, model).

        Raises:
            ValueError: If no configuration matching the specified tag (or list of tags) is found.
            ValueError: If the client_type in the configuration is not supported.

        Returns:
            ChatOpenAI : LangChain's chat model instance.
        """
        selected_config = None

        if tag is None:
            selected_config = self.configs[0]
        else:
            for config in self.configs:
                config_tags = set(config.get("tags", []))

                # If tag is a list, check if all required tags exist
                if isinstance(tag, list):
                    required_tags = set(tag)
                    if required_tags.issubset(config_tags):
                        selected_config = config
                        break
                # If tag is a string, check if the tag exists
                elif isinstance(tag, str):
                    if tag in config_tags:
                        selected_config = config
                        break

        if selected_config is None:
            raise ValueError(f"No LLM configuration found matching tag(s): '{tag}'")

        logger.debug(f"Using LLM configuration, base_url: {selected_config.get("base_url")} model: {selected_config.get("model")}")
        # Prepare model parameters
        params = {
            "temperature": self.temperature,
            "model": selected_config.get("model"),
        }
        # Update kwargs to allow overriding default values at runtime
        params.update(kwargs)
        params.update({
            "base_url": selected_config.get("base_url"),
            "api_key": selected_config.get("api_key"),
            "http_client": httpx.Client(proxy=selected_config.get("proxy")) if selected_config.get("proxy") else None,
        })
        return ChatOpenAI(**params)

    def alive_check(self):
        for config in self.configs:
            params = {
                "temperature": self.temperature,
                "model": config.get("model"),
            }
            params.update({
                "base_url": config.get("base_url"),
                "api_key": config.get("api_key"),
                "http_client": httpx.Client(proxy=config.get("proxy")) if config.get("proxy") else None,
            })
            model = ChatOpenAI(**params)
            if self.is_alive(model):
                print(f"{config} is alive.")
            else:
                print(f"{config} is not alive.")

    def is_alive(self, model: ChatOpenAI) -> bool:
        """
        Tests basic connectivity with the default model.
        Returns True on success, otherwise throws an exception directly (e.g., ConnectionError, ValueError).
        """
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "When you receive 'ping', you must reply with 'pong'."),
            ("human", "ping"),
        ]

        # Any network or API errors will be thrown here naturally as exceptions
        ai_msg = chain.invoke(messages)

        if "pong" not in ai_msg.lower():
            # Even if the connection is successful, but the response does not meet expectations, it is considered a failure
            self.alive = False
            raise ValueError(f"Model liveness check failed. Expected 'pong', got: {ai_msg}")

        self.alive = True
        return True

    def is_support_function_calling(self, tag: str = None) -> bool:
        """
        Tests whether the specified (or default) model supports function calling (Tool Calling) capabilities.
        Returns True on success, otherwise throws an exception directly.
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
