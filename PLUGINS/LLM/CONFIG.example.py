# 插件文档地址: https://asp.viperrtp.com/zh/asf/PLUGINS/LLM/
# get_model(tag="xxx") 会按顺序查找并使用第一个包含 "xxx" 标签的配置。tag可以自由定制.
# 如果不提供 tag，则默认使用列表中的第一个配置。
# ASF中正在使用的tag  "cheap","fast","powerful","function_calling","structured_output"

# Doc: https://asp.viperrtp.com/asf/PLUGINS/LLM/
# `get_model(tag="xxx")` will search for and use the first configuration containing the tag "xxx" in order. The tag can be customized.
# If no tag is provided, the first configuration in the list will be used by default.
# Tags currently used in ASF: "cheap", "fast", "powerful", "function_calling", "structured_output"

LLM_CONFIGS = [
    {
        "type": "ollama",
        "api_key": "ollama",  # 对于 ollama，api_key 通常是 'ollama'
        "base_url": "http://192.168.241.128:8080/v1",
        "model": "qwen2:7b-instruct-q8_0",
        "proxy": None,
        "tags": ["cheap", "fast"]
    },
    {
        "type": "openai",
        "api_key": "sk-XXXXXXXXXXXXXX",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen3-max",
        "proxy": None,
        "tags": ["powerful", "function_calling", "structured_output"]
    },
    {
        "type": "openai",
        "api_key": 'AIXXXX',
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.5-flash",
        "proxy": "http://127.0.0.1:7890",  # "http://192.168.1.100:3128", # 示例代理
        "tags": ["fast", "function_calling", "structured_output"]
    },
    {
        "type": "openai",
        "api_key": 'AIXXXX',
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.5-pro",
        "proxy": "http://127.0.0.1:7890",  # "http://192.168.1.100:3128", # 示例代理
        "tags": ["powerful", "function_calling", "structured_output"]
    },
    {
        "type": "openai",
        "api_key": 'sk-XXXXXXXXXXXXXX',
        "base_url": "https://api.moonshot.cn/v1",
        "model": "kimi-k2-0905-preview",
        "proxy": None,
        "tags": ["fast", "cheap", "function_calling", "structured_output"]
    }
]
