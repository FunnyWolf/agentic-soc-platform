# 插件文档地址: https://asp.viperrtp.com/zh/asf/PLUGINS/LLM/
# get_model(tag="xxx") 会按顺序查找并使用第一个包含 "xxx" 标签的配置.
# get_model(tag=["xxx","yyy"]) 会按顺序查找同时包含 "xxx" 和 "yyy" 标签的配置.
# tag可以自由定制.如果不提供 tag,则默认使用列表中的第一个配置.
# ASF中正在使用的tag "cheap","fast","powerful","function_calling","structured_output"

# Doc: https://asp.viperrtp.com/asf/PLUGINS/LLM/
# `get_model(tag="xxx")` will search for and use the first configuration containing the tag "xxx" in order.
# `get_model(tag=["xxx","yyy"])` will search for configurations that contain both "xxx" and "yyy" tags in order.
# The tag can be customized.If no tag is provided, the first configuration in the list will be used by default.
# Tags currently used in ASP: "cheap", "fast", "powerful", "function_calling", "structured_output"

LLM_CONFIGS = [
    {
        "api_key": 'ollama',
        "base_url": "http://10.10.10.10:11434/v1",
        "model": "qwen3.5:9b",
        "proxy": None,
        "tags": ["fast", "cheap", "function_calling", "structured_output"]
    },
    {
        "api_key": "sk-XXXXXXXXXXXXXX",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen3-max",
        "proxy": None,
        "tags": ["powerful", "function_calling", "structured_output"]
    },
    {
        "api_key": 'AIXXXX',
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.5-flash",
        # 支持代理格式
        # Support Proxy format
        # HTTP: http://192.168.1.100:3128
        # HTTP with username / password: http://user:pass@192.168.1.100:3128
        # SOCKS5: socks5://192.168.1.100:1080
        # SOCKS5 with username / password: socks5://user:pass@192.168.1.100:1080
        "proxy": "http://127.0.0.1:7890",
        "tags": ["fast", "function_calling", "structured_output"]
    },
    {
        "api_key": 'AIXXXX',
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.5-pro",
        "proxy": "http://127.0.0.1:7890",
        "tags": ["powerful", "function_calling", "structured_output"]
    },
    {
        "api_key": 'sk-XXXXXXXXXXXXXX',
        "base_url": "https://api.moonshot.cn/v1",
        "model": "kimi-k2-0905-preview",
        "proxy": None,
        "tags": ["fast", "cheap", "function_calling", "structured_output"]
    }
]
