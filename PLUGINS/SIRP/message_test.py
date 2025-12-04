import json
from typing import List, Dict, Any

from PLUGINS.SIRP.sirpapi import PlaybookMessage

# 尝试导入 langchain_core，如果未安装则报错提示
try:
    from langchain_core.messages import (
        BaseMessage,
        SystemMessage,
        HumanMessage,
        AIMessage,
        ToolMessage
    )
except ImportError:
    raise ImportError("请先安装 langchain-core: pip install langchain-core")


def parse_langchain_messages(msg: BaseMessage, playbook_rowid=None, node=None) -> List[Dict[str, Any]]:
    """
    将 LangChain 的消息对象列表解析为纯字典列表 (List[Dict])。
    涵盖 System, Human, AI (含 tool_calls), ToolMessage。
    """

    # 1. 处理 SystemMessage
    if isinstance(msg, SystemMessage):

        fields = [
            {"id": "type", "value": "SystemMessage"},
            {"id": "node", "value": node},
            {"id": "playbook_rowid", "value": playbook_rowid},
            {"id": "content", "value": msg.content},
            {"id": "json", "value": None},
        ]


    # 2. 处理 HumanMessage
    elif isinstance(msg, HumanMessage):

        fields = [
            {"id": "type", "value": "HumanMessage"},
            {"id": "node", "value": node},
            {"id": "playbook_rowid", "value": playbook_rowid},
            {"id": "content", "value": msg.content},
            {"id": "json", "value": None},
        ]


    # 3. 处理 AIMessage (包含普通回复和工具调用)
    elif isinstance(msg, AIMessage):
        # 检查是否有 tool_calls
        if hasattr(msg, 'tool_calls') and msg.tool_calls:
            fields = [
                {"id": "type", "value": "AIMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": msg.content},
                {"id": "json", "value": json.dumps(msg.tool_calls)},
            ]
        else:
            fields = [
                {"id": "type", "value": "AIMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": msg.content},
                {"id": "json", "value": None},
            ]
    # 4. 处理 ToolMessage (工具执行的结果)
    elif isinstance(msg, ToolMessage):

        try:
            json_data = {"name": msg.name, "tool_call_id": msg.tool_call_id, "result": json.loads(msg.content)}
        except json.decoder.JSONDecodeError:
            json_data = {"name": msg.name, "tool_call_id": msg.tool_call_id, "result": msg.content}

        fields = [
            {"id": "type", "value": "ToolMessage"},
            {"id": "node", "value": node},
            {"id": "playbook_rowid", "value": playbook_rowid},
            {"id": "json", "value": json.dumps(json_data)},
        ]
    # 5. 处理其他未知类型 (兜底)
    else:
        message_dict = {
            "role": "unknown",
            "content": msg.content,
            "type": msg.type
        }
        fields = [
            {"id": "role", "value": msg.type},
            {"id": "node", "value": node},
            {"id": "playbook_rowid", "value": playbook_rowid},
            {"id": "content", "value": msg.content},
            {"id": "json", "value": None},
        ]
    row_id = PlaybookMessage.create(fields)
    return row_id


# ==========================================
# 测试代码部分
# ==========================================
if __name__ == "__main__":
    print("-" * 30)
    print("开始测试 LangChain Message 解析")
    print("-" * 30)

    # 1. 模拟构建 LangChain 的消息列表
    # 场景：用户问天气 -> AI 决定调用工具 -> 工具返回结果 -> AI 总结

    # 模拟 tool_call 数据
    dummy_tool_call_id = "call_12345xyz"

    test_messages = [
        # System Message
        SystemMessage(content="你是一个有用的AI助手。"),

        # Human Message
        HumanMessage(content="东京现在的天气怎么样？"),

        # AI Message (决定调用工具)
        AIMessage(
            content="",  # 思维链内容可能为空
            tool_calls=[{
                "name": "get_current_weather",
                "args": {"location": "Tokyo", "unit": "celsius"},
                "id": dummy_tool_call_id
            }]
        ),

        # Tool Message (工具返回的结果)
        ToolMessage(
            content=json.dumps({"temperature": 22, "description": "Sunny"}),
            tool_call_id=dummy_tool_call_id,
            name="get_current_weather"
        ),

        # AI Message (最终回复)
        AIMessage(content="东京现在天气晴朗，气温约为 22 摄氏度。")
    ]

    # 2. 执行解析
    try:
        for msg in test_messages:
            results = parse_langchain_messages(msg)
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
