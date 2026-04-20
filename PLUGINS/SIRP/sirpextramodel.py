from __future__ import annotations

from enum import StrEnum
from typing import Optional, List, Union

from pydantic import Field

from PLUGINS.SIRP.sirpbasemodel import BaseSystemModel, AutoAccount


class MessageType(StrEnum):
    SYSTEM = "SystemMessage"
    HUMAN = "HumanMessage"
    TOOL = "ToolMessage"
    AI = "AIMessage"


class PlaybookType(StrEnum):
    CASE = "CASE"
    ALERT = "ALERT"
    ARTIFACT = "ARTIFACT"


class KnowledgeSource(StrEnum):
    MANUAL = "Manual"
    CASE = "Case"


class PlaybookJobStatus(StrEnum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    PENDING = 'Pending'
    RUNNING = 'Running'


class KnowledgeAction(StrEnum):
    STORE = 'Store'
    REMOVE = 'Remove'
    DONE = 'Done'


class MessageModel(BaseSystemModel):
    playbook: Optional[List[Union[PlaybookModel, str]]] = Field(default="", description="Owning playbook row ID (所属剧本行 ID)")
    node: Optional[str] = Field(default="", description="Source node name or ID (源节点名称或 ID)")
    content: Optional[str] = Field(default="", description="Message text content (消息文本内容)")
    data: Optional[str] = Field(default="", description="Message JSON payload (消息 JSON 负载)")
    type: Optional[MessageType] = Field(default=None, description="Message role type (消息角色类型)")


class PlaybookModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, description="Record ID e.g. playbook_000001 (记录 ID e.g. playbook_000001)")
    source_row_id: Optional[str] = Field(default="", description="Trigger source row ID (触发源行 ID)")
    source_id: Optional[str] = Field(default="",
                                     description="Trigger source record ID e.g. case_00000_1,alert_000001,artifact_000001 (触发源记录 ID e.g. case_00000_1,alert_000001,artifact_000001)")
    type: Optional[PlaybookType] = Field(default=None, description="Linked object type (关联对象类型)")
    name: Optional[str] = Field(default="", description="Executed playbook name (执行剧本名称)")
    user_input: Optional[str] = Field(default="", description="Initial or follow-up user input (初始或后续用户输入)")
    user: Optional[AutoAccount] = Field(default=None, description="Playbook requester (剧本请求者)")

    job_status: Optional[PlaybookJobStatus] = Field(default=None, description="Background job status (后台任务状态)")
    job_id: Optional[str] = Field(default="", description="Background job ID (后台任务 ID)")
    remark: Optional[str] = Field(default="", description="Execution remark (执行备注)")

    # 关联表
    messages: Optional[List[Union[MessageModel, str]]] = Field(default=None, description="Execution message history (执行消息历史)")


class KnowledgeModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, description="Record ID e.g. knowledge_000001 (记录 ID e.g. knowledge_000001)")
    title: Optional[str] = Field(default="", description="Knowledge title (知识标题)")
    body: Optional[str] = Field(default="", description="Knowledge content (知识内容)")
    using: Optional[bool] = Field(default=False, description="Currently in use (当前正在使用)")
    action: Optional[KnowledgeAction] = Field(default=None, description="Knowledge action (知识操作)")
    source: Optional[KnowledgeSource] = Field(default=None, description="Knowledge source (知识来源)")
    tags: Optional[List[str]] = Field(default=[], description="Knowledge tags (知识标签)", json_schema_extra={"type": 2})
