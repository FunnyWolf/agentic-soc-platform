from __future__ import annotations

from enum import StrEnum
from typing import Optional, List

from pydantic import Field

from PLUGINS.SIRP.sirpbasemodel import BaseSystemModel, AutoAccount, AutoDatetime, AI_PROFILE_MCP


class MessageType(StrEnum):
    SYSTEM = "SystemMessage"
    HUMAN = "HumanMessage"
    TOOL = "ToolMessage"
    AI = "AIMessage"


class KnowledgeSource(StrEnum):
    MANUAL = "Manual"
    CASE = "Case"


class PlaybookJobStatus(StrEnum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    PENDING = 'Pending'
    RUNNING = 'Running'


class PlaybookModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. playbook_000001 (记录 ID e.g. playbook_000001)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})
    source_row_id: Optional[str] = Field(default="", description="Trigger source row ID (触发源行 ID)",
                                         json_schema_extra={"ai": [AI_PROFILE_MCP]})
    case_id: Optional[str] = Field(default="",
                                   description="Trigger source record ID e.g. case_000001(触发源记录 ID e.g. case_0000001)",
                                   json_schema_extra={"ai": [AI_PROFILE_MCP]})
    name: Optional[str] = Field(default="", description="Executed playbook name (执行剧本名称)",
                                json_schema_extra={"ai": [AI_PROFILE_MCP]})
    user_input: Optional[str] = Field(default="", description="Initial or follow-up user input (初始或后续用户输入)",
                                      json_schema_extra={"ai": [AI_PROFILE_MCP]})
    user: Optional[AutoAccount] = Field(default=None, description="Playbook requester (剧本请求者)")

    job_status: Optional[PlaybookJobStatus] = Field(default=None, description="Background job status (后台任务状态)",
                                                    json_schema_extra={"ai": [AI_PROFILE_MCP]})
    job_id: Optional[str] = Field(default="", description="Background job ID (后台任务 ID)",
                                  json_schema_extra={"ai": [AI_PROFILE_MCP]})
    remark: Optional[str] = Field(default="", description="Execution remark (执行备注)",
                                  json_schema_extra={"ai": [AI_PROFILE_MCP]})


class KnowledgeModel(BaseSystemModel):
    id: Optional[str] = Field(default=None, init=False, description="Record ID e.g. knowledge_000001 (记录 ID e.g. knowledge_000001)",
                              json_schema_extra={"ai": [AI_PROFILE_MCP]})
    title: Optional[str] = Field(default="", description="Knowledge title (知识标题)",
                                 json_schema_extra={"ai": [AI_PROFILE_MCP]})
    body: Optional[str] = Field(default="", description="Knowledge content (知识内容)",
                                json_schema_extra={"ai": [AI_PROFILE_MCP]})
    expires_at: Optional[AutoDatetime] = Field(default=None,
                                               description="Knowledge expiration time; empty means permanently valid (知识过期时间，空表示永久有效)",
                                               json_schema_extra={"ai": [AI_PROFILE_MCP]})
    source: Optional[KnowledgeSource] = Field(default=None, description="Knowledge source (知识来源)",
                                              json_schema_extra={"ai": [AI_PROFILE_MCP]})
    tags: Optional[List[str]] = Field(default=[], description="Knowledge tags (知识标签)",
                                      json_schema_extra={"type": 2, "ai": [AI_PROFILE_MCP]})
