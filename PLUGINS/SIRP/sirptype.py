from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Literal, Any, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict


class AccountModel(BaseModel):
    accountId: Optional[str] = Field(default=None, description="用户的唯一标识ID")
    avatar: Optional[str] = Field(default=None, description="用户头像的URL")
    email: Optional[str] = Field(default=None, description="用户的电子邮件地址")
    fullname: Optional[str] = Field(default=None, description="用户的全名")
    jobNumber: Optional[str] = Field(default=None, description="用户的工号")
    mobilePhone: Optional[str] = Field(default=None, description="用户的手机号码")
    status: Optional[int] = Field(default=None, description="用户状态, 例如: 1表示正常")


class AttachmentModel(BaseModel):
    DownloadUrl: Optional[str] = Field(default=None, description="文件的下载地址")
    WaterMarkInfo: Optional[Any] = Field(default=None, description="文件水印信息")
    allow_down: Optional[bool] = Field(default=None, description="是否允许下载")
    allow_edit: Optional[bool] = Field(default=None, description="是否允许编辑")
    allow_view: Optional[bool] = Field(default=None, description="是否允许预览")
    createTime: Optional[Union[datetime, str]] = Field(default=None, description="文件创建时间")
    duration: Optional[float] = Field(default=None, description="音视频文件的时长（秒）")
    file_id: Optional[str] = Field(default=None, description="文件的唯一ID")
    file_name: Optional[str] = Field(default=None, description="文件名")
    file_path: Optional[str] = Field(default=None, description="文件在服务器上的存储路径")
    file_size: Optional[int] = Field(default=None, description="文件大小（字节）")
    file_type: Optional[int] = Field(default=None, description="文件类型的一种数字表示")
    height: Optional[int] = Field(default=None, description="图片或视频的高度（像素）")
    is_delete: Optional[bool] = Field(default=None, description="文件是否已被删除")
    is_knowledge: Optional[bool] = Field(default=None, description="是否为知识库文件")
    large_thumbnail_name: Optional[str] = Field(default=None, description="大缩略图名称")
    large_thumbnail_path: Optional[str] = Field(default=None, description="大缩略图路径")
    node_id: Optional[str] = Field(default="", description="关联的节点ID")
    origin_link_url: Optional[str] = Field(default=None, description="原始链接URL")
    original_file_full_path: Optional[str] = Field(default=None, description="原始文件的完整路径")
    original_file_name: Optional[str] = Field(default=None, description="原始文件名")
    preview_url: Optional[str] = Field(default=None, description="文件的预览地址")
    share_folder_url: Optional[str] = Field(default=None, description="共享文件夹地址")
    short_link_url: Optional[str] = Field(default=None, description="短链接地址")
    thumbnail_name: Optional[str] = Field(default="", description="缩略图名称")
    thumbnail_path: Optional[str] = Field(default="", description="缩略图路径")
    width: Optional[int] = Field(default=None, description="图片或视频的宽度（像素）")


class BaseSystemModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rowid: Optional[str] = Field(default=None, description="数据的唯一行ID")
    ownerid: Optional[AccountModel] = Field(default=None, description="数据的所有者/创建者")
    caid: Optional[AccountModel] = Field(default=None, description="当前处理人/负责人")
    ctime: Optional[Union[datetime, str]] = Field(default=None, description="创建时间")
    utime: Optional[Union[datetime, str]] = Field(default=None, description="最后更新时间")
    uaid: Optional[AccountModel] = Field(default=None, description="最后更新人")

    # 流程相关参数
    wfname: Optional[str] = Field(default=None, description="关联的工作流名称")
    wfcuaids: Optional[Any] = Field(default=None, description="工作流当前处理人列表")
    wfcaid: Optional[Any] = Field(default=None, description="工作流当前激活的处理人")
    wfctime: Optional[Union[datetime, str]] = Field(default=None, description="工作流创建时间")
    wfrtime: Optional[Union[datetime, str]] = Field(default=None, description="工作流接收时间")
    wfcotime: Optional[Union[datetime, str]] = Field(default=None, description="工作流完成时间")
    wfdtime: Optional[Union[datetime, str]] = Field(default=None, description="工作流截止时间")
    wfftime: Optional[Any] = Field(default=None, description="工作流关注时间")
    wfstatus: Optional[Literal["通过", "否决", "中止", "进行中", "", None]] = Field(default=None, description="工作流状态")

    @field_validator(
        "ctime", "utime", "wfctime", "wfrtime", "wfcotime", "wfdtime",
        "created_time", "modified_time", "first_seen_time", "last_seen_time", "acknowledged_time", "closed_time",
        check_fields=False
    )
    @classmethod
    def parse_datetime(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip():
            try:
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return v
        return v


class MessageModel(BaseSystemModel):
    playbook_rowid: str = Field(..., description="所属Playbook的唯一行ID")
    node: Optional[str] = Field(default="", description="消息来源的节点名称或ID")
    content: Optional[str] = Field(default="", description="消息的文本内容")
    json: Optional[str] = Field(default="", description="消息的JSON格式内容，通常用于工具调用和返回")
    type: Optional[Literal["SystemMessage", "HumanMessage", "ToolMessage", "AIMessage", None]] = Field(default=None,
                                                                                                       description="消息类型，用于区分不同角色的发言")


class PlaybookModel(BaseSystemModel):
    source_worksheet: Optional[str] = Field(default="", description="Playbook触发源所在的工作表名称")
    source_rowid: Optional[str] = Field(default="", description="Playbook触发源的行ID，例如具体的告警ID或事件ID")
    job_id: Optional[str] = Field(default="", description="执行Playbook的后台任务ID")
    job_status: Optional[Literal["Pending", "Running", "Success", "Failed", None]] = Field(default=None, description="Playbook执行任务的状态")
    remark: Optional[str] = Field(default="", description="关于Playbook执行的备注信息")
    type: Optional[Literal["CASE", "ALERT", "ARTIFACT", None]] = Field(default=None, description="Playbook关联的对象类型")
    name: Optional[str] = Field(default="", description="执行的Playbook的名称")
    messages: Optional[List[MessageModel]] = Field(default=None, description="Playbook执行过程中的所有消息记录，构成对话历史")
    user_input: Optional[str] = Field(default="", description="用户对Playbook的初始输入或后续指令")
    user: Optional[AccountModel] = Field(default=None, description="发起或与Playbook交互的用户")


class Knowledge(BaseSystemModel):
    title: str = Field(..., description="知识库条目的标题")
    body: Optional[str] = Field(default="", description="知识库条目的正文内容")
    using: Optional[bool] = Field(default=False, description="当前是否正在使用该知识")
    action: Optional[Literal["Store", "Remove", "Done", None]] = Field(default=None, description="对知识库条目执行的动作")
    source: Literal["Manual", "Case"] = Field(..., description="知识的来源，'Manual'表示手动创建，'Case'表示从安全事件中提取")


class EnrichmentModel(BaseSystemModel):
    name: str = Field(..., description="富化信息的名称或标题")
    type: Literal["Other"] = Field(..., description="富化信息的类型")
    provider: Optional[Literal["Other", None]] = Field(default=None, description="富化信息的提供方，例如威胁情报厂商")
    created_time: Optional[Union[datetime, str]] = Field(default=None, description="富化信息创建的时间")
    value: str = Field(..., description="富化信息的具体值")
    src_url: Optional[str] = Field(default="", description="富化信息的来源URL，方便溯源")
    desc: Optional[str] = Field(default="", description="对富化信息的简要描述")
    data: Optional[str] = Field(default="", description="富化信息的详细数据，通常是JSON字符串")


class TicketModel(BaseSystemModel):
    status: Optional[Literal['Unknown', 'New', 'In Progress', 'Notified', 'On Hold', 'Resolved', 'Closed', 'Canceled', 'Reopened', 'Other', None]] = Field(
        default=None, description="外部工单系统中的状态")
    type: Optional[Literal['Other', 'Jira', 'ServiceNow', None]] = Field(default=None, description="外部工单系统的类型")
    title: Optional[str] = Field(default="", description="工单的标题")
    uid: str = Field(..., description="工单在外部系统中的唯一ID")
    src_url: str = Field(..., description="访问该工单的URL")


class ArtifactModel(BaseSystemModel):
    name: Optional[str] = Field(default="", description="实体（Artifact）的名称，通常与值相同或为其描述")
    type: Optional[Literal[
        'Unknown', 'Hostname', 'IP Address', 'MAC Address', 'User Name', 'Email Address', 'URL String', 'File Name', 'Hash', 'Process Name', 'Resource UID', 'Port', 'Subnet', 'Command Line', 'Country', 'Process ID', 'HTTP User-Agent', 'CWE', 'CVE', 'User Credential ID', 'Endpoint', 'User', 'Email', 'Uniform Resource Locator', 'File', 'Process', 'Geo Location', 'Container', 'Registry', 'Fingerprint', 'Group', 'Account', 'Script Content', 'Serial Number', 'Resource', 'Message', 'Advisory', 'File Path', 'Device', 'Other', None]] = Field(
        default=None, description="实体的类型, 例如: IP地址, 主机名, 文件哈希等")
    role: Optional[Literal['Unknown', 'Target', 'Actor', 'Affected', 'Related', 'Other', None]] = Field(default=None,
                                                                                                        description="实体在事件中扮演的角色, 如攻击者(Actor)、受害者(Target)等")
    owner: Optional[str] = Field(default="", description="实体归属的系统或用户")
    value: Optional[str] = Field(default="", description="实体的具体值, 如 '192.168.1.1'")
    reputation_provider: Optional[str] = Field(default="", description="提供信誉评分的威胁情报厂商名称")
    reputation_score: Optional[Literal[
        'Unknown', 'Very Safe', 'Safe', 'Probably Safe', 'Leans Safe', 'May not be Safe', 'Exercise Caution', 'Suspicious/Risky', 'Possibly Malicious', 'Probably Malicious', 'Malicious', 'Other', None]] = Field(
        default=None, description="实体的信誉评分")

    # 关联表
    enrichments: Optional[List[EnrichmentModel]] = Field(default=[], description="针对此实体的一系列富化结果")

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal['TI Enrichment By AlienVaultOTX', 'TI Enrichment By Mock', None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段


class AlertModel(BaseSystemModel):
    severity: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = Field(default=None,
                                                                                                                                 description="告警的严重性，由源安全产品定义")
    title: Optional[str] = Field(default="", description="告警的标题")
    impact: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = Field(default=None, description="告警可能造成的影响范围")
    disposition: Optional[Literal[
        "Unknown", "Allowed", "Blocked", "Quarantined", "Isolated", "Deleted", "Dropped", "Custom Action", "Approved", "Restored", "Exonerated", "Corrected", "Partially Corrected", "Uncorrected", "Delayed", "Detected", "No Action", "Logged", "Tagged", "Alert", "Count", "Reset", "Captcha", "Challenge", "Access Revoked", "Rejected", "Unauthorized", "Error", "Other", None]] = Field(
        default=None, description="安全产品对该活动的处置结果, 如'Blocked', 'Allowed等")
    action: Optional[Literal["Unknown", "Allowed", "Denied", "Observed", "Modified", "Other", None]] = Field(default=None,
                                                                                                             description="检测到的原始行为, 如'Allowed', 'Denied等")
    confidence: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = Field(default=None,
                                                                                             description="告警的置信度，表示该告警为真阳性的可能性")
    uid: Optional[str] = Field(default="", description="告警的唯一标识符")
    labels: Optional[List[str]] = Field(default=[], description="为告警打上的标签")
    desc: Optional[str] = Field(default="", description="对告警的详细描述")

    created_time: Optional[Union[datetime, str]] = Field(default=None, description="告警在SIRP平台中创建的时间")
    modified_time: Optional[Union[datetime, str]] = Field(default=None, description="告警在SIRP平台中最后修改的时间")
    first_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="首次观测到该活动的时间")
    last_seen_time: Optional[Union[datetime, str]] = Field(default=None, description="最后一次观测到该活动的时间")

    rule_id: Optional[str] = Field(default="", description="触发告警的规则ID")
    rule_name: Optional[str] = Field(default="", description="触发告警的规则名称")
    correlation_uid: Optional[str] = Field(default="", description="用于事件关联的唯一ID")
    count: Optional[Union[int, str]] = Field(default=None, description="告警聚合的次数")

    src_url: Optional[str] = Field(default="", description="在源安全产品中查看此告警的URL")
    source_uid: Optional[str] = Field(default="", description="告警在源产品中的唯一ID")
    data_sources: Optional[List[str]] = Field(default=[], description="告警的数据来源，如'EDR', 'Firewall'等")

    analytic: Optional[Any] = Field(default="", description="分析引擎的详细信息")
    analytic_name: Optional[str] = Field(default="", description="分析引擎的名称")
    analytic_type: Optional[Literal[
        "Unknown", "Rule", "Behavioral", "Statistical", "Learning (ML/DL)", "Fingerprinting", "Tagging", "Keyword Match", "Regular Expressions", "Exact Data Match", "Partial Data Match", "Indexed Data Match", "Other", None]] = Field(
        default=None, description="分析引擎的类型, 如'Rule', 'Behavioral'等")
    analytic_state: Optional[Literal["Unknown", "Active", "Suppressed", "Experimental", "Other", None]] = Field(default=None, description="分析规则当前的状态")
    analytic_desc: Optional[str] = Field(default="", description="分析规则的描述")

    tactic: Optional[str] = Field(default="", description="关联的MITRE ATT&CK战术")
    technique: Optional[str] = Field(default="", description="关联的MITRE ATT&CK技术")
    sub_technique: Optional[str] = Field(default="", description="关联的MITRE ATT&CK子技术")
    mitigation: Optional[str] = Field(default="", description="针对该攻击的缓解措施建议")

    product_category: Optional[Literal["DLP", "Email", "OT", "Proxy", "UEBA", "TI", "IAM", "EDR", "NDR", "Cloud", "Other", None]] = Field(default=None,
                                                                                                                                          description="产生告警的安全产品类别")
    product_vender: Optional[str] = Field(default=None, description="安全产品的厂商")
    product_name: Optional[str] = Field(default=None, description="安全产品的名称")
    product_feature: Optional[str] = Field(default=None, description="产生告警的产品具体功能模块")

    policy_name: Optional[str] = Field(default="", description="触发告警的策略名称")
    policy_type: Optional[Literal["Identity Policy", "Resource Policy", "Service Control Policy", None]] = Field(default=None, description="触发告警的策略类型")
    policy_desc: Optional[str] = Field(default="", description="触发告警的策略描述")

    risk_level: Optional[Literal["Info", "Low", "Medium", "High", "Critical", "Other", None]] = Field(default=None, description="评估的风险等级")
    risk_details: Optional[str] = Field(default="", description="风险详情说明")

    status: Optional[Literal["Unknown", "New", "In Progress", "Suppressed", "Resolved", "Archived", "Deleted", "Other", None]] = Field(default=None,
                                                                                                                                       description="告警的处理状态")
    status_detail: Optional[str] = Field(default="", description="状态的详细说明，例如抑制原因")
    remediation: Optional[str] = Field(default="", description="修复建议或记录")

    comment: Optional[str] = Field(default="", description="分析师对告警的评论")

    unmapped: Optional[str] = Field(default="", description="未被映射到标准字段的原始数据")

    raw_data: Optional[str] = Field(default="", description="原始告警日志，通常为JSON格式的字符串")

    summary_ai: Optional[str] = Field(default="", description="AI提供的汇总摘要")

    # 关联表
    case: Optional[CaseModel] = Field(default=None, description="此告警关联到的安全事件（Case）")
    attachments: Optional[AttachmentModel] = Field(default=[], description="告警的附件")
    artifacts: Optional[List[ArtifactModel]] = Field(default=[], description="从告警中提取出的实体（Artifact）列表")
    enrichments: Optional[List[EnrichmentModel]] = Field(default=[], description="对整个告警进行的富化结果")

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal["Alert Analysis Agent", None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段


class CaseModel(BaseSystemModel):
    title: str = Field(..., description="安全事件的标题, 应能简明扼要地概括事件的核心内容")
    severity: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = Field(default=None,
                                                                                                                                 description="由分析师评估或重新定义的事件严重性")
    impact: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = Field(default=None, description="由分析师评估的事件实际影响")
    priority: Optional[Literal["Unknown", "Low", "Medium", "High", "Critical", "Other", None]] = Field(default=None, description="事件的处置优先级")
    src_url: Optional[str] = Field(default="", description="在源系统中查看此事件的URL")
    confidence: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = Field(default=None, description="由分析师评估的事件置信度")
    description: Optional[str] = Field(default="", description="对安全事件的详细描述")

    category: Optional[Literal["DLP", "Email", "OT", "Proxy", "UEBA", "TI", "IAM", "EDR", "NDR", "Cloud", "Other", None]] = Field(default=None,
                                                                                                                                  description="安全事件的分类，通常与主要告警源的产品类别一致")
    tags: Optional[List[str]] = Field(default=[], description="为事件打上的一系列标签")
    created_time: Optional[Union[datetime, str]] = Field(default=None, description="事件在SIRP中创建的时间")

    status: Optional[Literal["Unknown", "New", "In Progress", "On Hold", "Resolved", "Closed", "Other", None]] = Field(default=None,
                                                                                                                       description="安全事件的处理状态")
    assignee_l1: Optional[AccountModel] = Field(default=None, description="分配给L1一线分析师")
    acknowledged_time: Optional[Union[datetime, str]] = Field(default=None, description="L1分析师首次确认接收事件的时间")
    comment: Optional[str] = Field(default="", description="分析师对整个事件的评论或处置记录")

    assignee_l2: Optional[AccountModel] = Field(default=None, description="分配或升级给L2二线分析师")
    assignee_l3: Optional[AccountModel] = Field(default=None, description="分配或升级给L3专家分析师")
    closed_time: Optional[Union[datetime, str]] = Field(default=None, description="事件关闭的时间")
    verdict: Optional[Literal[
        "Unknown", "False Positive", "True Positive", "Disregard", "Suspicious", "Benign", "Test", "Insufficient Data", "Security Risk", "Managed Externally", "Duplicate", "Other", None]] = Field(
        default=None, description="对事件的最终裁定结论")
    summary: Optional[str] = Field(default="", description="事件关闭时生成的最终摘要总结")

    correlation_uid: Optional[str] = Field(default="", description="用于关联其他事件或数据的唯一ID")

    workbook: Optional[str] = Field(default="", description="事件调查使用的工作簿或调查手册内容")

    # ai 字段
    analysis_rationale_ai: Optional[str] = Field(default="", description="AI对事件的分析基本原理和逻辑")
    recommended_actions_ai: Optional[str] = Field(default="", description="AI推荐的下一步操作或修复建议")
    attack_stage_ai: Optional[str] = Field(default="", description="AI评估的攻击阶段")
    severity_ai: Optional[Literal["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other", None]] = Field(default=None,
                                                                                                                                    description="AI评估的事件严重性")
    confidence_ai: Optional[Literal["Unknown", "Low", "Medium", "High", "Other", None]] = Field(default=None, description="AI评估的事件置信度")

    threat_hunting_report_ai: Optional[str] = Field(default="", description="AI生成的与此事件相关的威胁狩猎报告")

    # 公式计算字段
    start_time: Optional[Any] = Field(default=None, description="事件开始时间(通常是关联告警的最早first_seen_time), 用于计算MTTD")
    end_time: Optional[Any] = Field(default=None, description="事件结束时间(通常是closed_time), 用于计算MTTR")
    detect_time: Optional[Any] = Field(default=None, description="事件检测时间(通常是关联告警的最早created_time), 用于计算MTTD")
    acknowledge_time: Optional[Any] = Field(default=None, description="事件响应时间(acknowledged_time), 用于计算MTTA")
    respond_time: Optional[Any] = Field(default=None, description="事件处置完成时间(closed_time), 用于计算MTTR")

    # 关联表
    attachments: Optional[List[AttachmentModel]] = Field(default=[], description="与事件相关的附件列表")
    tickets: Optional[List[TicketModel]] = Field(default=[], description="与此事件关联的外部工单列表")
    enrichments: Optional[List[EnrichmentModel]] = Field(default=[], description="对整个事件进行的富化结果")
    alerts: Optional[List[AlertModel]] = Field(default=[], description="合并到此事件中的告警列表")

    # playbooks: Optional[Any] = "" # 内部字段
    # playbook: Optional[Literal["Threat Hunting Agent", "L3 SOC Analyst Agent", "L3 SOC Analyst Agent With Tools", None]] = None # 内部字段
    # user_input: Optional[str] = "" # 内部字段
