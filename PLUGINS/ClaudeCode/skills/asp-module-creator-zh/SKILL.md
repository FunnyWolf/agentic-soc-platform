---
name: asp-module-creator-zh
description: '创建 ASP 告警处理模块。当用户想为某个 SIEM rule 创建 ASP module、编写告警处理脚本、新建 MODULES 目录下的 Python 模块时使用。'
argument-hint: '<rule-name>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ module, siem, alert-processing, development ]
  documentation: https://asp.viperrtp.com/
---

# ASP Module Creator

当用户需要为某个 SIEM rule 创建 ASP 告警处理模块时，使用这个 skill 引导完成从需求确认到代码生成的完整流程。

## 适用场景

- 用户想为某个 SIEM rule 创建对应的 ASP 处理模块。
- 用户想在 `MODULES/` 目录下新建一个 Python 告警处理脚本。
- 用户想把某个 SIEM 告警接入 ASP 的 Alert/Case 管理流程。

## 运行规则

- 模块文件名必须与 SIEM rule 名称完全一致（含大小写）——Rule 名 = Redis Stream 名 = 文件名，三者强约束，任意一处不一致框架将无法路由告警。
- 编写代码前必须先获取 raw_alert 样本，不得凭空猜测字段结构。
- 编写代码前必须读取 `PLUGINS/SIRP/sirpcoremodel.py`，所有 enum 值只能使用该文件中实际定义的值，不得凭记忆或推断自行发明。
- 所有模块必须继承 `BaseModule` 并实现 `run()` 方法。
- SIRP 数据层级：`Case → Alert → Artifact`（三级体系）。Artifact 是调查的最小原子实体（一个 IP、一个用户名），应尽量从 raw_alert
  中提取；Alert 挂在 Case 下；同类告警通过 `correlation_uid` 聚合到同一个 Case。Enrichment 是独立于三级体系之外的横切附加层，可按需挂载到
  Case / Alert / Artifact 任意一级。
- 参考实现：`MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py`，体现当前推荐的 raw_alert 消费、Artifact 提取、Alert/Case 组装、Case 去重追加和分析调度调用方式。
- 数据模型参考：`PLUGINS/SIRP/sirpcoremodel.py`。

## 决策流程

1. 如果用户未提供 rule 名称，先询问。
2. 如果 raw_alert 样本未获取，按优先级尝试三种方式获取（见 SOP Step 3）。
3. 获取样本后分析字段结构，再编写代码。
4. 代码生成后提示用户添加调试入口并验证。

## SOP

### Step 1 — 获取 Rule 名称

要求用户提供 SIEM Rule 的完整名称，例如 `XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3`。

- 模块文件将命名为 `MODULES/XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3.py`。
- 告警将从同名 Redis Stream `XXX-01-YYY-ZZZ1-ZZZ2-ZZZ3` 中读取。

### Step 2 — 确认前置条件

提示用户确认以下三项均已就绪：

1. SIEM 中已存在名为 `<rule-name>` 的 rule。
2. 该 rule 已产生告警。
3. 告警已通过转发工具写入 Redis Stream `<rule-name>`。

### Step 3 — 获取 raw_alert 样本

按以下优先级尝试，任意一种成功即可继续：

**方式 A（推荐，需已连接 ASP MCP）：**
调用 `ASP:read_stream_head(stream_name="<rule-name>")` 读取 stream 头部若干条告警。
或调用 `ASP:read_stream_message_by_id(stream_name="<rule-name>", message_id=<id>)` 读取指定消息。

**方式 B（离线开发）：**
要求用户将一条或多条 raw_alert JSON 拷贝到 `DATA/MODULES/<rule-name>/raw_alert_*.json`，然后读取该文件。

**方式 C（直接粘贴）：**
要求用户从 Redis Insight 中选择 `<rule-name>` stream，复制一条消息的 JSON 内容并粘贴到对话中。

### Step 4 — 分析 raw_alert 结构

阅读样本，识别并记录：

- 事件时间字段（如 `@timestamp`、`eventTime`）
- 主体身份字段（用户名、ARN、账号 ID、AccessKey 等）
- 目标字段（目标用户、目标资源等）
- 网络字段（源 IP、User-Agent 等）
- 结果字段（errorCode、outcome、status 等）
- 风险评分字段（如 `event.risk_score`、`log.level`）
- 其他有价值的字段

确定 `correlation_uid` 前，必须先判断该 rule 描述的是哪类 SOC 场景。不同告警的聚合逻辑不同，不得机械套用固定字段或固定时间窗口。

**聚合设计目标：**

- 一个 Case 应代表一次可调查、可处置的安全事件或攻击活动，而不是一条日志，也不是一个过宽泛的资产桶。
- 聚合键应优先选择"攻击活动不变项"，避免选择会随受害者、会话、请求、时间戳随机变化的字段。
- 聚合窗口应匹配响应节奏：窗口太短会拆散同一活动并重复通知；窗口太长会延迟新一轮攻击的响应。

**选择聚合键时按以下顺序思考：**

1. 攻击者维度：源 IP、发件人、外部账号、恶意域名、恶意文件 hash、C2 域名等。
2. 目标/受害者维度：目标用户、目标主机、目标资源。只有当"同一攻击者对同一目标"才构成同一事件时才加入。
3. 行为/载荷维度：邮件主题、URL 域名、文件 hash、命令行特征、API 名称、规则子类型等。只有字段稳定且能区分活动时才加入。
4. 环境维度：云账号、租户、业务系统、地域等。通常只作为辅助键，不应单独作为聚合键。

**避免作为聚合键的字段：**

- 随机或高基数字段：message_id、request_id、session_id、trace_id、uuid、精确时间戳。
- 受害者字段：当场景是"同一攻击者大范围投递/扫描/爆破"时，不要把每个 recipient/user/host 都放入 key，否则会产生大量碎片
  Case。
- 过宽字段：只用 account_id、tenant_id、rule_name 会把无关告警混到一起。

**常见场景参考：**

- 用户上报钓鱼邮件：优先用发件人/发件域；如果邮件标题没有收件人姓名、时间戳、订单号等随机值，可加入归一化标题；通常不要加入收件人。建议窗口
  `12h`，避免同一波钓鱼邮件被拆成多个 Case，同时避免过长窗口导致通知和响应不及时。
- 同一恶意 URL/域名投递：用 URL 域名或归一化 URL + 发件域；如果 URL 中包含一次性 token，应只取域名或稳定路径。
- 主机恶意进程/命令：用主机 + 进程名/命令行稳定特征；如果判断为横向传播或同一 hash 大范围爆发，可用文件 hash/命令特征，不一定加入主机。
- 云 IAM 异常操作：通常用云账号/租户 + 主体身份 + API/目标资源；如果关注一次大范围攻击，可按主体身份或源 IP
  聚合，再用目标资源作为辅助信息。例如 `AttachUserPolicy` 这类高危权限变更，如果 Case 表示"同一主体对同一目标用户的高危授权活动"，可使用
  `account_id + principal_user/principal_id + target_user`；不要加入 `policyArn`、`requestID`、`eventID` 这类会拆散同一活动或缺乏聚合价值的字段。
- C2 通信：用目标 C2 IP/域名 + 内部主机；如果同一 C2 影响多台主机，允许按 C2 先聚合，再在 Case 中保留受影响主机列表。

**时间窗口参考：**

- 用户上报/通知类：`6h`-`12h`，常用 `12h`。
- 高频扫描、爆破、C2 beacon：`15m`-`2h`，按检测频率和响应需求调整。
- 云权限变更、账号异常、低频高危操作：`4h`-`24h`。
- 使用窗口时必须在生成代码后的说明中写明选择理由。

如果无法判断聚合键，应先基于 raw_alert 和告警语义提出候选方案，并向用户确认。不要在不说明理由的情况下默认使用 `24h`
或默认加入所有主体/目标字段。

### Step 5 — 编写模块代码

**前置动作：** 读取 `PLUGINS/SIRP/sirpcoremodel.py`，确认所有需要用到的 enum 的合法值，再开始写代码。

按以下结构生成 `MODULES/<rule-name>.py`：

```python
import json
from typing import List

from dateutil import parser

from Lib.basemodule import BaseModule
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpcoremodel import (
    ArtifactType, ArtifactRole, Severity, Impact, Disposition, AlertAction,
    Confidence, AlertAnalyticType, ProductCategory, AlertPolicyType,
    AlertRiskLevel, AlertStatus, CasePriority,
    ArtifactModel, AlertModel, CaseModel, EnrichmentModel
)


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        # 1. 读取原始告警
        raw_alert = self.read_stream_message()

        # 2. 字段提取（根据 raw_alert 结构定制）
        # ...

        # 3. Artifact 提取
        artifacts: List[ArtifactModel] = []
        # artifacts.append(ArtifactModel(type=..., role=..., value=..., name=...))

        # 4. 计算 correlation_uid
        # 根据告警语义选择聚合键和时间窗口，不要机械使用固定字段。
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window=...,  # 例如用户上报钓鱼邮件可使用 "12h"
            keys=[...],  # 选择稳定的攻击活动不变项，避免 request_id/session_id 等随机字段
            timestamp=event_time_formatted
        )

        # 5. 组装 AlertModel
        alert_model = AlertModel(
            title=...,
            severity=...,
            status=AlertStatus.NEW,
            disposition=...,
            action=...,
            rule_id=self.module_name,
            rule_name=...,
            correlation_uid=correlation_uid,
            raw_data=json.dumps(raw_alert),
            unmapped=json.dumps({...}),
            # 其他字段...
        )
        alert_model.artifacts = artifacts if artifacts else None

        # 6. 创建告警
        saved_alert_row_id = Alert.create(alert_model)
        self.logger.info(f"Alert created: {saved_alert_row_id}")

        # 7. Case 处理
        existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
        if existing_case:
            existing_case_row_id = existing_case.row_id
            assert existing_case_row_id is not None
            existing_alerts = existing_case.alerts or []
            updated_alerts = existing_alerts if saved_alert_row_id in existing_alerts else [*existing_alerts, saved_alert_row_id]
            update_case = CaseModel(
                alerts=updated_alerts,
                row_id=existing_case_row_id
            )
            Case.update(update_case)
            Case.mark_analysis_requested(row_id=existing_case_row_id, cooldown_minutes=3)
        else:
            new_case = CaseModel(
                title=...,
                severity=...,
                impact=...,
                priority=...,
                confidence=Confidence.HIGH,
                description=...,
                correlation_uid=correlation_uid,
                alerts=[saved_alert_row_id]
            )
            created_case_row_id = Case.create(new_case)
            Case.mark_analysis_requested(row_id=created_case_row_id, cooldown_minutes=3)

        return True
```

框架行为说明：

- 框架会持续循环实例化 Module 类并调用 `run()`，每次调用只处理一条告警——模块应设计为无状态的，不要在实例变量中积累跨告警的状态。

字段映射原则：

- `AlertModel.raw_data`：存储原始告警的完整 JSON 字符串。
- `AlertModel.unmapped`：存储未能映射到 AlertModel/ArtifactModel 标准字段的内容。
- AlertModel 字段填充优先级：① 直接从原始告警提取映射；② 通过原始告警字段计算或转换得到；③ 以上两步均无法获取时使用合理默认值。
- MITRE ATT&CK 字段（`tactic`、`technique`、`sub_technique`）根据告警类型硬编码。
- `Alert.create(alert_model)` 会自动级联创建 artifacts 记录，并将生成的 row_id 列表回写到 AlertModel.artifacts，再创建
  alert 记录——因此 artifacts 应挂载到 alert_model 上，不要单独调用 Artifact.create。
- Artifact 选择原则：优先选择稳定、可复用、可调查的实体；判断一个字段是否适合作为 Artifact 时，重点看它能否帮助跨告警关联、调查取证或自动化处置。
- 避免把单事件随机标识作为 Artifact，例如 request_id、event_id、trace_id、session_id、uuid 等；除非该 rule 的调查目标就是这些 ID。
- 优先保留原始、完整、稳定的实体值，避免只保存过度裁剪或泛化后的派生值；派生值更适合放在 Alert label、描述或 unmapped 中。
- ArtifactRole 应表达实体在事件中的关系：行为发起方通常为 `ACTOR`，被操作对象通常为 `TARGET`，受影响资产/环境通常为 `AFFECTED`，仅提供上下文的信息通常为 `RELATED` 或 `OTHER`。
- 如果 unmapped 中有特殊价值的字段需要结构化存储，可创建 `EnrichmentModel` 记录并挂载到 ArtifactModel / AlertModel /
  CaseModel 的 enrichments 字段。
- Enrichment 只用于补充对调查有帮助但不适合作为核心 Alert/Case/Artifact 字段的信息。不要把所有 unmapped 字段都转成 Enrichment；默认先放入 `unmapped`，只有需要结构化展示或后续自动化消费时再创建 Enrichment。
- 针对实体的威胁情报信息或 Owner 归属，优先直接存储到 `ArtifactModel` 的对应字段（如 `owner`、`reputation_score`、
  `reputation_provider`）；若需要更丰富的结构化内容，再创建 EnrichmentModel 挂载到 ArtifactModel。

### Step 6 — 创建测试脚本

在 `TEST/test_module_<slug>.py` 创建独立测试脚本（使用可读的 slug，如 `test_module_cloud_01.py`）。**不要**在模块文件本身添加 `if __name__ == "__main__":` 块——测试代码与模块代码分离，保持模块文件干净。

使用标准测试脚本模板：

```python
import os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
import django; django.setup()

import importlib.util
_mod = importlib.util.module_from_spec(
    importlib.util.spec_from_file_location("m", Path(__file__).resolve().parents[1] / "MODULES" / "<rule-name>.py")
)
_mod.__spec__.loader.exec_module(_mod)
Module = _mod.Module

if __name__ == "__main__":
    module = Module()
    # module.debug_message_id = "<message_id>"
    # module.run()

    for mid in module.read_stream_head_ids(20):
        module.debug_message_id = mid
        module.run()
```

两种模式：
- 注释掉批量循环，取消注释单条消息行，调试单条告警。
- 默认：批量处理 stream 中最早的 N 条消息。

## 澄清规则

- 如果用户未提供 rule 名称，必须先询问，不得假设。
- 如果无法通过 MCP 读取 stream，询问用户选择方式 B 或方式 C 获取样本。
- 如果 raw_alert 字段含义不明确，询问用户或查阅相关文档后再映射。
- 如果用户未说明 correlation 聚合键，根据告警语义推断并向用户确认。

## 输出规则

- 生成完整的、可直接运行的 Python 文件内容。
- 代码中的注释使用中文，与项目风格保持一致。
- 生成代码后，简要说明各关键字段的映射逻辑，便于用户审查。
- 不要输出与模块代码无关的冗余内容。
- AlertModel 和 CaseModel 的 `description` 字段支持 markdown 渲染，但在前端以行内组件形式展示——不要使用 `#` `##` `###` 标题语法、`---` 水平分割线、HTML 标签和图片，会破坏页面布局。其他 markdown 特性（加粗、行内代码、代码块、列表、表格、链接、引用）均可正常使用，应充分利用以提升可读性。

## 失败处理

- 如果无法连接 ASP MCP 且用户也无法提供 raw_alert 样本，说明无法继续并指引用户先完成前置条件。
- 如果 raw_alert 结构异常（字段缺失或嵌套过深），说明发现的问题并要求用户提供更多样本或补充说明。
- 如果用户提供的 rule 名称含有非法字符（不能作为 Python 文件名），提示用户确认名称是否正确。
