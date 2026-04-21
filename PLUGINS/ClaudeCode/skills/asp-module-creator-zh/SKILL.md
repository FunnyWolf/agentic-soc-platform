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
- SIRP 数据层级：`Case → Alert → Artifact`（三级体系）。Artifact 是调查的最小原子实体（一个 IP、一个用户名），应尽量从 raw_alert 中提取；Alert 挂在 Case 下；同类告警通过 `correlation_uid` 聚合到同一个 Case。Enrichment 是独立于三级体系之外的横切附加层，可按需挂载到 Case / Alert / Artifact 任意一级。
- 参考实现：`MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py`。
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
要求用户将一条或多条 raw_alert JSON 拷贝到 `DATA/<rule-name>/raw_alert_1.json`（以此类推），然后读取该文件。

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

确定 correlation 聚合键（通常选择能唯一标识"同一攻击行为"的 2-3 个字段）：
- 键太宽泛（如只用 account_id）→ 不相关的告警混入同一个 Case，调查噪音大
- 键太精细（如包含随机 session_id）→ 同一次攻击的多条告警被拆成多个 Case，丢失上下文
- 好的聚合键应能回答："这些告警是否描述的是同一个攻击者对同一个目标的同一类行为？"

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
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window="24h",
            keys=[...],  # 聚合键列表
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
        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
            if existing_case:
                update_case = CaseModel(
                    alerts=[*existing_case.alerts, saved_alert_row_id],
                    row_id=existing_case.row_id
                )
                Case.update(update_case)
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
                Case.create(new_case)
        except Exception as e:
            self.logger.error(f"Case operation failed: {str(e)}")

        return True
```

框架行为说明：
- 框架会持续循环实例化 Module 类并调用 `run()`，每次调用只处理一条告警——模块应设计为无状态的，不要在实例变量中积累跨告警的状态。

字段映射原则：
- `AlertModel.raw_data`：存储原始告警的完整 JSON 字符串。
- `AlertModel.unmapped`：存储未能映射到 AlertModel/ArtifactModel 标准字段的内容。
- AlertModel 字段填充优先级：① 直接从原始告警提取映射；② 通过原始告警字段计算或转换得到；③ 以上两步均无法获取时使用合理默认值。
- MITRE ATT&CK 字段（`tactic`、`technique`、`sub_technique`）根据告警类型硬编码。
- `Alert.create(alert_model)` 会自动级联创建 artifacts 记录，并将生成的 row_id 列表回写到 AlertModel.artifacts，再创建 alert 记录——因此 artifacts 应挂载到 alert_model 上，不要单独调用 Artifact.create。
- 如果 unmapped 中有特殊价值的字段需要结构化存储，可创建 `EnrichmentModel` 记录并挂载到 ArtifactModel / AlertModel / CaseModel 的 enrichments 字段。
- 针对实体的威胁情报信息或 Owner 归属，优先直接存储到 `ArtifactModel` 的对应字段（如 `owner`、`reputation_score`、`reputation_provider`）；若需要更丰富的结构化内容，再创建 EnrichmentModel 挂载到 ArtifactModel。

### Step 6 — 添加调试入口

在文件末尾追加：

```python
if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    module = Module()
    module.debug_message_id = "<填入一个真实的 stream message ID>"
    module.run()
```

提示用户将 `debug_message_id` 替换为 Redis Stream 中的真实消息 ID，便于直接运行脚本进行调试。

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

## 失败处理

- 如果无法连接 ASP MCP 且用户也无法提供 raw_alert 样本，说明无法继续并指引用户先完成前置条件。
- 如果 raw_alert 结构异常（字段缺失或嵌套过深），说明发现的问题并要求用户提供更多样本或补充说明。
- 如果用户提供的 rule 名称含有非法字符（不能作为 Python 文件名），提示用户确认名称是否正确。
