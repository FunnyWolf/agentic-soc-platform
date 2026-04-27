# ASP 告警处理架构说明

## 整体链路

```
原始日志
  │
  ▼
SIEM（ELK / Splunk）
  │  Detection Rule 匹配后产生告警
  ▼
转发工具
  │  将告警写入 Redis Stack Stream
  │  Stream 名称 = Rule 名称（强约束）
  ▼
Redis Stream: "<rule-name>"
  │
  ▼
ASP Module: MODULES/<rule-name>.py
  │  框架持续循环调用 run()，Consumer Group 模式保证每条告警只处理一次
  ▼
SIRP（Case / Alert / Artifact / Enrichment）
```

---

## 命名约定（强约束）

```
SIEM Rule 名称
    = Redis Stream 名称
    = MODULES/<文件名>.py（不含 .py）
```

三者必须完全一致（含大小写），框架依赖此约定自动路由告警到对应模块。任意一处不一致，告警将无法被消费。

---

## Module 内部处理流程

```
self.read_stream_message()
        │
        │  raw_alert: dict
        ▼
┌─────────────────────────────────────────────┐
│ 1. 字段提取                                  │
│    从 raw_alert 中解析所有有价值的字段         │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 2. Artifact 提取                             │
│    将实体（IP、用户名、ARN、账号等）           │
│    封装为 List[ArtifactModel]                │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 3. correlation_uid 计算                      │
│    选取 2-3 个聚合键 + 时间窗口（通常 24h）   │
│    决定哪些告警归入同一个 Case               │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 4. AlertModel 组装 + Alert.create()          │
│    · artifacts 挂载到 alert_model            │
│    · Alert.create() 自动级联创建 Artifact    │
│      记录，并回写 row_id 到 AlertModel       │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ 5. Case 查找 / 创建 / 更新                   │
│    · 按 correlation_uid 查找已有 Case        │
│    · 有 → 将 alert row_id 追加到 Case.alerts │
│    · 无 → 创建新 Case                        │
└─────────────────────────────────────────────┘
```

---

## SIRP 数据层级

```
Case（调查案件，顶层）
 │  通过 correlation_uid 聚合同类告警
 │
 └── Alert（单次规则触发记录，二级）
      │  每条 raw_alert 对应一条 Alert
      │
      └── Artifact（最小调查实体，三级）
           IP、用户名、ARN、账号 ID 等
           可跨 Alert 共享


Enrichment（横切附加层，独立于三级体系之外）
 可挂载到 Case、Alert、Artifact 任意一级
 ├── → Case.enrichments
 ├── → Alert.enrichments
 └── → Artifact.enrichments
```

### 各层说明

| 层级 | 对象 | 说明 |
|------|------|------|
| 顶层 | Case | 一次完整的调查事件，包含多条相关 Alert |
| 二级 | Alert | 一次 SIEM 规则触发，对应一条 raw_alert |
| 三级 | Artifact | 最小调查原子（实体），是后续威胁情报查询、关联分析的基础 |
| 横切 | Enrichment | 结构化附加上下文，不属于三级体系，可按需挂载到任意层级 |

---

## correlation_uid 设计原则

`correlation_uid` 决定了告警的聚合粒度，是模块设计中最关键的判断。

**判断标准：** 这些告警是否描述的是"同一个攻击者对同一个目标的同一类行为"？

| 聚合键粒度 | 后果 |
|-----------|------|
| 太宽泛（如只用 account_id） | 不相关的告警混入同一 Case，调查噪音大 |
| 太精细（如包含随机 session_id） | 同一次攻击的多条告警被拆成多个 Case，丢失上下文 |
| 合适（如 principal_user + target_user + account_id） | 同一攻击者针对同一目标的行为聚合在一起 |

**生成方式：**
```python
correlation_uid = Correlation.generate_correlation_uid(
    rule_id=self.module_name,   # 模块名称，隔离不同规则
    time_window="24h",          # 时间窗口，超出则开新 Case
    keys=[key1, key2, key3],    # 聚合键列表
    timestamp=event_time        # 事件发生时间
)
```

---

## Artifact 设计原则

- Artifact 是后续调查（威胁情报查询、关联分析、Playbook 执行）的基础，应尽量从 raw_alert 中提取
- 每个有价值的实体单独建一条 Artifact，不要合并
- `type` 字段使用 `ArtifactType` 枚举（IP_ADDRESS、USER_NAME、RESOURCE_UID 等）
- `role` 字段区分实体在事件中的角色（ACTOR 攻击方、TARGET 目标方、RELATED 相关方）
- 威胁情报信息和 Owner 归属优先直接存入 ArtifactModel 字段（`owner`、`reputation_score`、`reputation_provider`）

---

## 关键文件索引

| 文件 | 用途 |
|------|------|
| `MODULES/<rule-name>.py` | 告警处理模块，一个 rule 对应一个文件 |
| `Lib/basemodule.py` | BaseModule 基类，提供 `read_stream_message()` 等基础能力 |
| `PLUGINS/SIRP/sirpcoremodel.py` | 所有数据模型和枚举定义 |
| `PLUGINS/SIRP/sirpapi.py` | Alert / Case 的 CRUD 操作接口 |
| `PLUGINS/SIRP/correlation.py` | `Correlation.generate_correlation_uid()` |
| `MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py` | 参考实现 |
| `DATA/<rule-name>/raw_alert_*.json` | 开发调试用的 raw_alert 样本 |
