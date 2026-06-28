# Custom Examples 文档设计

## 背景

当前 `定制开发` 文档已经分别说明了 Mock 数据、SIEM YAML、Module 开发和 Playbook 开发，但源码仓库里有一组示例文件本来是可以配合使用的：

- `backend/mock/siem/` 负责生成 SIEM 风格的模拟日志。
- `backend/custom/data/siem/` 提供描述这些模拟索引的 SIEM YAML。
- `backend/custom/modules/` 提供将 raw alert 转换为 ASP Case / Alert / Artifact 的 Module 示例。
- `backend/custom/data/modules/` 提供这些 Module 可使用的 raw alert 样本。
- `backend/custom/playbooks/` 提供两个 custom Playbook 示例。
- `backend/custom/data/playbooks/` 提供 Case Summary Playbook 使用的 prompt 文件。

新文档需要把这些关系讲清楚，让用户理解它们不是互相孤立的代码样例，而是一套可复用的定制开发演示资产，覆盖自定义日志说明、SIEM 查询、告警接入、Case 生成和 Case 后续自动化处理。

## 目标

1. 在 `Development / 定制开发` 下新增一个清晰的示例入口。
2. 说明 Mock SIEM 日志、SIEM YAML、Module、raw alert 样本和 custom Playbook 之间的关系。
3. 为用户提供的位置记录 Mock 日志对应的 Splunk SPL 和 ELK ES|QL 告警查询。
4. 保留现有 Mock Data、SIEM YAML、Module 开发、Playbook 开发页面的单项指南职责。
5. 从现有页面增加指向新示例页的交叉链接。
6. 同时说明源码仓库使用方式，以及如何把示例复制到 Compose 部署包的 `custom/` 目录中使用。
7. 中英文文档结构保持一致。

## 非目标

1. 不修改后端示例代码。
2. 不新增截图或图片占位符。
3. 不声称每个 SIEM YAML 都有对应 Module。
4. 不声称 Mail Module 来自 SIEM Mock 日志生成器。
5. 除非明确要求，不运行 VitePress build。

## 页面结构

在 `Development / 定制开发` 侧边栏下新增 Custom Examples 区域：

```text
custom-examples/
custom-examples/siem-module-flow/
custom-examples/playbooks/
```

推荐位置：放在 Custom Console 之后、单项开发指南之前；或者作为一个小的示例组，靠近 Module Development、Playbook Development、SIEM YAML 和 Mock Data。

整体 `定制开发` 栏目的信息架构应调整为：

- `定制开发总览`：解释扩展模型和推荐阅读路径。
- `Custom Console`：解释运行时观察和校验。
- `Module 开发`、`Playbook 开发`、`SIEM YAML`、`Mock 数据`：继续作为单项指南。
- `Custom Examples`：作为 cookbook / 端到端示例区域，解释这些单项能力如何组合使用。

这样可以把概念、接口和开发规范保留在现有页面，把跨模块的组合示例集中到新页面，避免内容重复和割裂。

### `custom-examples/`

职责：示例总览页。

内容：

- 说明源码树中的 `backend/custom/` 是测试/示例资产集合。
- 说明发布包中的 `custom/` 默认是空模板。
- 说明用户可以把需要的示例复制到 Compose 部署环境中运行。
- 展示整体关系：
  - Mock SIEM 日志生成测试日志数据。
  - SIEM YAML 描述索引和字段。
  - Module 消费 Redis Stream raw alert 并创建 ASP 资源。
  - Playbook 在 Case 生成后继续执行自动化处理。

### `custom-examples/siem-module-flow/`

职责：说明 Mock 日志、SIEM YAML、raw alert 和 Module 如何配合。

必须包含的关系表：

| 资产 | 角色 | 关系 |
| --- | --- | --- |
| `siem-host-events.yaml` | SIEM 索引说明 | 对应 Host mock events，支撑 EDR vssadmin 场景。 |
| `edr_vssadmin_delete_shadows.py` | Module | 将类似 vssadmin 的 raw alert 转换为勒索调查 Case。 |
| `siem-aws-cloudtrail.yaml` | SIEM 索引说明 | 对应 CloudTrail mock events，支撑 AttachUserPolicy 场景。 |
| `aws_iam_privilege_escalation_attach_user_policy.py` | Module | 将类似 AttachUserPolicy 的 raw alert 转换为 IAM 权限提升 Case。 |
| `siem-network-traffic.yaml` | SIEM 索引说明 | 支撑网络流量和暴力破解 mock 日志，可用于 SIEM 查询和规则编写示例；当前没有专属 Module。 |
| `mail_user_report_phishing.py` | Module | 使用 `backend/custom/data/modules/` 中的 raw alert 样本；它不是由 SIEM Mock 日志生成器产生的。 |

还需要说明：

- 源码仓库路径。
- 复制到 Compose 部署包后的路径。
- 如果有可用规则，展示每个场景的 Splunk SPL 和 ELK ES|QL 告警查询。
- 在 Custom Console 中执行 Refresh / Validate 的方式。
- Module 需要运行哪个 Worker。
- 预期输出：Case、Alert、Artifact、Enrichment，以及在适用场景下触发 AI analysis。

如果用户提供具体告警查询，应放在对应场景附近：

- Host vssadmin 场景：查找 `vssadmin.exe delete shadows` 的 Splunk SPL / ELK ES|QL。
- AWS AttachUserPolicy 场景：查找高风险 `AttachUserPolicy` 行为的 Splunk SPL / ELK ES|QL。
- Network traffic / brute-force 场景：查找可疑网络或认证模式的 Splunk SPL / ELK ES|QL。

需要明确：这些规则用于从 Mock SIEM 日志中筛选证据。如果该场景有对应 Module，那么告警/action 集成最终写入的 Redis Stream 名称必须和 Module 的 `STREAM_NAME` 一致。

用户已提供的 Network brute-force / failed-then-success 登录场景 Splunk SPL：

```spl
index=siem-network-traffic event.category=authentication (event.action=login_failed OR
  event.action=login_success)
  | search
      [search index=siem-network-traffic event.category=authentication event.action=login_failed
       | stats count AS failed_count BY source.ip, user.name
       | where failed_count >= 5
       | join source.ip, user.name
           [search index=siem-network-traffic event.category=authentication event.action=login_success
            | stats count AS success_count BY source.ip, user.name]
       | fields source.ip, user.name]
```

用户已提供的 AWS AttachUserPolicy 高风险成功授权场景 ELK ES|QL：

```esql
FROM siem-aws-cloudtrail
  | WHERE event.action == "AttachUserPolicy"
  | WHERE event.risk_score > 80
  | WHERE event.outcome == "success"
  | WHERE
      requestParameters.policyArn IN
        (
          "arn:aws:iam::aws:policy/AdministratorAccess",
          "arn:aws:iam::aws:policy/IAMFullAccess"
        )
  | SORT @timestamp DESC
```

用户已提供并整理的 Host vssadmin delete shadows 场景 ELK ES|QL：

```esql
FROM siem-host-events
  | WHERE process.name == "vssadmin.exe"
  | WHERE risk_score >= 80
  | WHERE process.command_line LIKE "*delete*shadows*"
  | SORT @timestamp DESC
```

### `custom-examples/playbooks/`

职责：介绍两个 custom Playbook 示例。

必须包含：

- `case_summary.py`
  - 读取 `custom/data/playbooks/case_summary/System_zh.md` 或 `System_en.md`。
  - 按 Runtime 中的 Prompt Language 选择提示词。
  - 调用 LLM，并把结果写回 Case Summary 字段。
- `cmdb_enrichment.py`
  - 遍历 Case 关联的 Artifact。
  - 通过集成层查询 CMDB 上下文。
  - 将结果写入 Artifact Enrichment。

还需要说明：

- 源码仓库路径。
- 复制到 Compose 部署包后的路径。
- 在 Custom Console 中执行 Refresh / Validate 的方式。
- 需要运行的 Worker。
- 在 ASP UI 中查看结果的位置。

## 现有页面更新

需要从以下页面增加简短入口链接：

- `development/`
- `development/custom-console/`
- `development/mock-data/`
- `development/siem-yaml/`
- `development/module-examples/`
- `development/playbook/`

每个页面继续保持当前职责，只把端到端组合示例引导到 Custom Examples。

具体更新：

- `定制开发总览`：在推荐阅读顺序中，把 Custom Examples 放到单项开发指南之后。
- `Custom Console`：链接到 Custom Examples，说明这里可以了解运行时加载的示例如何组合。
- `Mock 数据`：明确 SIEM Mock 日志可以配合示例 SIEM YAML、示例查询和示例 Module 使用。
- `SIEM YAML`：链接到 SIEM + Module 示例链路，展示具体索引 / 查询 / Module 的关系。
- `Module 开发`：链接到 SIEM + Module 示例链路，展示完整 raw alert 到 Case 的示例。
- `Playbook 开发`：链接到 Custom Playbook 示例页，说明两个 custom Playbook。

## 语言流程

1. 先写中文页面。
2. 中文结构稳定后，再创建对应英文页面。
3. zh/en 的标题和页面结构保持一致。

## 验证

手工验证应覆盖：

1. 中文和英文侧边栏都包含新页面。
2. 所有新页面都有 zh/en 两个版本。
3. 现有页面能链接到新总览页或详情页。
4. 新页面能链接回 Mock Data、SIEM YAML、Module Development、Playbook Development 和 Custom Console。
5. 页面没有声称 `siem-network-traffic` 有专属 Module。
6. 页面没有声称 Mail Module 来自 SIEM Mock 日志。
7. 除非明确要求，不运行 VitePress build。
