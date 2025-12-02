![cover-v5-optimized](Docker/Img/img.png)

<p align="center">
  <a href="https://asp.viperrtp.com/zh/asf/Development/environment_setup/">Getting-started</a> ·
  <a href="https://asp.viperrtp.com/zh/asf/Introduction/what_is_asf/">Documentation</a>
</p>

<p align="center">
    <a href="https://asp.viperrtp.com/" target="_blank">
        <img alt="Static Badge" src="https://img.shields.io/badge/Website-F04438"></a>
    <a href="https://github.com/funnywolf/agentic-soc-platform/graphs/commit-activity" target="_blank">
        <img alt="Commits last month" src="https://img.shields.io/github/commit-activity/m/funnywolf/agentic-soc-platform?labelColor=%20%2332b583&color=%20%2312b76a"></a>
    <a href="https://github.com/funnywolf/agentic-soc-platform/" target="_blank">
        <img alt="Issues closed" src="https://img.shields.io/github/issues-search?query=repo%3Afunnywolf%2Fagentic-soc-platform%20is%3Aclosed&label=issues%20closed&labelColor=%20%237d89b0&color=%20%235d6b98"></a>
    <a href="https://github.com/funnywolf/agentic-soc-platform/releases" target="_blank">
        <img alt="Release" src="https://img.shields.io/github/v/release/funnywolf/agentic-soc-platform?style=flat&label=Release&color=limegreen"></a>
</p>

<p align="center">
  <a href="./README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README_ZH.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>


**Agentic SOC Platform** 是一个功能强大、灵活且开源的自动化安全运营平台。它集成了 AI Agent 能力与自动化编排，支持主流
SIEM/SOAR 场景，帮助企业高效构建智能化安全运营体系。

## 核心功能

- 🧠 **AI 驱动智能**: 利用内置的 Langgraph 和 Dify 等 AI Agent 模板，支持本地 LLM，增强告警分析和自动化响应能力。
- 📊 **内置 SIRP 平台**: 内置安全事件响应平台 (SIRP)，可快速定制开发用户界面、数据模型、报告和工作流。
- ⚙️ **强大的自动化流程**: 通过 Webhook + Redis Stream 实现高效的告警处理流程，原生支持 Splunk 和 Kibana (ELK) 等主流
  SIEM 平台。
- 🛠️ **高度可扩展性**: 提供丰富的模块和插件库。整个框架用 Python 编写，便于二次开发和与各类安全设备及 API 集成。
- 🛡️ **本地部署与数据控制**: 支持完全本地化部署。所有数据、模型和操作都可以在您自己的环境中托管，确保企业数据安全和隐私。
- ⚡ **流式与批量处理**: 提供用于实时告警分析的流式处理（模块）和用于用户触发任务（剧本）的事件驱动自动化。

## 架构概览

ASP 通过简化的多阶段流程处理安全告警和事件：

1. **SIEM/告警源**: EDR、NDR 或其他安全工具将告警发送到 SIEM（例如 Splunk、Kibana）。
2. **Webhook 转发器**: SIEM 通过 Webhook 将这些告警转发到 ASP 内置的 Webhook 接收器。
3. **Redis Stream**: 接收器将告警推送到相应的 Redis Stream 中，作为持久化消息队列。每种告警类型都有自己的流。
4. **模块引擎**: ASP **模块** 从其指定的流中消费告警，执行分析（通常使用 AI Agent），丰富数据，并确定结果。
5. **SIRP 平台**: 模块的输出（现在已格式化为标准化的安全记录）被发送到 **SIRP** 平台，在那里创建或更新案例、告警和 Artifact。
6. **剧本引擎**: 分析师可以从 SIRP 用户界面触发针对案例、告警或 Artifact 的 **剧本**，以执行进一步的自动化操作，例如威胁情报丰富或修复。

![img_1.webp](Docker/Img/img_20.png)
![img_2.webp](Docker/Img/img_21.png)
![img_2.webp](Docker/Img/img_22.png)
![img_3.webp](Docker/Img/img_23.png)
![img_4.webp](Docker/Img/img_24.png)

## 官方网站

[https://asp.viperrtp.com/zh/](https://asp.viperrtp.com/zh/)
