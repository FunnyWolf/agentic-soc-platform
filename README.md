![cover-v5-optimized](Docker/Img/img.png)

<p align="center">
  <a href="https://asp.viperrtp.com/asf/Development/environment_setup/">Getting-started</a> ·
  <a href="https://asp.viperrtp.com/asf/Introduction/what_is_asf/">Documentation</a>
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


**Agentic SOC Platform** is a powerful, flexible, and open-source automated security operations platform. It integrates
AI Agent capabilities with automation orchestration, supporting mainstream SIEM/SOAR scenarios to help enterprises
efficiently build intelligent security operations systems.

## Core Features

- 🧠 **AI-driven Intelligence**: Utilizes built-in AI Agent templates like Langgraph and Dify, supporting local LLMs to
  enhance alert analysis and automated response capabilities.
- 📊 **Built-in SIRP Platform**: Comes with a ready-to-use Security Incident Response Platform (SIRP) built on Nocoly,
  allowing for rapid customization of user interfaces, data models, reports, and workflows.
- ⚙️ **Powerful Automation Workflow**: Achieves efficient alert processing through Webhook + Redis Stream, natively
  supporting mainstream SIEM platforms such as Splunk and Kibana (ELK).
- 🛠️ **Highly Extensible**: Provides a rich library of modules and plugins. The entire framework is written in Python,
  facilitating secondary development and integration with various security devices and APIs.
- 🛡️ **Local Deployment & Data Control**: Supports complete local deployment. All data, models, and operations can be
  hosted within your own environment, ensuring enterprise data security and privacy.
- ⚡ **Streaming and Batch Processing**: Offers streaming processing (modules) for real-time alert analysis and
  event-driven automation (playbooks) for user-triggered tasks.

## Architecture Overview

ASP processes security alerts and incidents through a simplified multi-stage process:

1. **SIEM/Alert Sources**: EDR, NDR, or other security tools send alerts to a SIEM (e.g., Splunk, Kibana).
2. **Webhook Forwarder**: The SIEM forwards these alerts via Webhook to the ASP's built-in Webhook receiver.
3. **Redis Stream**: The receiver pushes the alerts to the corresponding Redis Stream, serving as a persistent message
   queue. Each alert type has its own stream.
4. **Module Engine**: ASP **modules** consume alerts from their designated streams, perform analysis (often using AI
   Agents), enrich data, and determine outcomes.
5. **SIRP Platform**: The output of the modules (now formatted into standardized security records) is sent to the **SIRP
   ** platform, where cases, alerts, and artifacts are created or updated.
6. **Playbook Engine**: Analysts can trigger **playbooks** from the SIRP user interface against cases, alerts, or
   artifacts to perform further automated actions, such as threat intelligence enrichment or remediation.

![img_1.webp](Docker/Img/img_20.png)
![img_2.webp](Docker/Img/img_21.png)
![img_2.webp](Docker/Img/img_22.png)
![img_3.webp](Docker/Img/img_23.png)
![img_4.webp](Docker/Img/img_24.png)

## Official Website

[https://asp.viperrtp.com](https://asp.viperrtp.com)

## 404Starlink

<img src lazysrc="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

Agentic SOC Platform has joined [404Starlink](https://github.com/knownsec/404StarLink)