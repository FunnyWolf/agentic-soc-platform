![cover](Docker/IMG/img.png)

# Agentic SOC Platform

<p align="center">
  <a href="https://asp.viperrtp.com/asp/Development/environment_setup/">Quick Start</a> ·
  <a href="https://asp.viperrtp.com/asp/Introduction/what_is_asp/">Documentation</a> ·
  <a href="https://asp.viperrtp.com/sirp/Introduction/what_is_sirp/">SIRP Platform</a>
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

**Agentic SOC Platform** is an open-source security operations platform built on Agentic AI — free your security team from alert fatigue and focus on real threats.

---

### Alert Aggregation, 99% Noise Reduction

The Module framework continuously consumes SIEM alerts, automatically extracts IOCs and correlates them — reducing millions of logs to just a handful of actionable cases.

![Alert Aggregation](Docker/IMG/img_1.png)

### AI-Powered Investigation, Seconds Not Hours

LLM auto-generates structured investigation reports — verdicts, attack chains, IOCs, and remediation advice in seconds, not hours.

![AI Investigation Reports](Docker/IMG/img_2.png)

### One-Click Automation

Playbooks support one-click execution of case investigation, knowledge extraction, and threat intelligence enrichment — let AI handle the complexity while analysts focus on decisions.

![One-Click Automation](Docker/IMG/img_3.png)

### Unified Multi-SIEM Access

Manage ELK, Splunk and other SIEM indices through a single YAML configuration. One API to search across all backends — LLM and analysts never need to worry about the underlying differences.

![Unified Multi-SIEM Access](Docker/IMG/img_4.png)

### Automated Threat Intelligence Enrichment

When artifacts are created, threat intelligence providers are queried automatically. Reputation scores, pulse information, and malware context are attached to IOCs to accelerate analyst judgment.

![Threat Intelligence Enrichment](Docker/IMG/img_5.png)

### Deep Code Agent Integration

Integrated with Claude Code via MCP protocol, providing professional security agents and skills — operate cases, search logs, and write modules directly from within an AI agent.

![Code Agent Integration](Docker/IMG/img_6.png)

### Knowledge Accumulation, Smarter Over Time

Automatically extract reusable security knowledge from closed cases, continuously building an organizational knowledge base that makes future investigations faster and more accurate.

![Knowledge Accumulation](Docker/IMG/img_7.png)

### Open Source, Private Deployment, Pure Python

MIT licensed, fully on-premise deployment — your data never leaves your network. Modules, plugins, and playbooks are all Python scripts with zero technology stack barriers.

![Open Source & Private](Docker/IMG/img_8.png)

---

## Workflow

```
SIEM Alert → Webhook → Redis Stream → Module Processing → Case/Alert/Artifact → AI Report → Analyst Decision
```

## Official Website

[https://asp.viperrtp.com](https://asp.viperrtp.com)

## 404Starlink

<img src="./Docker/IMG/logo.png" width="30%">

Agentic SOC Platform has joined [404Starlink](https://github.com/knownsec/404StarLink)
