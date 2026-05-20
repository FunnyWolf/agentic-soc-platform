from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TIProviderResult(BaseModel):
    indicator: str = Field(default="", description="The indicator that was queried (被查询的指标)")
    indicator_type: str = Field(default="unknown", description="Detected type: ip, file, url, domain, etc. (检测到的指标类型)")
    provider: str = Field(default="", description="Provider name, e.g. 'AlienVault OTX' (提供商名称)")
    risk_level: Optional[str] = Field(default=None, description="Risk level: high / medium / low (风险等级)")
    reputation_score: Optional[int] = Field(default=None, description="Provider-specific reputation score (提供商信誉分数)")
    is_malicious: Optional[bool] = Field(default=None, description="Provider verdict on maliciousness (是否恶意)")
    tags: List[str] = Field(default_factory=list, description="Threat tags (威胁标签)")
    attack_techniques: List[str] = Field(default_factory=list, description="Attack techniques (攻击技术)")
    malware_families: List[str] = Field(default_factory=list, description="Malware families (恶意软件家族)")
    adversaries: List[str] = Field(default_factory=list, description="Adversaries / threat actors (对手/威胁行为者)")
    industries: List[str] = Field(default_factory=list, description="Targeted industries (目标行业)")
    pulses: List[Dict[str, Any]] = Field(default_factory=list, description="Threat intelligence pulses (威胁情报脉冲)")
    network_context: Optional[Dict[str, Any]] = Field(default=None, description="Network context info (网络上下文信息)")
    raw: Dict[str, Any] = Field(
        default_factory=dict,
        description="Full provider-specific response for drill-down (提供商原始完整响应)",
    )
    error: Optional[str] = Field(default=None, description="Error message if query failed (查询失败时的错误信息)")


class TIQueryInput(BaseModel):
    indicator: str = Field(..., description="Indicator to look up: IP, hash, URL, domain (待查询的指标)")
    provider: Optional[str] = Field(
        default=None,
        description="Specific provider name; None queries all registered providers (指定提供商名称,None 表示查询所有已注册的提供商)",
    )


class TIQueryOutput(BaseModel):
    indicator: str = Field(..., description="The indicator that was queried (被查询的指标)")
    indicator_type: str = Field(..., description="Detected indicator type (检测到的指标类型)")
    results: List[TIProviderResult] = Field(
        default_factory=list,
        description="Per-provider results (每个提供商的查询结果)",
    )
    aggregated_risk_level: Optional[str] = Field(
        default=None,
        description="Highest risk_level across providers (跨提供商的最高风险等级)",
    )
    errors: List[str] = Field(
        default_factory=list,
        description="Error messages from providers that failed (失败的提供商错误信息)",
    )
