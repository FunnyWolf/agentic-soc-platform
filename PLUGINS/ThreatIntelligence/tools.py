from __future__ import annotations

from typing import Callable, Dict, List, Optional

from Lib.log import logger
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.ThreatIntelligence.models import TIProviderResult, TIQueryOutput

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------
# Each provider must expose a query(indicator: str) -> dict function.
# The returned dict should include at minimum: indicator, indicator_type, provider.
# See AlienVaultOTX.summarize_result() for the expected field structure.
#
# To add a new provider:
#   1. Create PLUGINS/NewProvider/ with client code and CONFIG.example.py
#   2. Implement a query(indicator: str) -> dict function
#   3. Register it below: PROVIDERS["NewProvider Name"] = new_provider_query
# ---------------------------------------------------------------------------

PROVIDERS: Dict[str, Callable[[str], dict]] = {
    "AlienVaultOTX": AlienVaultOTX.query,
}

_RISK_PRIORITY = {"high": 3, "medium": 2, "low": 1, None: 0}


class TIToolKit:
    @classmethod
    def query(cls, indicator: str, provider: Optional[str] = None) -> TIQueryOutput:
        """Query threat intelligence providers for an indicator.

        Args:
            indicator: IP address, file hash, URL, or domain.
            provider: Specific provider name; None queries all registered providers.

        Returns:
            TIQueryOutput with per-provider results and aggregated risk level.
        """
        indicator = indicator.strip()
        if provider:
            providers_to_query = {provider: PROVIDERS[provider]}
        else:
            providers_to_query = PROVIDERS

        results: List[TIProviderResult] = []
        errors: List[str] = []

        for prov_name, query_func in providers_to_query.items():
            try:
                raw = query_func(indicator)
                result = cls._to_provider_result(raw, prov_name)
                results.append(result)
                if result.error:
                    errors.append(f"[{prov_name}] {result.error}")
            except Exception as exc:
                msg = f"[{prov_name}] {exc}"
                logger.exception(msg)
                errors.append(msg)

        indicator_type = cls._infer_indicator_type(results)
        aggregated_risk = cls._aggregate_risk(results)

        return TIQueryOutput(
            indicator=indicator,
            indicator_type=indicator_type,
            results=results,
            aggregated_risk_level=aggregated_risk,
            errors=errors,
        )

    @staticmethod
    def list_providers() -> List[str]:
        """Return names of all registered ThreatIntelligence providers."""
        return list(PROVIDERS.keys())

    @staticmethod
    def _to_provider_result(raw: dict, provider_name: str) -> TIProviderResult:
        if raw.get("error"):
            return TIProviderResult(
                indicator=raw.get("indicator", ""),
                indicator_type=raw.get("indicator_type", "unknown"),
                provider=provider_name,
                error=raw["error"],
                raw=raw,
            )
        return TIProviderResult(
            indicator=raw.get("indicator", ""),
            indicator_type=raw.get("indicator_type", "unknown"),
            provider=provider_name,
            risk_level=raw.get("risk_level"),
            reputation_score=raw.get("reputation_score"),
            is_malicious=raw.get("is_malicious"),
            tags=raw.get("tags", []),
            attack_techniques=raw.get("attack_techniques", []),
            malware_families=raw.get("malware_families", []),
            adversaries=raw.get("adversaries", []),
            industries=raw.get("industries", []),
            pulses=raw.get("pulses", []),
            network_context=raw.get("network_context"),
            raw=raw,
        )

    @staticmethod
    def _infer_indicator_type(results: List[TIProviderResult]) -> str:
        for r in results:
            if r.indicator_type and r.indicator_type != "unknown":
                return r.indicator_type
        return "unknown"

    @staticmethod
    def _aggregate_risk(results: List[TIProviderResult]) -> Optional[str]:
        best = None
        for r in results:
            if _RISK_PRIORITY.get(r.risk_level, 0) > _RISK_PRIORITY.get(best, 0):
                best = r.risk_level
        return best
