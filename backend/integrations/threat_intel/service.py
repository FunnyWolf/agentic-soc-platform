from integrations.threat_intel.models import TIQueryOutput
from integrations.threat_intel.providers import get_providers

RISK_PRIORITY = {"high": 3, "medium": 2, "low": 1, None: 0}


def list_providers():
    return list(get_providers().keys())


def query_indicator(indicator, *, artifact_type, provider=None):
    indicator = str(indicator or "").strip()
    active_providers = get_providers()
    if provider is not None:
        if provider not in active_providers:
            raise ValueError(f"Unknown threat intelligence provider: {provider}")
        providers = {provider: active_providers[provider]}
    else:
        providers = active_providers

    if not providers:
        return TIQueryOutput(
            indicator=indicator,
            indicator_type="unknown",
            results=[],
            aggregated_risk_level=None,
            errors=["No enabled threat intelligence providers are configured."],
        )

    results = []
    errors = []
    for provider_name, provider_instance in providers.items():
        try:
            result = provider_instance.query(indicator, artifact_type=artifact_type)
            results.append(result)
            if result.error:
                errors.append(f"[{provider_name}] {result.error}")
        except Exception as exc:
            errors.append(f"[{provider_name}] {type(exc).__name__}: {exc}")

    return TIQueryOutput(
        indicator=indicator,
        indicator_type=_indicator_type(results),
        results=results,
        aggregated_risk_level=_aggregate_risk(results),
        errors=errors,
    )


def _indicator_type(results):
    for result in results:
        if result.indicator_type and result.indicator_type != "unknown":
            return result.indicator_type
    return "unknown"


def _aggregate_risk(results):
    best = None
    for result in results:
        if RISK_PRIORITY.get(result.risk_level, 0) > RISK_PRIORITY.get(best, 0):
            best = result.risk_level
    return best
