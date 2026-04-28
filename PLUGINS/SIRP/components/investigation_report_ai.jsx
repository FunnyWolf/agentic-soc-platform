function SecurityIncidentReport({ value }) {
  let data = null;

  if (!value) {
    return <div className="p-4 text-gray-500 text-center font-mono">No data</div>;
  }

  if (typeof value === 'string') {
    try {
      data = JSON.parse(value);
    } catch (e) {
      throw new Error("Failed to parse JSON data in SecurityIncidentReport");
    }
  } else if (typeof value === 'object' && value !== null) {
    data = value;
  } else {
    throw new Error("Invalid data type for SecurityIncidentReport");
  }

  const getSeverityBadgeClass = (level) => {
    if (level === 'High' || level === 'Critical') {
      return 'bg-red-50 text-red-700 border-red-200';
    }
    if (level === 'Medium') {
      return 'bg-orange-50 text-orange-700 border-orange-200';
    }
    if (level === 'Low') {
      return 'bg-blue-50 text-blue-700 border-blue-200';
    }
    return 'bg-gray-50 text-gray-700 border-gray-200';
  };

  const formatLocalTime = (utcString) => {
    if (!utcString) return '';
    const date = new Date(utcString);
    if (isNaN(date.getTime())) {
      return utcString;
    }
    return date.toLocaleString();
  };

  return (
    <div className="flex flex-col gap-6 w-full">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={`flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-bold border ${getSeverityBadgeClass(data.severity)}`}>
          Severity: {data.severity}
        </div>
        <div className={`flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-bold border ${getSeverityBadgeClass(data.impact)}`}>
          Impact: {data.impact}
        </div>
        <div className={`flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-bold border ${getSeverityBadgeClass(data.priority)}`}>
          Priority: {data.priority}
        </div>
        <div className={`flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-bold border ${getSeverityBadgeClass(data.confidence)}`}>
          Confidence: {data.confidence}
        </div>
      </div>

      <div className="bg-slate-50 p-5 rounded-lg border border-slate-200">
        <h3 className="flex items-center gap-2 text-sm font-bold text-slate-800 mb-3">
          <LucideIcon name="FileText" size="18" className="text-slate-600" />
          Incident Digest
        </h3>
        <p className="text-sm text-slate-700 leading-relaxed text-justify">
          {data.digest}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="flex flex-col gap-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800 border-b border-gray-100 pb-2">
            <LucideIcon name="Server" size="18" className="text-blue-500" />
            Affected Assets
          </h3>
          <div className="flex flex-col gap-2">
            {Array.isArray(data.affected_assets) && data.affected_assets.map((asset, index) => (
              <div key={index} className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-gray-50 rounded-md border border-gray-100 gap-2">
                <span className="text-[11px] font-bold text-gray-500 px-2 py-1 bg-white border border-gray-200 rounded whitespace-nowrap w-max">
                  {asset.asset_type}
                </span>
                <span className="text-xs text-gray-700 font-mono break-all sm:text-right">
                  {asset.asset_value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800 border-b border-gray-100 pb-2">
            <LucideIcon name="Target" size="18" className="text-red-500" />
            IOC Indicators
          </h3>
          <div className="flex flex-col gap-2">
            {Array.isArray(data.ioc_indicators) && data.ioc_indicators.map((ioc, index) => (
              <div key={index} className="p-3 bg-red-50/50 rounded-md border border-red-100 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-bold text-red-700 px-2 py-0.5 bg-red-100 rounded">
                    {ioc.indicator_type}
                  </span>
                  <span className="text-sm font-mono text-red-600 font-bold">
                    {ioc.value}
                  </span>
                </div>
                <span className="text-xs text-red-500/90 leading-normal">
                  {ioc.context}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800 border-b border-gray-100 pb-2">
          <LucideIcon name="GitMerge" size="18" className="text-indigo-500" />
          Attack Chain
        </h3>
        <div className="flex flex-col gap-3">
          {Array.isArray(data.attack_chain) && data.attack_chain.map((chain, index) => (
            <div key={index} className="flex flex-col gap-2 p-4 bg-indigo-50/30 rounded-lg border border-indigo-100">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-indigo-700 bg-indigo-100 px-2 py-1 rounded">
                  Stage
                </span>
                <span className="text-sm font-bold text-indigo-900">
                  {chain.attack_stage}
                </span>
              </div>
              <p className="text-sm text-gray-700 leading-relaxed text-justify">
                {chain.description}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800 border-b border-gray-100 pb-2">
          <LucideIcon name="Clock" size="18" className="text-purple-500" />
          Timeline
        </h3>
        <div className="relative border-l-2 border-purple-200 ml-3 pl-5 py-2 flex flex-col gap-8">
          {Array.isArray(data.attack_timeline) && data.attack_timeline.map((event, index) => (
            <div key={index} className="relative">
              <div className="absolute -left-[26px] top-1 w-3 h-3 rounded-full bg-purple-500 ring-4 ring-purple-50"></div>
              <div className="text-[11px] font-bold font-mono text-purple-600 mb-1">
                {formatLocalTime(event.timestamp)}
              </div>
              <div className="text-sm text-gray-800 font-medium mb-2 leading-relaxed">
                {event.attack_behavior}
              </div>
              <div className="text-[11px] text-gray-500 bg-gray-50 p-2.5 rounded-md border border-gray-200 font-mono break-all">
                {event.evidence_field}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800 border-b border-gray-100 pb-2">
          <LucideIcon name="Wrench" size="18" className="text-green-600" />
          Remediation Recommendations
        </h3>
        <div className="grid grid-cols-1 gap-3">
          {Array.isArray(data.remediation_recommendations) && data.remediation_recommendations.map((rec, index) => (
            <div key={index} className="flex gap-4 p-4 bg-green-50/50 rounded-lg border border-green-200">
              <LucideIcon name="CheckCircle" size="20" className="text-green-600 shrink-0 mt-0.5" />
              <div className="flex flex-col gap-1.5 w-full">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-green-900">
                    {rec.action_type}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${getSeverityBadgeClass(rec.priority)}`}>
                    {rec.priority}
                  </span>
                </div>
                <span className="text-xs text-green-800 leading-relaxed text-justify">
                  {rec.description}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}