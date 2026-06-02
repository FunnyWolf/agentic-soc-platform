function SecurityIncidentReport({ value }) {
  let rawData = null;

  if (!value) {
    return <div className="text-gray-500 text-center font-mono">No data</div>;
  }

  if (typeof value === 'string') {
    try {
      rawData = JSON.parse(value);
    } catch (e) {
      throw new Error("Failed to parse JSON data in SecurityIncidentReport");
    }
  } else if (typeof value === 'object' && value !== null) {
    rawData = value;
  } else {
    throw new Error("Invalid data type for SecurityIncidentReport");
  }

  const report = rawData.report || {};

  const getSeverityBadgeClass = (level) => {
    if (level === 'High' || level === 'Critical') {
      return 'bg-red-500/10 text-red-400 border-red-500/30';
    }
    if (level === 'Medium') {
      return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    }
    if (level === 'Low') {
      return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    }
    return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
  };

  const getVerdictBadgeClass = (verdict) => {
    if (verdict === 'True Positive') {
      return 'bg-red-500/10 text-red-400 border-red-500/30';
    }
    if (verdict === 'Suspicious') {
      return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    }
    if (verdict === 'False Positive') {
      return 'bg-green-500/10 text-green-400 border-green-500/30';
    }
    return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
  };

  const formatLocalTime = (utcString) => {
    if (!utcString) return 'N/A';
    const date = new Date(utcString);
    if (isNaN(date.getTime())) {
      return utcString;
    }
    return date.toLocaleString();
  };

  return (
    <div className="flex flex-col gap-6 w-full h-full overflow-y-auto bg-[#161616] text-gray-300 font-sans">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-gray-500 font-mono shrink-0">
        <div className="flex items-center gap-1.5">
          <LucideIcon name="PlayCircle" size="14" />
          <span>Started: {formatLocalTime(rawData.analysis_last_started_at)}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <LucideIcon name="CheckCircle2" size="14" />
          <span>Completed: {formatLocalTime(rawData.analysis_last_completed_at)}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 shrink-0">
        <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border ${getVerdictBadgeClass(report.verdict)}`}>
          <span className="text-[10px] uppercase tracking-wider opacity-80 mb-0.5">Verdict</span>
          <span className="text-sm font-bold text-center leading-tight">{report.verdict}</span>
        </div>
        <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border ${getSeverityBadgeClass(report.severity)}`}>
          <span className="text-[10px] uppercase tracking-wider opacity-80 mb-0.5">Severity</span>
          <span className="text-sm font-bold text-center leading-tight">{report.severity}</span>
        </div>
        <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border ${getSeverityBadgeClass(report.impact)}`}>
          <span className="text-[10px] uppercase tracking-wider opacity-80 mb-0.5">Impact</span>
          <span className="text-sm font-bold text-center leading-tight">{report.impact}</span>
        </div>
        <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border ${getSeverityBadgeClass(report.priority)}`}>
          <span className="text-[10px] uppercase tracking-wider opacity-80 mb-0.5">Priority</span>
          <span className="text-sm font-bold text-center leading-tight">{report.priority}</span>
        </div>
        <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border ${getSeverityBadgeClass(report.confidence)}`}>
          <span className="text-[10px] uppercase tracking-wider opacity-80 mb-0.5">Confidence</span>
          <span className="text-sm font-bold text-center leading-tight">{report.confidence}</span>
        </div>
      </div>

      <div className="bg-[#1e1e1e] p-5 rounded-lg border border-gray-800 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 mb-3">
          <LucideIcon name="FileText" size="18" className="text-gray-400" />
          Incident Digest
        </h3>
        <p className="text-sm text-gray-400 leading-relaxed text-justify">
          {report.digest}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 shrink-0">
        <div className="flex flex-col gap-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
            <LucideIcon name="Server" size="18" className="text-blue-400" />
            Affected Assets
          </h3>
          <div className="flex flex-col gap-2">
            {Array.isArray(report.affected_assets) && report.affected_assets.map((asset, index) => (
              <div key={index} className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-[#1a1a1a] rounded-md border border-gray-800 gap-2">
                <span className="text-[11px] font-bold text-gray-400 px-2 py-1 bg-[#222] border border-gray-700 rounded whitespace-nowrap w-max">
                  {asset.asset_type}
                </span>
                <span className="text-xs text-gray-300 font-mono break-all sm:text-right">
                  {asset.asset_value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
            <LucideIcon name="Target" size="18" className="text-red-400" />
            IOC Indicators
          </h3>
          <div className="flex flex-col gap-2">
            {Array.isArray(report.ioc_indicators) && report.ioc_indicators.map((ioc, index) => (
              <div key={index} className="p-3 bg-red-500/5 rounded-md border border-red-500/20 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-bold text-red-400 px-2 py-0.5 bg-red-500/10 rounded">
                    {ioc.indicator_type}
                  </span>
                  <span className="text-sm font-mono text-red-400 font-bold">
                    {ioc.value}
                  </span>
                </div>
                <span className="text-xs text-red-300/70 leading-normal">
                  {ioc.context}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
          <LucideIcon name="Search" size="18" className="text-cyan-400" />
          Evidence Findings
        </h3>
        <div className="grid grid-cols-1 gap-4">
          {Array.isArray(report.evidence_findings) && report.evidence_findings.map((finding, index) => (
            <div key={index} className="flex flex-col gap-3 p-4 bg-[#1a1a1a] rounded-lg border border-gray-800">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 border-b border-gray-800 pb-2">
                <span className="text-sm font-bold text-gray-200">{finding.title}</span>
                <span className="text-[10px] font-bold text-cyan-400 px-2 py-0.5 bg-cyan-500/10 border border-cyan-500/20 rounded uppercase tracking-wider w-max shrink-0">
                  {finding.finding_type}
                </span>
              </div>
              <div className="flex flex-col gap-2 text-xs">
                <div className="flex gap-2">
                  <span className="font-bold text-gray-500 shrink-0 w-20">Subject:</span>
                  <span className="text-gray-300">{finding.subject}</span>
                </div>
                <div className="flex gap-2">
                  <span className="font-bold text-gray-500 shrink-0 w-20">Evidence:</span>
                  <span className="text-gray-400 font-mono bg-[#111] px-1.5 py-0.5 rounded border border-[#222] break-all">{finding.evidence}</span>
                </div>
                <div className="flex gap-2 mt-1">
                  <span className="font-bold text-gray-500 shrink-0 w-20">Conclusion:</span>
                  <span className="text-gray-300 font-medium leading-relaxed">{finding.conclusion}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
          <LucideIcon name="GitMerge" size="18" className="text-indigo-400" />
          Attack Chain
        </h3>
        <div className="flex flex-col gap-3">
          {Array.isArray(report.attack_chain) && report.attack_chain.map((chain, index) => (
            <div key={index} className="flex flex-col gap-2 p-4 bg-indigo-500/5 rounded-lg border border-indigo-500/20">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded">
                  Stage
                </span>
                <span className="text-sm font-bold text-indigo-300">
                  {chain.attack_stage}
                </span>
              </div>
              <p className="text-sm text-gray-400 leading-relaxed text-justify">
                {chain.description}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
          <LucideIcon name="Clock" size="18" className="text-purple-400" />
          Timeline
        </h3>
        <div className="relative border-l-2 border-purple-500/30 ml-3 pl-5 py-2 flex flex-col gap-8">
          {Array.isArray(report.attack_timeline) && report.attack_timeline.map((event, index) => (
            <div key={index} className="relative">
              <div className="absolute -left-[26px] top-1 w-3 h-3 rounded-full bg-purple-500 ring-4 ring-[#161616]"></div>
              <div className="text-[11px] font-bold font-mono text-purple-400 mb-1">
                {formatLocalTime(event.timestamp)}
              </div>
              <div className="text-sm text-gray-200 font-medium mb-2 leading-relaxed">
                {event.attack_behavior}
              </div>
              <div className="text-[11px] text-gray-400 bg-[#1a1a1a] p-2.5 rounded-md border border-gray-800 font-mono break-all mt-1">
                {event.evidence_field}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
          <LucideIcon name="HelpCircle" size="18" className="text-orange-400" />
          Unknowns
        </h3>
        <div className="bg-orange-500/5 p-4 rounded-lg border border-orange-500/20">
          <ul className="list-disc list-outside ml-4 flex flex-col gap-2">
            {Array.isArray(report.unknowns) && report.unknowns.map((item, index) => (
              <li key={index} className="text-sm text-orange-300/90 leading-relaxed">
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-2 shrink-0">
        <h3 className="flex items-center gap-2 text-sm font-bold text-gray-200 border-b border-gray-800 pb-2">
          <LucideIcon name="Wrench" size="18" className="text-green-400" />
          Remediation Recommendations
        </h3>
        <div className="grid grid-cols-1 gap-3">
          {Array.isArray(report.remediations) && report.remediations.map((rec, index) => (
            <div key={index} className="flex gap-4 p-4 bg-green-500/5 rounded-lg border border-green-500/20">
              <LucideIcon name="CheckCircle" size="20" className="text-green-500 shrink-0 mt-0.5" />
              <div className="flex flex-col gap-1.5 w-full">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-green-400">
                    {rec.action_type}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${getSeverityBadgeClass(rec.priority)}`}>
                    {rec.priority}
                  </span>
                </div>
                <span className="text-xs text-green-300/80 leading-relaxed text-justify">
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