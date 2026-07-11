from dataclasses import dataclass
from typing import Any

from django.utils import timezone

from apps.agentic.analysis.knowledge import build_knowledge_context
from apps.agentic.analysis.profiles import AI_PROFILE_VERSION, serialize_case_for_investigation
from apps.agentic.analysis.prompts import INVESTIGATION_SYSTEM_PROMPT, invoke_structured_llm
from apps.agentic.analysis.schemas import AnalysisRecord, InvestigationReport
from apps.agentic.services.cases import save_case_analysis_record


@dataclass(frozen=True)
class CaseAnalysisRequest:
    case: Any
    trigger: str
    user_input: str = ""
    source: Any = None


@dataclass(frozen=True)
class AnalysisResult:
    report: InvestigationReport
    analysis_record: dict


def generate_investigation_report(analysis_input):
    return invoke_structured_llm(
        prompt_id=INVESTIGATION_SYSTEM_PROMPT,
        payload=analysis_input,
        output_schema=InvestigationReport,
    )


def _source_identity(source):
    if source is None:
        return "", ""
    model_name = source._meta.model_name if hasattr(source, "_meta") else type(source).__name__
    return model_name, str(getattr(source, "pk", ""))


@dataclass(frozen=True)
class CaseAnalysisRunner:
    def run(self, request: CaseAnalysisRequest):
        case_payload = serialize_case_for_investigation(request.case)
        knowledge_context = build_knowledge_context(case_payload)
        analysis_input = self._build_analysis_input(
            case_payload=case_payload,
            knowledge_context=knowledge_context,
            user_input=request.user_input,
        )

        report = generate_investigation_report(analysis_input)
        record = self._build_analysis_record(
            request=request,
            knowledge_context=knowledge_context,
            report=report,
        )
        save_case_analysis_record(case=request.case, record=record)
        return AnalysisResult(report=report, analysis_record=record.model_dump())

    def _build_analysis_input(self, *, case_payload, knowledge_context, user_input):
        analysis_input = {
            "case": case_payload,
            "knowledge": knowledge_context.as_payload(),
        }
        if user_input:
            analysis_input["user_input"] = user_input
        return analysis_input

    def _build_analysis_record(self, *, request, knowledge_context, report):
        source_type, source_id = _source_identity(request.source)
        return AnalysisRecord(
            trigger=request.trigger,
            source_type=source_type,
            source_id=source_id,
            profile_version=AI_PROFILE_VERSION,
            generated_at=timezone.now().isoformat(),
            knowledge_keywords=knowledge_context.keywords,
            knowledge_records=knowledge_context.records,
            report=report,
        )


def run_case_analysis(*, case, trigger, user_input="", source=None):
    request = CaseAnalysisRequest(
        case=case,
        trigger=trigger,
        user_input=user_input,
        source=source,
    )
    return CaseAnalysisRunner().run(request)
