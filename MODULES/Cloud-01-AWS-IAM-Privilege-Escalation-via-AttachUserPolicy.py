import json
from datetime import datetime
from typing import Optional, Union, Dict, Any, List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from pydantic import BaseModel, Field

from Lib.api import get_current_time_str
from Lib.basemodule import LanggraphModule
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import AlertModel, ArtifactModel, ArtifactType, ArtifactRole, Severity, AlertStatus, AlertAnalyticType, ProductCategory, Confidence, \
    ImpactLevel, AlertRiskLevel, Disposition, AlertAction, AlertPolicyType


class AnalyzeResult(BaseModel):
    """Structure for extracting C2 communication analysis result"""
    original_severity: Severity = Field(description="Original alert severity", default=Severity.UNKNOWN)
    new_severity: Severity = Field(description="Recommended new severity level", default=Severity.UNKNOWN)
    confidence: Confidence = Field(description="Confidence level assessment", default=Confidence.UNKNOWN)
    analysis_rationale: str = Field(description="Analysis process and reasons", default=None)
    attack_stage: Optional[Union[str, Dict[str, Any]]] = Field(description="e.g., 'T1071 - Application Layer Protocol', 'Command and Control'", default=None)
    recommended_actions: Optional[Union[str, Dict[str, Any]]] = Field(description="e.g., 'Isolate host 10.1.1.5'", default=None)


class AgentState(BaseAgentState):
    analyze_result: AnalyzeResult = None


class Module(LanggraphModule):
    THREAD_NUM = 2

    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        def alert_preprocess_node(state: AgentState):
            """
            Read one alert from Redis Stream and preprocess into AlertModel.
            Extract artifacts and create AlertModel with proper structure.
            """
            raw_message = self.read_message()
            if raw_message is None:
                return Command(update={}, goto=END)

            alert_raw = raw_message

            event_name = alert_raw.get("eventName", "AttachUserPolicy")
            event_time = alert_raw.get("eventTime", alert_raw.get("@timestamp", ""))
            rule_name = "AWS IAM Privilege Escalation via AttachUserPolicy"

            user_identity = alert_raw.get("userIdentity", {})
            principal_user = user_identity.get("userName", "unknown-user")
            principal_arn = user_identity.get("arn", "unknown-arn")
            principal_id = user_identity.get("principalId", "unknown-id")
            access_key_id = user_identity.get("accessKeyId", "unknown-key")

            request_params = alert_raw.get("requestParameters", {})
            target_user = request_params.get("userName", "unknown-target")
            policy_arn = request_params.get("policyArn", "unknown-policy")

            source_ip = alert_raw.get("sourceIPAddress", "unknown-ip")
            aws_region = alert_raw.get("awsRegion", "unknown-region")
            account_id = alert_raw.get("recipientAccountId", alert_raw.get("cloud.account.id", "unknown-account"))
            user_agent = alert_raw.get("userAgent", "unknown-agent")
            event_id = alert_raw.get("eventID", "")

            risk_score = alert_raw.get("event.risk_score", alert_raw.get("risk_score", 100))
            log_level = alert_raw.get("log.level", "critical")
            message = alert_raw.get("message", "")

            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFORMATIONAL,
            }
            severity = severity_map.get(log_level.lower(), Severity.CRITICAL)

            event_time_formatted = event_time if event_time else get_current_time_str()

            correlation_uid = f"{account_id}-{principal_user}-{target_user}-{event_id}"

            alert_model = AlertModel(
                title=f"AWS IAM Privilege Escalation: {principal_user} attached {policy_arn.split('/')[-1]} to {target_user}",
                src_url=f"AWS CloudTrail - Event ID: {event_id}",
                severity=severity,
                status=AlertStatus.NEW,
                status_detail="New alert received from AWS CloudTrail - awaiting analysis",
                disposition=Disposition.DETECTED,
                action=AlertAction.OBSERVED,
                rule_id=self.module_name,
                rule_name=rule_name,
                source_uid=event_id,
                correlation_uid=correlation_uid,
                count=1,
                analytic_type=AlertAnalyticType.BEHAVIORAL,
                analytic_name="AWS IAM Behavioral Anomaly Detection",
                analytic_desc="Detects suspicious IAM policy attachment operations that indicate privilege escalation attempts or backdoor account creation",
                analytic_state=None,
                product_category=ProductCategory.CLOUD,
                product_name="AWS CloudTrail",
                product_vendor="Amazon AWS",
                product_feature="CloudTrail Logging",
                first_seen_time=event_time_formatted,
                last_seen_time=event_time_formatted,
                desc=message or f"IAM user {principal_user} attached policy {policy_arn} to user {target_user} in account {account_id}",
                data_sources=["AWS CloudTrail"],
                labels=["iam-privilege-escalation", "aws-cloudtrail", f"account-{account_id}"],
                raw_data=json.dumps(alert_raw),
                unmapped=json.dumps({
                    "userAgent": user_agent,
                    "awsRegion": aws_region,
                    "requestID": alert_raw.get("requestID", ""),
                    "eventVersion": alert_raw.get("eventVersion", "")
                }),
                tactic="T1098.003 - AWS IAM Account Manipulation",
                technique="Privilege Escalation",
                sub_technique="Create IAM Access Keys",
                mitigation="Enable IAM access analyzer, enforce MFA, use service control policies to restrict policy attachment",
                policy_name="AWS IAM Access Policy",
                policy_type=AlertPolicyType.IDENTITY_POLICY,
                policy_desc="IAM identity-based policy that grants permissions to AWS services",
                impact=ImpactLevel.CRITICAL if severity in [Severity.CRITICAL, Severity.HIGH] else ImpactLevel.HIGH,
                confidence=Confidence.HIGH,
                risk_level=AlertRiskLevel.CRITICAL if severity == Severity.CRITICAL else AlertRiskLevel.HIGH,
                risk_details=f"Unauthorized administrator policy attached to {target_user} - potential backdoor account creation or privilege escalation attack"
            )

            artifacts: List[ArtifactModel] = []

            artifacts.append(ArtifactModel(
                type=ArtifactType.USER,
                role=ArtifactRole.ACTOR,
                value=principal_user,
                name="Principal User"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.ACTOR,
                value=principal_arn,
                name="Principal ARN"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.USER,
                role=ArtifactRole.TARGET,
                value=target_user,
                name="Target User"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.IP_ADDRESS,
                role=ArtifactRole.ACTOR,
                value=source_ip,
                name="Source IP"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.RELATED,
                value=policy_arn,
                name="Policy ARN"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.RELATED,
                value=account_id,
                name="AWS Account ID"
            ))

            if access_key_id and access_key_id != "unknown-key":
                artifacts.append(ArtifactModel(
                    type=ArtifactType.OTHER,
                    role=ArtifactRole.ACTOR,
                    value=access_key_id,
                    name="Access Key ID"
                ))

            alert_model.artifacts = artifacts
            return {"alert": alert_model}

        def alert_analyze_node(state: AgentState):
            """
            Analyze the alert using AI (LLM) with structured few-shot examples for AWS IAM privilege escalation detection.
            Leverages threat intelligence and cloud behavior patterns.
            """
            system_prompt_template = self.load_system_prompt_template("senior_cloud_security_expert")

            current_date = datetime.now().strftime("%Y-%m-%d")
            system_message = system_prompt_template.format(current_date=current_date)

            few_shot_examples = [
            ]

            alert = state.alert
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=alert.model_dump_json_for_ai()),
            ]

            llm_api = LLMAPI()
            llm = llm_api.get_model(tag=["fast", "structured_output"])
            llm_structured = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm_structured.invoke(messages)

            state.analyze_result = response
            return state

        def alert_output_node(state: AgentState):
            """
            Save analysis result to AlertModel and persist using SIRP API.
            Updates severity, confidence, and enriches with AI-generated insights.
            """
            alert_model: AlertModel = state.alert
            analyze_result: AnalyzeResult = state.analyze_result

            alert_model.severity = analyze_result.new_severity
            alert_model.confidence = analyze_result.confidence
            alert_model.summary_ai = str(analyze_result.analysis_rationale)

            if analyze_result.recommended_actions:
                alert_model.remediation = str(analyze_result.recommended_actions)

            labels = list(alert_model.labels) if alert_model.labels else []
            if analyze_result.attack_stage and analyze_result.confidence in [Confidence.HIGH, Confidence.MEDIUM]:
                labels.append("confirmed-privilege-escalation")
                if analyze_result.new_severity in [Severity.CRITICAL, Severity.HIGH]:
                    labels.append("high-priority-incident")
            alert_model.labels = labels

            alert_model.uid = f"iam-priv-esc-{get_current_time_str()}"

            saved_alert = Alert.create(alert_model)

            self.logger.info(
                f"AWS IAM Privilege Escalation Alert saved with ID: {saved_alert}, Severity: {analyze_result.new_severity}, Confidence: {analyze_result.confidence}")

            return state

        workflow = StateGraph(AgentState)

        workflow.add_node("alert_preprocess_node", alert_preprocess_node)
        workflow.add_node("alert_analyze_node", alert_analyze_node)
        workflow.add_node("alert_output_node", alert_output_node)

        workflow.set_entry_point("alert_preprocess_node")
        workflow.add_edge("alert_preprocess_node", "alert_analyze_node")
        workflow.add_edge("alert_analyze_node", "alert_output_node")
        workflow.set_finish_point("alert_output_node")

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    module = Module()
    module.debug_message_id = "1770882717911-0"
    module.run()
