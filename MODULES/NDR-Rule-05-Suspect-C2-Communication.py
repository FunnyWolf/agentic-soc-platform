import json
from datetime import datetime
from typing import Optional, Union, Dict, Any, List

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from pydantic import BaseModel, Field

from Lib.api import get_current_time_str
from Lib.basemodule import LanggraphModule
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import AlertModel, ArtifactModel, ArtifactType, ArtifactRole, Severity, AlertStatus, AlertAnalyticType, ProductCategory, Confidence


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

            artifacts_raw: list = alert_raw.get("artifact", [])
            alert_date: str = alert_raw.get("alert_date", "")
            rule_name = "Suspicious command and control (C2) communication"

            hostname = "unknown-hostname"
            source_ip = "unknown-ip"
            destination_ip = "unknown-ip"
            destination_domain = "unknown-domain"

            for artifact_item in artifacts_raw:
                artifact_type = artifact_item.get("type", "").lower()
                if artifact_type == "hostname":
                    hostname = artifact_item.get("value", hostname)
                elif artifact_type == "source_ip":
                    source_ip = artifact_item.get("value", source_ip)
                elif artifact_type == "destination_ip":
                    destination_ip = artifact_item.get("value", destination_ip)
                elif artifact_type == "destination_domain":
                    destination_domain = artifact_item.get("value", destination_domain)

            tags = alert_raw.get("tags", [])
            severity_str = alert_raw.get("severity", "Medium")
            reference = alert_raw.get("reference", "")
            description = alert_raw.get("description", "")
            raw_log = alert_raw.get("raw_log", {})

            alert_date_formatted = alert_date if alert_date else get_current_time_str()

            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFORMATIONAL,
            }
            severity = severity_map.get(severity_str.lower(), Severity.MEDIUM)

            alert_model = AlertModel(
                title=f"C2 Communication: {hostname} → {destination_domain or destination_ip}",
                src_url=reference,
                severity=severity,
                status=AlertStatus.NEW,
                rule_id=self.module_name,
                rule_name=rule_name,
                source_uid=alert_raw.get("id", ""),
                analytic_type=AlertAnalyticType.BEHAVIORAL,
                product_category=ProductCategory.NDR,
                product_name="Network Detection & Response",
                first_seen_time=alert_date_formatted,
                desc=description,
                data_sources=["NDR"],
                labels=tags + ["c2-communication"],
                raw_data=json.dumps(alert_raw),
                unmapped=json.dumps(raw_log),
                tactic="T1071 - Application Layer Protocol",
                technique="Command and Control"
            )

            artifacts: List[ArtifactModel] = []

            type_role_map = {
                "hostname": (ArtifactType.HOSTNAME, ArtifactRole.ACTOR),
                "source_ip": (ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR),
                "destination_ip": (ArtifactType.IP_ADDRESS, ArtifactRole.TARGET),
                "destination_domain": (ArtifactType.UNIFORM_RESOURCE_LOCATOR, ArtifactRole.TARGET),
                "destination_port": (ArtifactType.PORT, ArtifactRole.RELATED),
                "protocol": (ArtifactType.OTHER, ArtifactRole.RELATED),
            }

            for artifact_item in artifacts_raw:
                artifact_type_str = artifact_item.get("type", "").lower()
                artifact_value = artifact_item.get("value", "")

                if artifact_type_str in type_role_map:
                    artifact_type, artifact_role = type_role_map[artifact_type_str]
                else:
                    artifact_type_upper = artifact_type_str.upper()
                    artifact_type = getattr(ArtifactType, artifact_type_upper, ArtifactType.OTHER)
                    artifact_role = ArtifactRole.RELATED

                artifacts.append(ArtifactModel(
                    type=artifact_type,
                    role=artifact_role,
                    value=artifact_value,
                    name=f"{artifact_type_str}: {artifact_value}"
                ))

            alert_model.artifacts = artifacts
            return {"alert": alert_model}

        def alert_analyze_node(state: AgentState):
            """
            Analyze the alert using AI (LLM) with structured few-shot examples for C2 detection.
            Leverages threat intelligence and network behavior patterns.
            """
            system_prompt_template = self.load_system_prompt_template("senior_ndr_cyber_security_expert")

            current_date = datetime.now().strftime("%Y-%m-%d")
            system_message = system_prompt_template.format(current_date=current_date)

            benign_alert = AlertModel(
                title="Windows Update Check: workstation-01 → 13.91.47.3",
                severity=Severity.LOW,
                status=AlertStatus.NEW,
                rule_id="ndr-detection",
                rule_name="Network Behavior Analysis",
                desc="Legitimate Windows Update service connecting to Microsoft update servers on standard HTTPS port",
                product_category=ProductCategory.NDR,
                product_name="Network Detection & Response",
                analytic_type=AlertAnalyticType.BEHAVIORAL,
                data_sources=["NDR"],
                labels=["windows-update", "legitimate"],
                tactic="General",
                technique="Legitimate Software Updates",
                raw_data=json.dumps({
                    "flow_direction": "outbound",
                    "source_ip": "192.168.1.50",
                    "destination_ip": "13.91.47.3",
                    "destination_port": 443,
                    "protocol": "HTTPS",
                    "bytes_in": 4096,
                    "bytes_out": 2048,
                    "duration_seconds": 60,
                    "threat_intel": "No malicious matches"
                })
            )

            benign_alert.artifacts = [
                ArtifactModel(
                    type=ArtifactType.HOSTNAME,
                    role=ArtifactRole.ACTOR,
                    value="workstation-01",
                    name="Source Hostname"
                ),
                ArtifactModel(
                    type=ArtifactType.IP_ADDRESS,
                    role=ArtifactRole.ACTOR,
                    value="192.168.1.50",
                    name="Source IP"
                ),
                ArtifactModel(
                    type=ArtifactType.IP_ADDRESS,
                    role=ArtifactRole.TARGET,
                    value="13.91.47.3",
                    name="Microsoft Update Server"
                ),
                ArtifactModel(
                    type=ArtifactType.PORT,
                    role=ArtifactRole.RELATED,
                    value="443",
                    name="HTTPS Port"
                ),
            ]

            c2_alert = AlertModel(
                title="C2 Communication: FIN-WKS-JDOE-05 → known-bad.c2.server",
                severity=Severity.CRITICAL,
                status=AlertStatus.NEW,
                rule_id="ndr-c2-detection",
                rule_name="Suspicious C2 Communication Pattern",
                desc="Host FIN-WKS-JDOE-05 maintains persistent beaconing pattern with known C2 server. Multiple indicators: Cobalt Strike signature match, periodic low-volume communication, command execution observed.",
                product_category=ProductCategory.NDR,
                product_name="Network Detection & Response",
                analytic_type=AlertAnalyticType.BEHAVIORAL,
                data_sources=["NDR"],
                labels=["c2-communication", "cobaltstrike", "threat-intel-match"],
                tactic="T1071 - Application Layer Protocol",
                technique="Command and Control",
                raw_data=json.dumps({
                    "flow_direction": "outbound",
                    "source_ip": "192.168.1.101",
                    "destination_ip": "198.51.100.50",
                    "destination_domain": "known-bad.c2.server",
                    "destination_port": 443,
                    "protocol": "HTTPS",
                    "bytes_in": 256,
                    "bytes_out": 128,
                    "duration_seconds": 2,
                    "connection_pattern": "periodic_beaconing",
                    "threat_intel": {
                        "source": "threat-feed-X",
                        "match": "Cobalt Strike C2 server",
                        "confidence": "Very High"
                    }
                })
            )

            c2_alert.artifacts = [
                ArtifactModel(
                    type=ArtifactType.HOSTNAME,
                    role=ArtifactRole.ACTOR,
                    value="FIN-WKS-JDOE-05",
                    name="Infected Hostname"
                ),
                ArtifactModel(
                    type=ArtifactType.IP_ADDRESS,
                    role=ArtifactRole.ACTOR,
                    value="192.168.1.101",
                    name="Infected Source IP"
                ),
                ArtifactModel(
                    type=ArtifactType.IP_ADDRESS,
                    role=ArtifactRole.TARGET,
                    value="198.51.100.50",
                    name="C2 Server IP"
                ),
                ArtifactModel(
                    type=ArtifactType.UNIFORM_RESOURCE_LOCATOR,
                    role=ArtifactRole.TARGET,
                    value="known-bad.c2.server",
                    name="C2 Domain"
                ),
                ArtifactModel(
                    type=ArtifactType.PORT,
                    role=ArtifactRole.RELATED,
                    value="443",
                    name="HTTPS Port (Obfuscation)"
                ),
            ]

            few_shot_examples = [
                HumanMessage(content=benign_alert.model_dump_json_for_ai()),
                AIMessage(
                    content=str(AnalyzeResult(
                        original_severity=Severity.LOW,
                        new_severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        analysis_rationale="Standard Windows Update communication pattern. Legitimate Microsoft IP address, standard HTTPS port, expected byte ratios. No threat intelligence matches. No command execution patterns observed.",
                        attack_stage=None,
                        recommended_actions="No action required. Continue monitoring."
                    ).model_dump())
                ),
                HumanMessage(content=c2_alert.model_dump_json_for_ai()),
                AIMessage(
                    content=str(AnalyzeResult(
                        original_severity=Severity.CRITICAL,
                        new_severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        analysis_rationale="Multiple C2 indicators confirmed: (1) Destination IP/domain matches known Cobalt Strike C2 server, (2) Periodic beaconing pattern observed (5-min intervals, low-volume, consistent byte counts), (3) Non-standard communication protocol/timing for legitimate software, (4) Threat intelligence feeds confirm malicious infrastructure.",
                        attack_stage="T1071 - Application Layer Protocol / Command and Control",
                        recommended_actions="IMMEDIATE: Isolate FIN-WKS-JDOE-05 from network to prevent lateral movement and data exfiltration. Preserve network captures and process memory for forensic analysis. Escalate to incident response team. Check for command execution artifacts, lateral movement, and persistence mechanisms."
                    ).model_dump())
                ),
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
                labels.append("confirmed-c2")
                if analyze_result.new_severity in [Severity.CRITICAL, Severity.HIGH]:
                    labels.append("high-priority-incident")
            alert_model.labels = labels

            alert_model.uid = f"c2-{get_current_time_str()}"

            saved_alert = Alert.create(alert_model)

            self.logger.info(
                f"C2 Communication Alert saved with ID: {saved_alert}, Severity: {analyze_result.new_severity}, Confidence: {analyze_result.confidence}")

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
    module.debug_message_id = "1769500067483-0"
    module.run()
