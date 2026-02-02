import json
from datetime import datetime
from typing import Optional, Union, Dict, Any, List

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from pydantic import BaseModel, Field

from Lib.api import string_to_string_time, get_current_time_str
from Lib.basemodule import LanggraphModule
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import AlertModel, ArtifactModel, ArtifactType, ArtifactRole, Severity, AlertStatus, AlertAnalyticType, ProductCategory, Confidence


class AnalyzeResult(BaseModel):
    """Structure for extracting phishing analysis result"""
    is_phishing: bool = Field(description="Whether it is a phishing email, True or False", default=False)
    confidence: Confidence = Field(description="Confidence level assessment", default=Confidence.UNKNOWN)
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="Reasoning process", default=None)


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
            Read one alert from Redis Stream and preprocess email data into AlertModel.
            Extract and filter email headers, then create AlertModel with artifacts.
            """
            raw_message = self.read_message()
            if raw_message is None:
                return Command(update={}, goto=END)

            alert_raw = raw_message

            headers = alert_raw.get("headers", {})
            body = alert_raw.get("body", {})
            attachments = alert_raw.get("attachments", [])

            mail_to = headers.get("To", "")
            mail_from = headers.get("From", "")
            mail_subject = headers.get("Subject", "")
            mail_date = headers.get("Date", "")

            alert_date = string_to_string_time(
                mail_date,
                "%a, %d %b %Y %H:%M:%S %z",
                "%Y-%m-%dT%H:%M:%SZ"
            ) if mail_date else get_current_time_str()

            alert_model = AlertModel(
                title=f"User Reported Phishing Email: {mail_subject}",
                severity=Severity.INFORMATIONAL,
                status=AlertStatus.NEW,
                rule_id=self.module_name,
                rule_name="User Reported Phishing Email",
                source_uid=alert_raw.get("id", ""),
                analytic_type=AlertAnalyticType.RULE,
                product_category=ProductCategory.EMAIL,
                product_name="Email Security",
                first_seen_time=alert_date,
                desc=f"Subject: {mail_subject}\nFrom: {mail_from}\nTo: {mail_to}",
                data_sources=["Email"],
                labels=["phishing", "user-report"],
                raw_data=json.dumps(alert_raw)
            )

            artifacts: List[ArtifactModel] = []

            artifacts.append(ArtifactModel(
                type=ArtifactType.EMAIL_ADDRESS,
                role=ArtifactRole.ACTOR,
                value=mail_from,
                name=f"Sender Email: {mail_from}"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.EMAIL_ADDRESS,
                role=ArtifactRole.TARGET,
                value=mail_to,
                name=f"Recipient Email: {mail_to}"
            ))

            artifacts.append(ArtifactModel(
                type=ArtifactType.MESSAGE,
                role=ArtifactRole.RELATED,
                value=mail_subject,
                name=f"Email Subject: {mail_subject}"
            ))

            alert_model.artifacts = artifacts
            return {"alert": alert_model}

        def alert_analyze_node(state: AgentState):
            """
            Analyze the email using AI (LLM) with structured few-shot examples for phishing detection.
            """
            system_prompt_template = self.load_system_prompt_template("senior_phishing_expert")

            current_date = datetime.now().strftime("%Y-%m-%d")
            system_message = system_prompt_template.format(current_date=current_date)

            legitimate_email_data = {
                "headers": {
                    "From": "\"Wang Lei, Project Manager\" <lei.wang@example-corp.com>",
                    "To": "\"Li Na, Marketing Department\" <na.li@example-corp.com>",
                    "Subject": "Project Alpha Weekly Status Report",
                    "Date": "Tue, 2 Sep 2025 10:15:00 +0800",
                    "Return-Path": "lei.wang@example-corp.com",
                    "Authentication-Results": "mx.example-corp.com; spf=pass smtp.mail=lei.wang@example-corp.com;"
                },
                "body": {
                    "plain_text": "Hi Li Na,\n\nPlease find attached the weekly status report for Project Alpha.\n\nThis week, we have completed the initial design phase and are on track to begin development next Monday as planned. Please review the attached document and let me know if you have any feedback before our sync-up meeting on Wednesday.\n\nThanks,\n\nBest Regards\nWang Lei / 王雷\nProject Manager / 项目经理\nTechnology Department / 技术部\nExample Corporation / 示例公司\nMobile: +86 13800138000\nEmail / 邮箱: lei.wang@example-corp.com\n",
                    "html": ""
                },
                "attachments": [
                    {
                        "filename": "Project_Alpha_Weekly_Report_W35.pdf",
                        "filepath": "attachments/Project_Alpha_Weekly_Report_W35.pdf",
                        "content_type": "application/pdf"
                    }
                ]
            }

            legitimate_alert = AlertModel(
                title="Project Alpha Weekly Status Report",
                severity=Severity.INFORMATIONAL,
                status=AlertStatus.NEW,
                rule_id="phishing-detection",
                rule_name="Phishing Detection Rule",
                desc="From: lei.wang@example-corp.com\nTo: na.li@example-corp.com\nSubject: Project Alpha Weekly Status Report",
                product_category=ProductCategory.EMAIL,
                product_name="Email Security",
                analytic_type=AlertAnalyticType.RULE,
                data_sources=["Email"],
                labels=["phishing", "user-report"],
                raw_data=json.dumps(legitimate_email_data)
            )

            legitimate_alert.artifacts = [
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.ACTOR,
                    value="lei.wang@example-corp.com",
                    name="Sender Email"
                ),
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.TARGET,
                    value="na.li@example-corp.com",
                    name="Recipient Email"
                ),
            ]

            phishing_email_data = {
                "headers": {
                    "From": "\"Microsoft Support\" <support-noreply@microsft.com>",
                    "To": "\"Valued Customer\" <user@example.com>",
                    "Subject": "紧急：您的账户已被暂停,需要立即验证 Urgent: Your Account is Suspended, Immediate Verification Required",
                    "Date": "Tue, 2 Sep 2025 14:30:10 +0800",
                    "Return-Path": "<bounce-scam@phish-delivery.net>",
                    "Authentication-Results": "mx.example.com; spf=fail smtp.mail=support-noreply@microsft.com; dkim=fail header.d=microsft.com; dmarc=fail (p=REJECT sp=REJECT) header.from=microsft.com"
                },
                "body": {
                    "plain_text": "尊敬的用户,\n\n我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.\n\n请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：\n\nhttps://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=... (请注意,这只是显示文本,实际链接是恶意的)\n\n如果您不在24小时内完成验证,您的帐户将被永久锁定.\n\n感谢您的合作.\n\n微软安全团队",
                    "html": "<html><head></head><body><p>尊敬的用户,</p><p>我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.</p><p>请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：</p><p><a href='http://secure-login-update-required.com/reset-password?user=user@example.com'>https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...</a></p><p>如果您不在24小时内完成验证,您的帐户将被永久锁定.</p><p>感谢您的合作.</p><p><b>微软安全团队</b></p></body></html>"
                },
                "attachments": [
                    {
                        "filename": "Account_Verification_Form.html",
                        "filepath": "attachments/Account_Verification_Form.html",
                        "content_type": "text/html"
                    }
                ]
            }

            phishing_alert = AlertModel(
                title="紧急：您的账户已被暂停,需要立即验证 Urgent: Your Account is Suspended, Immediate Verification Required",
                severity=Severity.HIGH,
                status=AlertStatus.NEW,
                rule_id="phishing-detection",
                rule_name="Phishing Detection Rule",
                desc="From: support-noreply@microsft.com\nTo: user@example.com\nSubject: 紧急：您的账户已被暂停,需要立即验证",
                product_category=ProductCategory.EMAIL,
                product_name="Email Security",
                analytic_type=AlertAnalyticType.RULE,
                data_sources=["Email"],
                labels=["phishing", "user-report"],
                raw_data=json.dumps(phishing_email_data)
            )

            phishing_alert.artifacts = [
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.ACTOR,
                    value="support-noreply@microsft.com",
                    name="Sender Email (Spoofed)"
                ),
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.TARGET,
                    value="user@example.com",
                    name="Recipient Email"
                ),
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.RELATED,
                    value="bounce-scam@phish-delivery.net",
                    name="Return-Path (Suspicious)"
                ),
                ArtifactModel(
                    type=ArtifactType.URL_STRING,
                    role=ArtifactRole.RELATED,
                    value="http://secure-login-update-required.com/reset-password?user=user@example.com",
                    name="Phishing URL"
                ),
            ]

            few_shot_examples = [
                HumanMessage(content=legitimate_alert.model_dump_json_for_ai()),
                AIMessage(
                    content=str(AnalyzeResult(
                        is_phishing=False,
                        confidence=Confidence.HIGH,
                        reasoning="The email is from a known colleague within the same organization, discussing a legitimate project. SPF and authentication checks pass."
                    ).model_dump())
                ),
                HumanMessage(content=phishing_alert.model_dump_json_for_ai()),
                AIMessage(
                    content=str(AnalyzeResult(
                        is_phishing=True,
                        confidence=Confidence.HIGH,
                        reasoning="Multiple red flags: sender's domain is misspelled (microsft vs microsoft), Return-Path from suspicious domain, SPF and DKIM checks fail, urgent language with threats, and suspicious URL not matching official Microsoft domain."
                    ).model_dump())
                ),
            ]

            alert = state.alert
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(alert.model_dump_json_for_ai())),
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
            """
            alert_model: AlertModel = state.alert
            analyze_result: AnalyzeResult = state.analyze_result

            if analyze_result.is_phishing and analyze_result.confidence in [Confidence.HIGH, Confidence.MEDIUM]:
                alert_model.severity = Severity.HIGH
            else:
                alert_model.severity = Severity.INFORMATIONAL

            alert_model.summary_ai = str(analyze_result.reasoning)
            alert_model.confidence = analyze_result.confidence

            labels = list(alert_model.labels) if alert_model.labels else []
            if analyze_result.is_phishing:
                labels.append("confirmed-phishing")
            alert_model.labels = labels

            alert_model.uid = f"phishing-{get_current_time_str()}"

            saved_alert = Alert.create(alert_model)

            self.logger.info(f"Alert saved with ID: {saved_alert}")

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
    module.debug_message_id = "1769493179937-0"
    module.run()
