import json
import textwrap
from datetime import datetime
from typing import Optional, Union, Dict, Any

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from pydantic import BaseModel, Field

from Lib.api import string_to_string_time, get_current_time_str
from Lib.basemodule import LanggraphModule
from Lib.llmapi import AgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIRP.grouprule import GroupRule
from PLUGINS.SIRP.sirpapi import create_alert_with_group_rule, InputAlert


class AnalyzeResult(BaseModel):
    """Structure for extracting user information from text"""
    is_phishing: bool = Field(description="Whether it is a phishing email, True or False")
    confidence: float = Field(description="Confidence score, range between 0 and 1")
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="Reasoning process", default=None)


class Module(LanggraphModule):
    # Number of concurrent worker threads for alert processing
    # Two threads will consume alerts from the Redis stream queue in parallel
    THREAD_NUM = 2

    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        def alert_preprocess_node(state: AgentState):
            """
            Read one alert from Redis Stream and preprocess the data
            Preprocess the raw alert by extracting and filtering email headers.
            """
            # Read raw alert from Redis stream
            alert = self.read_message()
            if alert is None:
                return Command(
                    update={"alert": {}},
                    goto=END
                )

            # Example: For Splunk webhooks, uncomment the following line
            # alert = json.loads(alert["_raw"])

            # Extract email headers from Kibana alert
            # Filter to keep only essential headers for analysis
            headers = alert["headers"]
            headers = {"From": headers["From"], "To": headers["To"], "Subject": headers["Subject"], "Date": headers["Date"],
                       "Return-Path": headers["Return-Path"],
                       "Authentication-Results": headers["Authentication-Results"]}
            alert["headers"] = headers

            # Store the preprocessed alert in workflow state for downstream nodes
            state.alert = alert
            return state

        def alert_analyze_node(state: AgentState):
            """
            Analyze the alert using AI (LLM) with structured few-shot examples for phishing detection.
            """
            # Load system prompt template for senior phishing expert from: DATA/ES-Rule-21-Phishing_user_report_mail/senior_phishing_expert.md
            system_prompt_template = self.load_system_prompt_template(f"senior_phishing_expert")

            # Generate dynamic prompt by injecting current date for temporal context
            current_date = datetime.now().strftime("%Y-%m-%d")
            system_message = system_prompt_template.format(current_date=current_date)

            # Construct few-shot examples to guide LLM analysis with legitimate and malicious email samples
            few_shot_examples = [
                HumanMessage(
                    content=json.dumps({
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
                    })
                ),
                AIMessage(
                    content=str(AnalyzeResult(is_phishing=False, confidence=0.95,
                                              reasoning="The email is from a known colleague within the same organization, discussing a legitimate project.").model_dump())
                ),
                HumanMessage(
                    content=json.dumps({
                        "headers": {
                            "From": "\"Microsoft Support\" <support-noreply@microsft.com>",
                            "To": "\"Valued Customer\" <user@example.com>",
                            "Subject": "紧急：您的账户已被暂停,需要立即验证 Urgent: Your Account is Suspended, Immediate Verification Required",
                            "Date": "Tue, 2 Sep 2025 14:30:10 +0800",
                            "Return-Path": "<bounce-scam@phish-delivery.net>",
                            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=support-noreply@microsft.com; dkim=fail header.d=microsft.com; dmarc=fail (p=REJECT sp=REJECT) header.from=microsft.com",
                        },
                        "body": {
                            "plain_text": "尊敬的用户,\n\n我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.\n\n请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：\n\nhttps://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=... (请注意,这只是显示文本,实际链接是恶意的)\n\n如果您不在24小时内完成验证,您的帐户将被永久锁定.\n\n感谢您的合作.\n\n微软安全团队\n\n---\n\nDear User,\n\nOur system has detected unusual sign-in activity on your account. For your security, we have temporarily suspended your account.\n\nPlease click the link below immediately to verify your identity and restore access:\n\nhttp://secure-login-update-required.com/reset-password?user=user@example.com\n\nIf you do not verify within 24 hours, your account will be permanently locked.\n\nThank you for your cooperation.\n\nThe Microsoft Security Team",
                            "html": "<html><head></head><body><p>尊敬的用户,</p><p>我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.</p><p>请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：</p><p><a href='http://secure-login-update-required.com/reset-password?user=user@example.com'>https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...</a></p><p>如果您不在24小时内完成验证,您的帐户将被永久锁定.</p><p>感谢您的合作.</p><p><b>微软安全团队</b></p></body></html>"
                        },
                        "attachments": [
                            {
                                "filename": "Account_Verification_Form.html",
                                "filepath": "attachments/Account_Verification_Form.html",
                                "content_type": "text/html"
                            }
                        ]
                    })
                ),
                AIMessage(
                    content=str(AnalyzeResult(is_phishing=True, confidence=0.92,
                                              reasoning="The email contains several red flags: the sender's domain is misspelled, the Return-Path is from a suspicious domain, SPF and DKIM checks fail, and the email urges immediate action with threatening language. Additionally, the provided links do not match official Microsoft URLs.").model_dump())
                ),
            ]

            # Assemble complete message chain: system message → few-shot examples → current alert
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(state.alert)),
            ]

            # Invoke LLM with structured output schema for consistent analysis results
            openai_api = LLMAPI()

            llm = openai_api.get_model(tag=["fast", "structured_output"])
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)

            # Store analysis result in state for downstream processing
            state.analyze_result = response.model_dump()
            return state

        def alert_output_node(state: AgentState):
            """
            Use custom grouping rule to send analysis results to SIRP
            Generate alert ticket and send to SIRP for incident tracking and investigation.
            """
            analyze_result: AnalyzeResult = AnalyzeResult(**state.analyze_result)
            alert_raw = state.alert

            mail_to = alert_raw["headers"]["To"]
            mail_subject = alert_raw["headers"]["Subject"]
            mail_from = alert_raw["headers"]["From"]

            # Determine alert severity based on LLM analysis confidence
            if analyze_result.is_phishing and analyze_result.confidence > 0.8:
                severity = "High"
            else:
                severity = "Info"

            # Parse email header date and convert to ISO format
            # Example formats: Splunk timestamp = 2024-10-10T12:34:56.789Z (commented out below)
            # Email RFC2822 date = Tue, 2 Sep 2025 14:30:10 +0800
            alert_date = string_to_string_time(alert_raw.get("headers").get("Date"), "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ")

            # Format alert description with AI analysis results (supports Markdown)
            description = f"""
                #### Analyze Result (AI)

                * **confidence**: {analyze_result.confidence}
                * **is_phishing**: <font color="green">{analyze_result.is_phishing}</font>

                """
            description = textwrap.dedent(description).strip()

            rule_name = "User Reported Phishing Email"
            # Construct alert payload for SIRP ingestion
            input_alert: InputAlert = {
                "source": "Email",
                "rule_id": self.module_name,
                "rule_name": rule_name,
                # Alert title includes a unique identifier for deduplication (sender address)
                "name": f"User Reported Phishing Email: {mail_subject}",
                # Time when the security event occurred (alert occurrence time)
                "alert_date": alert_date,
                # Time when SIRP created this alert record (used to calculate MTTD - Mean Time To Detect)
                "created_date": get_current_time_str(),
                # Tags for alert classification, filtering, and search
                "tags": ["phishing", "user-report"],
                "severity": severity,
                # Alert description supports Markdown formatting
                "description": description,
                # Reference URL pointing to the original alert source system for context
                "reference": "https://your-siem-or-device-url.com/data?source=123456",
                # Unique identifier in source system for alert traceability
                "source_data_identifier": "id-12345678979",
                # Store LLM's analysis reasoning and confidence assessment
                "summary_ai": analyze_result.reasoning,
                # Artifacts: IOCs and key data extracted for correlation, TI lookup, asset mapping
                # Email artifacts: sender, recipient, subject, attachment hashes
                # EDR artifacts: process names, file hashes, hostnames
                # NDR artifacts: source/dest IPs, domains, URLs
                "artifact": [
                    {
                        "type": "mail_to",
                        "value": mail_to,
                        # Enrichment metadata (TI lookup results, asset info, etc.)
                        "enrichment": {"update_time": get_current_time_str()}
                    },
                    {
                        "type": "mail_subject",
                        "value": mail_subject,
                        "enrichment": {"update_time": get_current_time_str()}
                    },
                    {
                        "type": "mail_from",
                        "value": mail_from,
                        "enrichment": {"update_time": get_current_time_str()}
                    },
                ],
                # Store raw alert payload as JSON for full traceability and historical queries
                "raw_log": alert_raw
            }

            # Load investigation workbook for analyst guidance
            # Workbook contains investigation steps and remediation procedures for analysts to follow
            # Located at: DATA/ES-Rule-21-Phishing_user_report_mail/PHISHING_L2_WORKBOOK.md
            workbook = self.load_markdown_template("PHISHING_L2_WORKBOOK").format()

            # Define alert grouping and deduplication rules
            # Alerts with the same mail_from address will be grouped together
            # See GroupRule class documentation for configuration options
            rule = GroupRule(
                rule_id=self.module_name,
                rule_name=rule_name,
                deduplication_fields=["mail_from"],
                source="Email",
                workbook=workbook
            )

            case_row_id = create_alert_with_group_rule(input_alert, rule)
            return state

        # Compile the workflow graph and prepare it for execution
        workflow = StateGraph(AgentState)

        # Register workflow nodes
        workflow.add_node("alert_preprocess_node", alert_preprocess_node)
        workflow.add_node("alert_analyze_node", alert_analyze_node)
        workflow.add_node("alert_output_node", alert_output_node)

        # Define workflow entry point and execution sequence
        workflow.set_entry_point("alert_preprocess_node")
        workflow.add_edge("alert_preprocess_node", "alert_analyze_node")
        workflow.add_edge("alert_analyze_node", "alert_output_node")
        workflow.set_finish_point("alert_output_node")

        # Compile the workflow with checkpoint support for persistence
        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True


# Debug/development helper for testing the module standalone
if __name__ == "__main__":
    module = Module()
    # Set debug_message_id to replay a specific alert from Redis Stream for testing
    # Stream name: ES-Rule-21-Phishing_user_report_mail
    # Message ID "0-0" reads the first message from the stream beginning
    # During development, change debug_message_id to test different alerts and verify module behavior
    module.debug_message_id = "1762331465600-0"
    module.run()
    # Standalone execution: Run this file directly to test module logic without starting the full framework
