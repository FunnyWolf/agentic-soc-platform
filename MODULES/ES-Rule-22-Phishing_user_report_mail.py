import json
import textwrap
from typing import Optional, Union, Dict, Any

from pydantic import BaseModel, Field

from Lib.api import string_to_string_time, get_current_time_str
from Lib.basemodule import BaseModule
from PLUGINS.Dify.dify import Dify
from PLUGINS.SIRP.grouprule import GroupRule
from PLUGINS.SIRP.sirpapi import create_alert_with_group_rule, InputAlert


class AnalyzeResult(BaseModel):
    """Structure for extracting user information from text"""
    is_phishing: bool = Field(description="Whether it is a phishing email, True or False")
    confidence: float = Field(description="Confidence score, range between 0 and 1")
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="Reasoning process", default=None)


class Module(BaseModule):

    def __init__(self):
        super().__init__()

    def alert_preprocess_node(self):
        """Preprocess alert data"""
        # Get raw alert from stream
        alert = self.read_message()
        if alert is None:
            return None

        # Parse data, this is an example of handling JSON data sent by Splunk Webhook
        # alert = json.loads(alert["_raw"])

        headers = alert["headers"]
        headers = {"From": headers["From"], "To": headers["To"], "Subject": headers["Subject"], "Date": headers["Date"],
                   "Return-Path": headers["Return-Path"],
                   "Authentication-Results": headers["Authentication-Results"]}
        alert["headers"] = headers

        self.agent_state.alert_raw = alert
        return None

    def alert_analyze_node(self):
        client = Dify()
        api_key = client.get_dify_api_key(self.module_name)
        inputs = {
            "alert": json.dumps(self.agent_state.alert_raw)
        }

        result = client.run_workflow(
            api_key=api_key,
            inputs=inputs,
            user=self.module_name
        )
        self.agent_state.analyze_result = result.get("analyze_result")
        return

    def alert_output_node(self):
        """Process analysis results"""
        analyze_result: AnalyzeResult = AnalyzeResult(**self.agent_state.analyze_result)
        alert_raw = self.agent_state.alert_raw

        mail_to = alert_raw["headers"]["To"]
        mail_subject = alert_raw["headers"]["Subject"]
        mail_from = alert_raw["headers"]["From"]
        if analyze_result.is_phishing and analyze_result.confidence > 0.8:
            severity = "High"
        else:
            severity = "Info"

        alert_date = string_to_string_time(alert_raw.get("@timestamp"), "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
        description = f"""
                        ## Analyze Result (AI)

                        * **confidence**: {analyze_result.confidence}
                        * **is_phishing**: <font color="green">{analyze_result.is_phishing}</font>
                        """
        description = textwrap.dedent(description).strip()

        rule_name = "User Reported Phishing Email"
        input_alert: InputAlert = {
            "source": "Email",
            "rule_id": self.module_name,
            "rule_name": rule_name,
            "name": f"User Reported Phishing Email: {mail_subject}",
            "alert_date": alert_date,
            "created_date": get_current_time_str(),
            "tags": ["phishing", "user-report"],
            "severity": severity,
            "description": description,
            "reference": "https://your-siem-or-device-url.com/data?source=123456",
            "summary_ai": analyze_result.reasoning,
            "artifact": [
                {
                    "type": "mail_to",
                    "value": mail_to,
                    "enrichment": {"update_time": get_current_time_str()}  # just for test, no meaning, data should come from TI or other cmdb
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
            "raw_log": alert_raw
        }
        workbook = self.load_markdown_template("PHISHING_L2_WORKBOOK").format()
        rule = GroupRule(
            rule_id=self.module_name,
            rule_name=rule_name,
            deduplication_fields=["mail_from"],
            source="Email",
            workbook=workbook,
        )
        case_row_id = create_alert_with_group_rule(input_alert, rule)

        return

    def run(self):
        self.alert_preprocess_node()
        self.alert_analyze_node()
        self.alert_output_node()


if __name__ == "__main__":
    module = Module()
    module.debug_message_id = "0-0"
    module.run()
