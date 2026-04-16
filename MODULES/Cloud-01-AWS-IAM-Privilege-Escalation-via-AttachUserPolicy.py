import json
from typing import List

from Lib.api import get_current_time_str
from Lib.basemodule import BaseModule
from PLUGINS.SIRP.grouprule import GroupRule, CorrelationConfig
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpmodel import AlertModel, ArtifactModel, ArtifactType, ArtifactRole, Severity, AlertStatus, AlertAnalyticType, ProductCategory, Confidence, \
    ImpactLevel, AlertRiskLevel, Disposition, AlertAction, AlertPolicyType, CaseModel, CaseStatus, CasePriority


class Module(BaseModule):
    THREAD_NUM = 2

    def __init__(self):
        super().__init__()

    def run(self):
        # 获取原始告警JSON
        message = self.read_message()

        alert_raw = message

        # 解析需要的字段
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

        # 提取 artifact

        artifacts: List[ArtifactModel] = [
            ArtifactModel(
                type=ArtifactType.USER,
                role=ArtifactRole.ACTOR,
                value=principal_user,
                name="Principal User"
            ), ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.ACTOR,
                value=principal_arn,
                name="Principal ARN"
            ), ArtifactModel(
                type=ArtifactType.USER,
                role=ArtifactRole.TARGET,
                value=target_user,
                name="Target User"
            ), ArtifactModel(
                type=ArtifactType.IP_ADDRESS,
                role=ArtifactRole.ACTOR,
                value=source_ip,
                name="Source IP"
            ), ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.RELATED,
                value=policy_arn,
                name="Policy ARN"
            ), ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.RELATED,
                value=account_id,
                name="AWS Account ID"
            )
        ]

        if access_key_id and access_key_id != "unknown-key":
            artifacts.append(ArtifactModel(
                type=ArtifactType.OTHER,
                role=ArtifactRole.ACTOR,
                value=access_key_id,
                name="Access Key ID"
            ))

        # 计算 correlation
        correlation_config = CorrelationConfig(
            rule_id=self.module_name,
            time_window="24h",
            keys=[principal_user, target_user, account_id]
        )
        group_rule = GroupRule(config=correlation_config)
        correlation_uid = group_rule.generate_correlation_uid(timestamp=event_time_formatted)

        # 拼装 Alert
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

        alert_model.artifacts = artifacts

        saved_alert_rowid = Alert.create(alert_model)
        alert_model.rowid = saved_alert_rowid

        self.logger.debug(f"Alert created with Rowid: {saved_alert_rowid}")

        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)

            if existing_case is not None:
                self.logger.debug(f"Found existing case with correlation_uid: {correlation_uid}, Case ID: {existing_case.rowid}")

                # 将alert 挂载到已有 case , 也可以根据需求更新 case 其他字段
                update_case = CaseModel(alerts=[*existing_case.alerts, saved_alert_rowid], rowid=existing_case.rowid)
                Case.update(update_case)

                self.logger.debug(f"Alert {saved_alert_rowid} added to existing case {existing_case.rowid}")

            else:
                self.logger.debug(f"No existing case found for correlation_uid: {correlation_uid}, creating new case")

                new_case = CaseModel(
                    title=f"AWS IAM Privilege Escalation: {principal_user} → {target_user}",
                    severity=severity,
                    impact=ImpactLevel.CRITICAL if severity in [Severity.CRITICAL, Severity.HIGH] else ImpactLevel.HIGH,
                    priority=CasePriority.CRITICAL if severity == Severity.CRITICAL else CasePriority.HIGH,
                    confidence=Confidence.HIGH,
                    status=CaseStatus.NEW,
                    description=f"AWS IAM privilege escalation detected: {principal_user} attached {policy_arn} to {target_user}",
                    category=ProductCategory.CLOUD,
                    tags=["iam-privilege-escalation", "aws-cloudtrail", f"account-{account_id}"],
                    correlation_uid=correlation_uid,
                    alerts=[saved_alert_rowid]
                )

                case_uid = Case.create(new_case)
                self.logger.debug(f"New case created with UID: {case_uid}, Alert: {saved_alert_rowid}")

        except Exception as e:
            self.logger.error(f"Error creating/updating case for correlation_uid {correlation_uid}: {str(e)}")

        return True


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    module = Module()
    module.debug_message_id = "1776307910636-0"
    module.run()
