import json
from typing import List

from Lib.api import get_current_time_str
from Lib.basemodule import BaseModule
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpmodel import (
    AlertModel, ArtifactModel, ArtifactType, ArtifactRole, Severity,
    AlertStatus, AlertAnalyticType, ProductCategory, Confidence,
    ImpactLevel, AlertRiskLevel, Disposition, AlertAction,
    AlertPolicyType, CaseModel, CaseStatus, CasePriority
)


class Module(BaseModule):
    THREAD_NUM = 2

    def __init__(self):
        super().__init__()

    def run(self):
        # 获取原始告警JSON
        raw_alert = self.read_message()

        # 1. 尽可能解析所有字段 (Extraction)
        event_time = raw_alert.get("eventTime", raw_alert.get("@timestamp", ""))
        event_id = raw_alert.get("eventID", "")
        aws_region = raw_alert.get("awsRegion", "")
        source_ip = raw_alert.get("sourceIPAddress", "0.0.0.0")
        user_agent = raw_alert.get("userAgent", "Unknown")

        # 用户身份信息
        user_identity = raw_alert.get("userIdentity", {})
        principal_type = user_identity.get("type", "")
        principal_user = user_identity.get("userName", "unknown-user")
        principal_arn = user_identity.get("arn", "")
        principal_id = user_identity.get("principalId", "")
        access_key_id = user_identity.get("accessKeyId", "")
        account_id = user_identity.get("accountId", raw_alert.get("recipientAccountId", raw_alert.get("cloud.account.id", "")))

        # 请求参数
        request_params = raw_alert.get("requestParameters", {})
        target_user = request_params.get("userName", "unknown-target")
        policy_arn = request_params.get("policyArn", "")
        policy_name = policy_arn.split('/')[-1] if policy_arn else "UnknownPolicy"

        # 响应与错误
        error_code = raw_alert.get("errorCode")
        error_message = raw_alert.get("errorMessage")
        outcome = raw_alert.get("event.outcome", "success" if not error_code else "failure")

        # 严重程度映射
        risk_score = raw_alert.get("event.risk_score", 80)
        log_level = raw_alert.get("log.level", "warning")

        severity_map = {
            "critical": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.HIGH,
            "info": Severity.LOW,
        }
        severity = severity_map.get(log_level.lower(), Severity.HIGH)

        # 处置结果判定
        if error_code == "UnauthorizedOperation":
            disposition = Disposition.UNAUTHORIZED
            action = AlertAction.DENIED
        elif error_code:
            disposition = Disposition.ERROR
            action = AlertAction.OTHER
        else:
            disposition = Disposition.DETECTED
            action = AlertAction.OBSERVED

        event_time_formatted = event_time if event_time else get_current_time_str()

        # 2. 提取符合标准的 Artifact (Artifact Extraction)
        artifacts: List[ArtifactModel] = []

        # 主体身份
        if principal_user:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_NAME, role=ArtifactRole.ACTOR, value=principal_user, name="Principal User"))
        if principal_arn:
            artifacts.append(ArtifactModel(type=ArtifactType.RESOURCE_UID, role=ArtifactRole.ACTOR, value=principal_arn, name="Principal ARN"))
        if access_key_id:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_CREDENTIAL_ID, role=ArtifactRole.ACTOR, value=access_key_id, name="Access Key ID"))

        # 目标与环境
        if target_user:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_NAME, role=ArtifactRole.TARGET, value=target_user, name="Target User"))
        if source_ip:
            artifacts.append(ArtifactModel(type=ArtifactType.IP_ADDRESS, role=ArtifactRole.ACTOR, value=source_ip, name="Source IP"))
        if user_agent:
            artifacts.append(ArtifactModel(type=ArtifactType.HTTP_USER_AGENT, role=ArtifactRole.OTHER, value=user_agent, name="User Agent"))
        if policy_arn:
            artifacts.append(ArtifactModel(type=ArtifactType.RESOURCE_UID, role=ArtifactRole.RELATED, value=policy_arn, name="Attached Policy ARN"))
        if account_id:
            artifacts.append(ArtifactModel(type=ArtifactType.ACCOUNT, role=ArtifactRole.RELATED, value=account_id, name="AWS Account ID"))

        # 3. 计算 correlation_uid (Correlation Logic)
        # 选择 [主体用户, 目标用户, 账号] 作为聚合键，这能有效捕获针对特定目标的持续攻击
        rule_id = self.module_name
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=rule_id,
            time_window="24h",
            keys=[principal_user, target_user, account_id],
            timestamp=event_time_formatted
        )

        # 4. 组装 Alert (Alert Assembly)
        status_detail = f"Outcome: {outcome}"
        if error_code:
            status_detail += f" ({error_code}: {error_message})"

        alert_model = AlertModel(
            title=f"AWS IAM PrivyEsc: {principal_user} attempted to attach {policy_name} to {target_user}",
            severity=severity,
            status=AlertStatus.NEW,
            status_detail=status_detail,
            disposition=disposition,
            action=action,
            rule_id=rule_id,
            rule_name="AWS IAM Privilege Escalation via AttachUserPolicy",
            source_uid=event_id,
            correlation_uid=correlation_uid,
            count=1,
            analytic_type=AlertAnalyticType.RULE,
            analytic_name="CloudTrail IAM Security Rule",
            analytic_desc="Detects AttachUserPolicy API calls which can be used for privilege escalation or maintaining persistence.",
            product_category=ProductCategory.CLOUD,
            product_name="AWS CloudTrail",
            product_vendor="Amazon AWS",
            product_feature="IAM Auditing",
            first_seen_time=event_time_formatted,
            last_seen_time=event_time_formatted,
            desc=f"User {principal_user} ({principal_type}) initiated an AttachUserPolicy request for target user {target_user} in account {account_id}. "
                 f"Policy: {policy_arn or 'N/A'}. Source IP: {source_ip}.",
            data_sources=["aws.cloudtrail"],
            labels=["aws", "iam", "privilege-escalation", f"account:{account_id}", outcome],
            raw_data=json.dumps(raw_alert),
            unmapped=json.dumps({
                "errorCode": error_code,
                "errorMessage": error_message,
                "userAgent": user_agent,
                "awsRegion": aws_region,
                "principalId": principal_id,
                "requestID": raw_alert.get("requestID")
            }),
            tactic="Privilege Escalation",
            technique="T1098 - Account Manipulation",
            sub_technique="T1098.003 - Additional Cloud Credentials",
            mitigation="Implement Least Privilege, Use Permission Boundaries, Monitor for sensitive IAM API calls.",
            policy_type=AlertPolicyType.IDENTITY_POLICY,
            impact=ImpactLevel.CRITICAL if outcome == "success" else ImpactLevel.MEDIUM,
            confidence=Confidence.HIGH,
            risk_level=AlertRiskLevel.HIGH if outcome == "success" else AlertRiskLevel.MEDIUM,
            risk_details=f"High risk of administrative takeover if the attached policy contains broad permissions. "
                         f"Current status is {outcome}."
        )
        alert_model.artifacts = artifacts

        # 保存告警
        saved_alert_rowid = Alert.create(alert_model)
        self.logger.info(f"Alert created: {saved_alert_rowid} with disposition {disposition}")

        # 5. Case 处理 (Case Management)
        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
            if existing_case:
                # 附加到已有 Case
                update_case = CaseModel(
                    alerts=[*existing_case.alerts, saved_alert_rowid],
                    rowid=existing_case.rowid
                )
                Case.update(update_case)
            else:
                new_case = CaseModel(
                    title=f"Potential IAM Privilege Escalation in Account {account_id}",
                    severity=severity,
                    impact=ImpactLevel.HIGH if outcome == "success" else ImpactLevel.MEDIUM,
                    priority=CasePriority.HIGH if outcome == "success" else CasePriority.MEDIUM,
                    confidence=Confidence.HIGH,
                    status=CaseStatus.NEW,
                    description=f"Investigation required for multiple AttachUserPolicy attempts by {principal_user} "
                                f"targeting {target_user} in account {account_id}.",
                    category=ProductCategory.CLOUD,
                    tags=["iam", "aws", "privesc"],
                    correlation_uid=correlation_uid,
                    alerts=[saved_alert_rowid]
                )
                Case.create(new_case)
        except Exception as e:
            self.logger.error(f"Case operation failed: {str(e)}")

        return True


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    module = Module()
    module.debug_message_id = "1776309110403-0"
    module.run()
