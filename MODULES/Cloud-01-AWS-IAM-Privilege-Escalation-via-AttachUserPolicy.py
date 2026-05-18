import json
from typing import List

from dateutil import parser

from Lib.basemodule import BaseModule
from PLUGINS.CMDB.tools import lookup_cmdb_context_tool
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpcoremodel import ArtifactName, ArtifactType, ArtifactRole, Severity, Impact, Disposition, AlertAction, Confidence, AlertAnalyticType, \
    ProductCategory, \
    AlertPolicyType, AlertRiskLevel, AlertStatus, CasePriority, ArtifactModel, AlertModel, CaseModel, EnrichmentModel, EnrichmentType, EnrichmentProvider


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        # 获取原始告警JSON
        raw_alert = self.read_stream_message()

        # 1. 尽可能解析所有字段 (Extraction)
        event_time = raw_alert.get("eventTime", raw_alert.get("@timestamp", ""))
        event_id = raw_alert.get("eventID", "")
        aws_region = raw_alert.get("awsRegion", "")
        source_ip = raw_alert.get("sourceIPAddress", "")
        user_agent = raw_alert.get("userAgent", "")

        user_identity = raw_alert.get("userIdentity", {})
        principal_type = user_identity.get("type", "")
        principal_user = user_identity.get("userName", "")
        principal_arn = user_identity.get("arn", "")
        principal_id = user_identity.get("principalId", "")
        access_key_id = user_identity.get("accessKeyId", "")
        account_id = user_identity.get("accountId", raw_alert.get("recipientAccountId", raw_alert.get("cloud.account.id", "")))

        request_params = raw_alert.get("requestParameters") or {}
        target_user = request_params.get("userName", "")
        policy_arn = request_params.get("policyArn", "")
        policy_name = policy_arn.split('/')[-1] if policy_arn else "UnknownPolicy"

        error_code = raw_alert.get("errorCode")
        error_message = raw_alert.get("errorMessage")
        outcome = raw_alert.get("event.outcome", "")

        # 严重程度映射 (定制化字段处理)
        risk_score_raw = raw_alert.get("event.risk_score", 80)
        try:
            risk_score = float(risk_score_raw)
        except (TypeError, ValueError):
            risk_score = 80.0
        log_level = raw_alert.get("log.level", "warning")

        if risk_score >= 90:
            risk_level = AlertRiskLevel.CRITICAL
        elif risk_score >= 70:
            risk_level = AlertRiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = AlertRiskLevel.MEDIUM
        else:
            risk_level = AlertRiskLevel.LOW

        severity_map = {
            "critical": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.HIGH,
            "info": Severity.LOW,
        }
        severity = severity_map.get(log_level.lower(), Severity.HIGH)

        # 处置结果判定 (定制化字段处理)
        if error_code == "UnauthorizedOperation":
            disposition = Disposition.UNAUTHORIZED
            action = AlertAction.DENIED
        elif error_code:
            disposition = Disposition.ERROR
            action = AlertAction.OTHER
        else:
            disposition = Disposition.DETECTED
            action = AlertAction.MODIFIED

        # 状态计算 (定制化字段处理)
        status_detail = f"Outcome: {outcome}"

        event_time_formatted = parser.parse(event_time)

        # 2. 提取符合标准的 Artifact (Artifact Extraction)
        artifacts: List[ArtifactModel] = []

        # 主体身份
        if principal_user:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_NAME, role=ArtifactRole.ACTOR, value=principal_user, name=ArtifactName.PRINCIPAL_USER))
        if principal_arn:
            artifacts.append(ArtifactModel(type=ArtifactType.RESOURCE_UID, role=ArtifactRole.ACTOR, value=principal_arn, name=ArtifactName.CLOUD_RESOURCE_ARN))
        if principal_id:
            artifacts.append(ArtifactModel(type=ArtifactType.RESOURCE_UID, role=ArtifactRole.ACTOR, value=principal_id, name=ArtifactName.CLOUD_RESOURCE_ID))
        if access_key_id:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_CREDENTIAL_ID, role=ArtifactRole.ACTOR, value=access_key_id, name=ArtifactName.ACCESS_KEY_ID))

        # 目标与环境
        if target_user:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_NAME, role=ArtifactRole.TARGET, value=target_user, name=ArtifactName.TARGET_USER))
        if source_ip:
            artifacts.append(ArtifactModel(type=ArtifactType.IP_ADDRESS, role=ArtifactRole.ACTOR, value=source_ip, name=ArtifactName.SOURCE_IP))
        if user_agent:
            artifacts.append(ArtifactModel(type=ArtifactType.HTTP_USER_AGENT, role=ArtifactRole.OTHER, value=user_agent, name=ArtifactName.HTTP_USER_AGENT))
        if policy_arn:
            artifacts.append(ArtifactModel(type=ArtifactType.RESOURCE_UID, role=ArtifactRole.RELATED, value=policy_arn, name=ArtifactName.IAM_POLICY_ARN))
        if account_id:
            artifacts.append(ArtifactModel(type=ArtifactType.ACCOUNT, role=ArtifactRole.AFFECTED, value=account_id, name=ArtifactName.AWS_ACCOUNT_ID))

        # 2b. CMDB 富化: 为每个 artifact 附加 CMDB 上下文
        for artifact in artifacts:
            if not artifact.type or not artifact.value:
                continue
            cmdb_result = lookup_cmdb_context_tool(artifact.type, artifact.value)
            if cmdb_result.get("supported"):
                cmdb_enrichment = EnrichmentModel(
                    name=f"CMDB: {artifact.name or artifact.type}",
                    type=EnrichmentType.CMDB,
                    provider=EnrichmentProvider.INTERNAL_CMDB,
                    value=artifact.value,
                    desc=f"CMDB context for {artifact.type} {artifact.value}",
                    data=json.dumps(cmdb_result),
                )
                artifact.enrichments = [cmdb_enrichment]

        # 3. 计算 correlation_uid (Correlation Logic)
        # 选择 [账号, 操作者, 目标用户] 作为聚合键，聚合同一主体对同一 IAM 用户的高危策略绑定

        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window="24h",
            keys=[account_id, principal_user, target_user],
            timestamp=event_time_formatted
        )

        # 4. 组装 Alert (Alert Assembly)
        alert_enrichments: List[EnrichmentModel] = []
        if aws_region:
            enrichment_location = EnrichmentModel(name="AWS Region", type=EnrichmentType.GEO_LOCATION, provider=EnrichmentProvider.AWS_CLOUDTRAIL,
                                                  value=aws_region,
                                                  desc="Alert region from raw alert", data=json.dumps({"awsRegion": aws_region}))
            alert_enrichments.append(enrichment_location)

        alert_model = AlertModel(
            title=f"AWS IAM PrivEsc: {principal_user} attached {policy_name} to {target_user}",
            severity=severity,
            status=AlertStatus.NEW,
            status_detail=status_detail,
            disposition=disposition,
            action=action,
            rule_id=self.module_name,
            rule_name="AWS IAM Privilege Escalation via AttachUserPolicy",
            source_uid=event_id,
            correlation_uid=correlation_uid,
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
                "awsRegion": aws_region,
                "principalId": principal_id,
                "requestID": raw_alert.get("requestID")
            }),
            tactic="Privilege Escalation",
            technique="T1098 - Account Manipulation",
            sub_technique="T1098.003 - Additional Cloud Credentials",
            mitigation="Implement Least Privilege, Use Permission Boundaries, Monitor for sensitive IAM API calls.",
            policy_type=AlertPolicyType.IDENTITY_POLICY,
            impact=Impact.CRITICAL if outcome == "success" else Impact.MEDIUM,
            confidence=Confidence.HIGH,
            risk_level=risk_level,
        )

        # 当关联表值是list[BaseModel]类型时,创建关联记录并关联.当值为None,则不做任何处理,当职位值为[],则清空关联
        if artifacts:
            alert_model.artifacts = artifacts
        else:
            alert_model.artifacts = None

        if alert_enrichments:
            alert_model.enrichments = alert_enrichments
        else:
            alert_model.enrichments = None

        case_impact = Impact.CRITICAL if outcome == "success" else Impact.MEDIUM
        case_priority = CasePriority.HIGH if outcome == "success" else CasePriority.MEDIUM

        # 保存告警
        saved_alert_row_id = Alert.create(alert_model)

        # 5. Case 处理 (Case Management)

        existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
        if existing_case:
            # 附加到已有 Case
            existing_case_row_id = existing_case.row_id
            assert existing_case_row_id is not None
            existing_alerts = existing_case.alerts or []
            updated_alerts = existing_alerts if saved_alert_row_id in existing_alerts else [*existing_alerts, saved_alert_row_id]
            update_case = CaseModel(
                alerts=updated_alerts,
                row_id=existing_case_row_id
            )
            severity_order = {Severity.UNKNOWN: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            if severity_order.get(severity or Severity.UNKNOWN, 0) > severity_order.get(existing_case.severity or Severity.UNKNOWN, 0):
                update_case.severity = severity
                update_case.impact = case_impact
                update_case.priority = case_priority
            Case.update(update_case)
            Case.mark_analysis_requested(row_id=existing_case_row_id, cooldown_minutes=3)
        else:
            # 根据 Alert 计算 Case字段
            new_case = CaseModel(
                title=f"IAM Privilege Escalation: {principal_user} -> {target_user} in Account {account_id}",
                severity=severity,
                impact=case_impact,
                priority=case_priority,
                confidence=Confidence.HIGH,
                description=f"Investigation required for high-risk AttachUserPolicy activity by {principal_user} "
                            f"targeting {target_user} in account {account_id}.",
                category=ProductCategory.CLOUD,
                tags=["iam", "aws", "privesc"],
                correlation_uid=correlation_uid,
                alerts=[saved_alert_row_id]
            )
            created_case_row_id = Case.create(new_case)
            Case.mark_analysis_requested(row_id=created_case_row_id, cooldown_minutes=3)
        return True


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    # 单独测试某条告警
    # module = Module()
    # module.debug_message_id = "1776753170359-0"
    # module.run()

    # 批量测试最早的100条告警
    module = Module()
    message_ids = module.read_stream_head_ids(20)
    for message_id in message_ids:
        module.debug_message_id = message_id
        module.run()
