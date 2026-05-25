import json
from typing import List

from dateutil import parser

from Lib.basemodule import BaseModule
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpcoremodel import ArtifactName, ArtifactType, ArtifactRole, Severity, Impact, Disposition, AlertAction, Confidence, AlertAnalyticType, ProductCategory, \
    AlertPolicyType, AlertRiskLevel, AlertStatus, CasePriority, ArtifactModel, AlertModel, CaseModel


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        # 获取原始告警JSON
        raw_alert = self.read_stream_message()

        # 1. 字段提取
        event_time = raw_alert.get("@timestamp", "")
        event_outcome = raw_alert.get("event.outcome", raw_alert.get("event", {}).get("outcome", "success"))

        host_name = raw_alert.get("host.name", raw_alert.get("host", {}).get("name", ""))
        host_id = raw_alert.get("host.id", raw_alert.get("host", {}).get("id", ""))
        host_os = raw_alert.get("host.os.name", raw_alert.get("host", {}).get("os", {}).get("name", "Windows"))

        user_name = raw_alert.get("user.name", raw_alert.get("user", {}).get("name", ""))
        user_id = raw_alert.get("user.id", raw_alert.get("user", {}).get("id", ""))

        process_name = raw_alert.get("process.name", raw_alert.get("process", {}).get("name", ""))
        process_cmd = raw_alert.get("process.command_line", raw_alert.get("process", {}).get("command_line", ""))
        process_exe = raw_alert.get("process.executable", raw_alert.get("process", {}).get("executable", ""))
        process_pid = raw_alert.get("process.pid", raw_alert.get("process", {}).get("pid", ""))
        process_hash_md5 = raw_alert.get("process.hash.md5", raw_alert.get("process", {}).get("hash", {}).get("md5", ""))
        process_hash_sha256 = raw_alert.get("process.hash.sha256", raw_alert.get("process", {}).get("hash", {}).get("sha256", ""))
        parent_name = raw_alert.get("process.parent.name", raw_alert.get("process", {}).get("parent", {}).get("name", ""))
        parent_pid = raw_alert.get("process.parent.pid", raw_alert.get("process", {}).get("parent", {}).get("pid", ""))

        risk_score_raw = raw_alert.get("risk_score", 100)
        try:
            risk_score = float(risk_score_raw)
        except (TypeError, ValueError):
            risk_score = 100.0
        log_level = raw_alert.get("log.level", raw_alert.get("log", {}).get("level", "critical"))

        # 严重程度映射
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
            "warning": Severity.MEDIUM,
            "info": Severity.LOW,
        }
        severity = severity_map.get(log_level.lower(), Severity.CRITICAL)

        # 处置结果：vssadmin 删除影子副本是勒索软件典型行为，直接标记为检测到
        disposition = Disposition.DETECTED
        action = AlertAction.OBSERVED

        event_time_formatted = parser.parse(event_time)

        # 2. Artifact 提取
        artifacts: List[ArtifactModel] = []

        if user_name:
            artifacts.append(ArtifactModel(type=ArtifactType.USER_NAME, role=ArtifactRole.ACTOR, value=user_name, name=ArtifactName.EXECUTING_USER))
        if host_name:
            artifacts.append(ArtifactModel(type=ArtifactType.HOSTNAME, role=ArtifactRole.AFFECTED, value=host_name, name=ArtifactName.AFFECTED_HOST))
        if process_hash_sha256:
            artifacts.append(ArtifactModel(type=ArtifactType.HASH, role=ArtifactRole.RELATED, value=process_hash_sha256, name=ArtifactName.PROCESS_HASH))
        if process_hash_md5:
            artifacts.append(ArtifactModel(type=ArtifactType.HASH, role=ArtifactRole.RELATED, value=process_hash_md5, name=ArtifactName.PROCESS_HASH))
        if process_cmd:
            artifacts.append(ArtifactModel(type=ArtifactType.COMMAND_LINE, role=ArtifactRole.RELATED, value=process_cmd, name=ArtifactName.PROCESS_COMMAND_LINE))

        # 3. Correlation：同一主机 + 同一用户，24h 内聚合为一个 Case
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window="24h",
            keys=[host_name, user_name],
            timestamp=event_time_formatted
        )

        # 4. 组装 AlertModel
        alert_model = AlertModel(
            title=f"Shadow Copy Deletion: {user_name} ran vssadmin on {host_name}",
            severity=severity,
            status=AlertStatus.NEW,
            status_detail=f"Parent process: {parent_name} (PID {parent_pid})",
            disposition=disposition,
            action=action,
            rule_id=self.module_name,
            rule_name="Vssadmin Delete Shadows",
            correlation_uid=correlation_uid,
            analytic_type=AlertAnalyticType.RULE,
            analytic_name="EDR Endpoint Security Rule",
            analytic_desc="Detects vssadmin.exe delete shadows command, a common ransomware pre-encryption step to prevent recovery.",
            product_category=ProductCategory.EDR,
            product_name="EDR",
            product_vendor="Endpoint Security",
            product_feature="Process Monitoring",
            first_seen_time=event_time_formatted,
            last_seen_time=event_time_formatted,
            desc=(
                f"User {user_name} executed '{process_cmd}' on host {host_name} ({host_os}). "
                f"Parent process: {parent_name} (PID {parent_pid}). "
                f"This command deletes all Volume Shadow Copies and is a strong ransomware indicator."
            ),
            data_sources=["endpoint.process"],
            labels=["ransomware", "defense-evasion", "vssadmin", f"host:{host_name}", f"user:{user_name}"],
            raw_data=json.dumps(raw_alert),
            unmapped=json.dumps({
                "host.id": host_id,
                "host.os.name": host_os,
                "user.id": user_id,
                "process.pid": process_pid,
                "process.executable": process_exe,
                "event.outcome": event_outcome,
                "risk_score": risk_score,
            }),
            # MITRE ATT&CK: Impact - Inhibit System Recovery
            tactic="Impact",
            technique="T1490 - Inhibit System Recovery",
            sub_technique=None,
            mitigation="Restrict vssadmin.exe usage via AppLocker/WDAC, monitor for shadow copy deletion, maintain offline backups.",
            policy_type=AlertPolicyType.IDENTITY_POLICY,
            impact=Impact.CRITICAL,
            confidence=Confidence.HIGH,
            risk_level=risk_level,
        )

        alert_model.artifacts = artifacts if artifacts else None

        # 保存告警
        saved_alert_row_id = Alert.create(alert_model)

        # 5. Case 处理
        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
            if existing_case:
                update_case = CaseModel(
                    alerts=[*existing_case.alerts, saved_alert_row_id],
                    row_id=existing_case.row_id
                )
                Case.update(update_case)
            else:
                new_case = CaseModel(
                    title=f"Potential Ransomware Activity on {host_name} by {user_name}",
                    severity=severity,
                    impact=Impact.CRITICAL,
                    priority=CasePriority.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Shadow Copy deletion detected on host {host_name}. "
                        f"User {user_name} executed vssadmin delete shadows, which is a strong indicator of ransomware pre-encryption activity. "
                        f"Immediate investigation and containment recommended."
                    ),
                    category=ProductCategory.EDR,
                    tags=["ransomware", "vssadmin", "shadow-copy", f"host:{host_name}"],
                    correlation_uid=correlation_uid,
                    alerts=[saved_alert_row_id]
                )
                Case.create(new_case)
        except Exception as e:
            self.logger.error(f"Case operation failed: {str(e)}")

        return True
