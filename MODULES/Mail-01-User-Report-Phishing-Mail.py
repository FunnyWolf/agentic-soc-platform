import json
import re
from datetime import datetime
from hashlib import sha1
from typing import List, Optional

from dateutil import parser

from Lib.basemodule import BaseModule
from PLUGINS.SIRP.correlation import Correlation
from PLUGINS.SIRP.sirpapi import Alert, Case
from PLUGINS.SIRP.sirpcoremodel import (
    ArtifactName,
    ArtifactModel,
    ArtifactRole,
    ArtifactType,
    AlertAction,
    AlertAnalyticType,
    AlertModel,
    AlertRiskLevel,
    AlertStatus,
    CaseModel,
    CasePriority,
    CaseStatus,
    Confidence,
    Disposition,
    Impact,
    ProductCategory,
    Severity,
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SUSPICIOUS_ATTACHMENT_EXTS = {
    ".exe",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".scr",
    ".msi",
    ".hta",
    ".docm",
    ".xlsm",
    ".pptm",
    ".iso",
    ".img",
    ".lnk",
    ".zip",
    ".rar",
}
URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "suspend",
    "blocked",
    "action required",
    "warning",
    "account deletion",
    "permanent block",
    "security",
    "confirm",
]


def _extract_email_address(value: str) -> str:
    if not value:
        return ""
    match = EMAIL_RE.search(value)
    return match.group(1).strip().lower() if match else value.strip().lower()


def _extract_domain(email_value: str) -> str:
    email_value = _extract_email_address(email_value)
    if "@" not in email_value:
        return ""
    return email_value.split("@", 1)[1].lower()


def _extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = URL_RE.findall(text)
    normalized = []
    for url in urls:
        cleaned = url.rstrip(").,;\"'>]")
        if cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def _extract_attachment_names(attachments: list) -> List[str]:
    names = []
    for attachment in attachments or []:
        filename = attachment.get("filename", "")
        if filename:
            names.append(filename)
    return names


def _attachment_is_suspicious(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTS)


def _url_domains(urls: List[str]) -> List[str]:
    domains = []
    for url in urls:
        try:
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split("?", 1)[0].lower()
        except Exception:
            host = ""
        if host and host not in domains:
            domains.append(host)
    return domains


def _normalize_subject_for_correlation(subject: str) -> Optional[str]:
    if not subject:
        return None
    normalized = re.sub(r"\s+", " ", subject.strip().lower())
    has_date = bool(re.search(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b|\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", normalized))
    long_number_count = len(re.findall(r"\d{4,}", normalized))
    email_in_subject = bool(EMAIL_RE.search(normalized))
    if has_date or long_number_count > 0 or email_in_subject:
        return None
    return normalized


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        raw_alert = self.read_stream_message()

        headers = raw_alert.get("headers", {})
        body = raw_alert.get("body", {})
        attachments = raw_alert.get("attachments", []) or []

        sender_raw = headers.get("From", "")
        recipient_raw = headers.get("To", "")
        subject = headers.get("Subject", "")
        sent_time_raw = headers.get("Date", "")
        return_path = headers.get("Return-Path", "")
        auth_results = headers.get("Authentication-Results", "")

        sender_email = _extract_email_address(sender_raw)
        recipient_email = _extract_email_address(recipient_raw)
        sender_domain = _extract_domain(sender_email)
        recipient_domain = _extract_domain(recipient_email)
        return_path_email = _extract_email_address(return_path)
        return_path_domain = _extract_domain(return_path_email)

        plain_text = body.get("plain_text", "") or ""
        html_text = body.get("html", "") or ""
        body_text = f"{plain_text}\n{html_text}"
        urls = _extract_urls(body_text)
        url_domains = _url_domains(urls)
        attachment_names = _extract_attachment_names(attachments)

        auth_lower = auth_results.lower()
        spf_fail = "spf=fail" in auth_lower
        dkim_fail = "dkim=fail" in auth_lower
        dmarc_fail = "dmarc=fail" in auth_lower

        suspicious_urls = []
        for url in urls:
            host = _url_domains([url])
            host_value = host[0] if host else ""
            if url.lower().startswith("http://"):
                suspicious_urls.append(url)
            elif sender_domain and host_value and sender_domain not in host_value:
                suspicious_urls.append(url)

        suspicious_attachments = [name for name in attachment_names if _attachment_is_suspicious(name)]
        urgent_hits = [keyword for keyword in URGENT_KEYWORDS if keyword in body_text.lower() or keyword in subject.lower()]

        suspicious_signals = sum(
            [
                1 if spf_fail else 0,
                1 if dkim_fail else 0,
                1 if dmarc_fail else 0,
                1 if suspicious_urls else 0,
                1 if suspicious_attachments else 0,
                1 if urgent_hits else 0,
            ]
        )

        if suspicious_signals >= 3:
            severity = Severity.HIGH
            risk_level = AlertRiskLevel.HIGH
            confidence = Confidence.HIGH
            disposition = Disposition.DETECTED
            impact = Impact.HIGH
        elif suspicious_signals >= 1:
            severity = Severity.MEDIUM
            risk_level = AlertRiskLevel.MEDIUM
            confidence = Confidence.MEDIUM
            disposition = Disposition.DETECTED
            impact = Impact.MEDIUM
        else:
            severity = Severity.INFORMATIONAL
            risk_level = AlertRiskLevel.INFO
            confidence = Confidence.LOW
            disposition = Disposition.LOGGED
            impact = Impact.LOW

        if "failed" in auth_lower or suspicious_attachments or suspicious_urls:
            action = AlertAction.DENIED
        else:
            action = AlertAction.OBSERVED

        event_time = parser.parse(sent_time_raw) if sent_time_raw else datetime.now()

        artifacts: List[ArtifactModel] = []
        if sender_email:
            artifacts.append(
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.ACTOR,
                    value=sender_email,
                    name=ArtifactName.SENDER_EMAIL,
                )
            )
        if recipient_email:
            artifacts.append(
                ArtifactModel(
                    type=ArtifactType.EMAIL_ADDRESS,
                    role=ArtifactRole.TARGET,
                    value=recipient_email,
                    name=ArtifactName.RECIPIENT_EMAIL,
                )
            )
        if subject:
            artifacts.append(
                ArtifactModel(
                    type=ArtifactType.MESSAGE,
                    role=ArtifactRole.RELATED,
                    value=subject,
                    name=ArtifactName.MAIL_SUBJECT,
                )
            )
        for url in urls:
            artifacts.append(
                ArtifactModel(
                    type=ArtifactType.UNIFORM_RESOURCE_LOCATOR,
                    role=ArtifactRole.RELATED,
                    value=url,
                    name=ArtifactName.MAIL_URL,
                )
            )
        for attachment in attachments:
            filename = attachment.get("filename", "")
            filepath = attachment.get("filepath", "")
            content_type = attachment.get("content_type", "")
            if filename:
                artifacts.append(
                    ArtifactModel(
                        type=ArtifactType.FILE_NAME,
                        role=ArtifactRole.RELATED,
                        value=filename,
                        name=ArtifactName.ATTACHMENT_FILE,
                    )
                )

        normalized_subject = _normalize_subject_for_correlation(subject)
        correlation_keys = [sender_email or sender_domain or sender_raw]
        if normalized_subject:
            correlation_keys.append(normalized_subject)
        correlation_keys = [key for key in correlation_keys if key]
        if not correlation_keys:
            correlation_keys = [sender_domain or subject or self.module_name]

        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window="12h",
            keys=correlation_keys,
            timestamp=event_time,
        )

        source_uid_seed = json.dumps(
            {
                "from": sender_raw,
                "to": recipient_raw,
                "subject": subject,
                "date": sent_time_raw,
            },
            sort_keys=True,
        )
        source_uid = f"mail-{sha1(source_uid_seed.encode('utf-8')).hexdigest()[:16]}"

        alert_model = AlertModel(
            title=f"User Reported Phishing Mail: {subject}" if subject else "User Reported Phishing Mail",
            severity=severity,
            confidence=confidence,
            impact=impact,
            disposition=disposition,
            action=action,
            status=AlertStatus.NEW,
            rule_id=self.module_name,
            rule_name="Mail-01-User-Report-Phishing-Mail",
            correlation_uid=correlation_uid,
            source_uid=source_uid,
            analytic_type=AlertAnalyticType.RULE,
            analytic_name="Mail User Report Phishing Rule",
            analytic_desc="Detects user-reported mail and preserves sender, recipient, URL, attachment, and authentication evidence.",
            product_category=ProductCategory.EMAIL,
            product_name="Email Security",
            product_vendor="Mail Gateway",
            product_feature="User Reported Mail Analysis",
            first_seen_time=event_time,
            last_seen_time=event_time,
            desc=(
                f"From: {sender_raw}\nTo: {recipient_raw}\nSubject: {subject}\n"
                f"Return-Path: {return_path}\nAuthentication-Results: {auth_results}"
            ),
            data_sources=["email"],
            labels=[
                "email",
                "user-report",
                "phishing",
                f"sender:{sender_domain}" if sender_domain else "sender:unknown",
                f"recipient:{recipient_domain}" if recipient_domain else "recipient:unknown",
            ],
            tactic="Initial Access",
            technique="T1566 - Phishing",
            sub_technique="T1566.001 - Spearphishing Attachment",
            mitigation="Train users to report suspicious mail, verify sender authenticity, and block malicious links and attachments.",
            raw_data=json.dumps(raw_alert),
            unmapped=json.dumps(
                {
                    "headers": headers,
                    "body": {
                        "plain_text_length": len(plain_text),
                        "html_length": len(html_text),
                    },
                    "return_path": return_path,
                    "return_path_domain": return_path_domain,
                    "authentication_results": auth_results,
                    "urls": urls,
                    "url_domains": url_domains,
                    "suspicious_urls": suspicious_urls,
                    "correlation_keys": correlation_keys,
                    "correlation_window": "12h",
                    "attachments": attachments,
                    "attachment_names": attachment_names,
                    "suspicious_attachments": suspicious_attachments,
                    "urgent_hits": urgent_hits,
                    "heuristics": {
                        "spf_fail": spf_fail,
                        "dkim_fail": dkim_fail,
                        "dmarc_fail": dmarc_fail,
                        "suspicious_signals": suspicious_signals,
                    },
                },
                ensure_ascii=False,
            ),
        )

        if artifacts:
            alert_model.artifacts = artifacts

        saved_alert_row_id = Alert.create(alert_model)
        self.logger.info(f"Alert created: {saved_alert_row_id}")

        try:
            existing_case = Case.get_by_correlation_uid(correlation_uid, lazy_load=True)
            if existing_case:
                update_case = CaseModel(
                    alerts=[*existing_case.alerts, saved_alert_row_id],
                    row_id=existing_case.row_id,
                )
                Case.update(update_case)
                Case.mark_analysis_requested(row_id=existing_case.row_id, cooldown_minutes=3)
            else:
                new_case = CaseModel(
                    title=f"User Reported Phishing Mail: {subject}" if subject else "User Reported Phishing Mail",
                    status=CaseStatus.NEW,
                    severity=severity,
                    impact=impact,
                    priority=CasePriority.HIGH if severity in [Severity.HIGH, Severity.CRITICAL] else CasePriority.MEDIUM,
                    confidence=confidence,
                    description=(
                        f"Reported mail from {sender_raw} to {recipient_raw}. "
                        f"Authentication result: {auth_results}. "
                        f"Attachments: {', '.join(attachment_names) if attachment_names else 'None'}."
                    ),
                    category=ProductCategory.EMAIL,
                    tags=["email", "user-report", "phishing"],
                    correlation_uid=correlation_uid,
                    alerts=[saved_alert_row_id],
                )
                created_case_row_id = Case.create(new_case)
                Case.mark_analysis_requested(row_id=created_case_row_id, cooldown_minutes=3)
        except Exception as e:
            self.logger.error(f"Case operation failed: {str(e)}")

        return True
