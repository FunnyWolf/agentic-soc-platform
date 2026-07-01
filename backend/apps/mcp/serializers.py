import mimetypes

from django.contrib.contenttypes.models import ContentType
from django.urls import reverse

from apps.comments.models import Comment

DEFAULT_COMMENTS_LIMIT = 20
MAX_COMMENTS_LIMIT = 50


def _dt(value):
    return value.isoformat() if value else None


def normalize_comments_limit(value):
    return max(1, min(int(value or DEFAULT_COMMENTS_LIMIT), MAX_COMMENTS_LIMIT))


def _request_header(request, header_name):
    scope = getattr(request, "scope", {}) if request is not None else {}
    expected = header_name.lower().encode()
    for key, value in scope.get("headers", []):
        if key.lower() == expected:
            return value.decode("utf-8", errors="ignore")
    return ""


def _absolute_url(path, request=None):
    if request is None:
        return path

    scope = getattr(request, "scope", {})
    scheme = (_request_header(request, "x-forwarded-proto").split(",", 1)[0].strip()
              or scope.get("scheme")
              or "http")
    host = (_request_header(request, "x-forwarded-host").split(",", 1)[0].strip()
            or _request_header(request, "host"))
    if not host:
        server = scope.get("server")
        if server:
            host = f"{server[0]}:{server[1]}"
    if not host:
        return path
    return f"{scheme}://{host}{path}"


def serialize_attachment(attachment, *, request=None):
    path = reverse("attachment-download", kwargs={"access_key": attachment.access_key})
    return {
        "file_key": str(attachment.access_key),
        "filename": attachment.filename,
        "size": attachment.size,
        "content_type": mimetypes.guess_type(attachment.filename)[0] or "application/octet-stream",
        "download_url": _absolute_url(path, request=request),
    }


def _record_content_type(record):
    return ContentType.objects.get_for_model(record, for_concrete_model=False)


def _comments_for_record(record, *, comments_limit=DEFAULT_COMMENTS_LIMIT):
    content_type = _record_content_type(record)
    comments = list(
        Comment.objects
        .filter(content_type=content_type, object_id=str(record.pk))
        .select_related("author", "parent")
        .prefetch_related("attachments")
        .order_by("-created_at", "-id")[:normalize_comments_limit(comments_limit)]
    )
    return reversed(comments)


def _add_comments(data, record, *, include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, request=None):
    if include_comments:
        data["comments"] = [
            serialize_comment(comment, request=request)
            for comment in _comments_for_record(record, comments_limit=comments_limit)
        ]
    return data


def serialize_enrichment(enrichment):
    return {
        "enrichment_id": enrichment.enrichment_id,
        "name": enrichment.name,
        "type": enrichment.type,
        "provider": enrichment.provider,
        "uid": enrichment.uid,
        "value": enrichment.value,
        "desc": enrichment.desc,
        "data": enrichment.data,
        "created_at": _dt(enrichment.created_at),
    }


def serialize_artifact(
    artifact,
    *,
    include_enrichments=True,
    include_comments=False,
    comments_limit=DEFAULT_COMMENTS_LIMIT,
    request=None,
):
    data = {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "type": artifact.type,
        "role": artifact.role,
        "value": artifact.value,
        "created_at": _dt(artifact.created_at),
    }
    if include_enrichments:
        data["enrichments"] = [serialize_enrichment(item) for item in artifact.enrichments.all()[:20]]
    return _add_comments(data, artifact, include_comments=include_comments, comments_limit=comments_limit, request=request)


def serialize_alert(
    alert,
    *,
    include_related=False,
    include_comments=False,
    comments_limit=DEFAULT_COMMENTS_LIMIT,
    request=None,
):
    data = {
        "alert_id": alert.alert_id,
        "case_id": alert.case.case_id if alert.case_id else "",
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "confidence": alert.confidence,
        "correlation_uid": alert.correlation_uid,
        "source_uid": alert.source_uid,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "created_at": _dt(alert.created_at),
    }
    if include_related:
        data["artifacts"] = [serialize_artifact(item, include_enrichments=False) for item in alert.artifacts.all()[:50]]
        data["enrichments"] = [serialize_enrichment(item) for item in alert.enrichments.all()[:20]]
    return _add_comments(data, alert, include_comments=include_comments, comments_limit=comments_limit, request=request)


def serialize_comment(comment, *, request=None):
    return {
        "id": comment.id,
        "body": comment.body,
        "author": comment.author.username if comment.author else "",
        "created_at": _dt(comment.created_at),
        "updated_at": _dt(comment.updated_at),
        "parent_id": comment.parent_id,
        "attachments": [
            serialize_attachment(item, request=request)
            for item in comment.attachments.all()
        ],
    }


def serialize_case(
    case,
    *,
    include_related=True,
    include_comments=False,
    comments_limit=DEFAULT_COMMENTS_LIMIT,
    request=None,
):
    data = {
        "case_id": case.case_id,
        "title": case.title,
        "severity": case.severity,
        "confidence": case.confidence,
        "impact": case.impact,
        "priority": case.priority,
        "status": case.status,
        "verdict": case.verdict,
        "severity_ai": case.severity_ai,
        "confidence_ai": case.confidence_ai,
        "impact_ai": case.impact_ai,
        "priority_ai": case.priority_ai,
        "verdict_ai": case.verdict_ai,
        "summary": case.summary,
        "correlation_uid": case.correlation_uid,
        "tags": case.tags,
        "created_at": _dt(case.created_at),
    }
    if include_related:
        data["alerts"] = [serialize_alert(alert, include_related=True) for alert in case.alerts.all()[:50]]
        data["enrichments"] = [serialize_enrichment(item) for item in case.enrichments.all()[:20]]
        data["playbooks"] = [serialize_playbook(item) for item in case.playbooks.all()[:20]]
    return _add_comments(data, case, include_comments=include_comments, comments_limit=comments_limit, request=request)


def serialize_playbook(
    playbook,
    *,
    include_related=False,
    include_comments=False,
    comments_limit=DEFAULT_COMMENTS_LIMIT,
    request=None,
):
    data = {
        "playbook_id": playbook.playbook_id,
        "case_id": playbook.case.case_id if playbook.case_id else "",
        "name": playbook.name,
        "user_input": playbook.user_input,
        "job_status": playbook.job_status,
        "job_id": playbook.job_id,
        "remark": playbook.remark,
        "created_at": _dt(playbook.created_at),
    }
    if include_related and playbook.case_id:
        data["case"] = serialize_case(playbook.case, include_related=False)
    return _add_comments(data, playbook, include_comments=include_comments, comments_limit=comments_limit, request=request)


def serialize_knowledge(
    knowledge,
    *,
    include_comments=False,
    comments_limit=DEFAULT_COMMENTS_LIMIT,
    request=None,
):
    data = {
        "knowledge_id": knowledge.knowledge_id,
        "title": knowledge.title,
        "body": knowledge.body,
        "expires_at": _dt(knowledge.expires_at),
        "source": knowledge.source,
        "tags": knowledge.tags,
        "case_id": knowledge.case.case_id if knowledge.case_id else "",
        "created_at": _dt(knowledge.created_at),
    }
    return _add_comments(data, knowledge, include_comments=include_comments, comments_limit=comments_limit, request=request)
