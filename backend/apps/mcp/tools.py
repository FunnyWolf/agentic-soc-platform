import json
from datetime import timezone as datetime_timezone
from functools import wraps
from inspect import signature
from uuid import UUID

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils.dateparse import parse_datetime
from mcp.server.fastmcp import Context

from apps.accounts.permissions import is_business_writer
from apps.agentic.services.playbooks import (
    create_pending_playbook_run,
    list_playbook_definitions as list_playbook_definition_records,
)
from apps.audit.context import audit_actor
from apps.alerts.models import Alert
from apps.artifacts.models import Artifact
from apps.attachments.models import Attachment
from apps.cases.models import Case
from apps.comments.models import Comment
from apps.comments.services import create_record_comment
from apps.common.redis_stream import RedisStreamClient
from apps.enrichments.models import Enrichment, EnrichmentProvider
from apps.knowledge.models import Knowledge
from apps.mcp.serializers import (
    DEFAULT_COMMENTS_LIMIT,
    normalize_comments_limit,
    serialize_attachment,
    serialize_alert,
    serialize_artifact,
    serialize_case,
    serialize_comment,
    serialize_enrichment,
    serialize_knowledge,
    serialize_playbook,
)
from apps.playbooks.models import Playbook
from integrations.cmdb.service import lookup_artifact_context
from integrations.siem import service as siem_service
from integrations.siem.models import (
    AdaptiveQueryInput,
    DiscoverIndexFieldsInput,
    ESQLQueryInput,
    KeywordSearchInput,
    SchemaExplorerInput,
    SPLQueryInput,
)
from integrations.threat_intel.service import query_indicator

MAX_LIMIT = 100


def _limit(value):
    return max(1, min(int(value or 10), MAX_LIMIT))


def _list(value):
    if value in (None, ""):
        return []
    if isinstance(value, list | tuple | set):
        return [item for item in value if item not in (None, "")]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, list):
                return [item for item in decoded if item not in (None, "")]
            if decoded not in (None, ""):
                return [decoded]
        if "," in text:
            return [item.strip() for item in text.split(",") if item.strip()]
        return [text]
    return [value]


def _bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return default
        return normalized not in {"0", "false", "no", "off"}
    return bool(value)


def _current_request(ctx):
    if ctx is None:
        return None
    request_context = getattr(ctx, "request_context", None)
    return getattr(request_context, "request", None)


def _comments_kwargs(include_comments, comments_limit, ctx):
    include = _bool(include_comments, default=False)
    return {
        "include_comments": include,
        "comments_limit": normalize_comments_limit(comments_limit) if include else DEFAULT_COMMENTS_LIMIT,
        "request": _current_request(ctx),
    }


def _json_object(value, field_name):
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be valid JSON object")

    try:
        payload = json.loads(value.strip())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{field_name} must be valid JSON object")
    return payload


def _parse_timezone_aware_datetime(value, field_name):
    if value in (None, ""):
        return None
    parsed = parse_datetime(str(value).strip())
    if parsed is None:
        raise ValueError(f"{field_name} must be ISO 8601 datetime with timezone, e.g. 2026-06-23T12:00:00Z")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone, e.g. 2026-06-23T12:00:00Z or 2026-06-23T20:00:00+08:00")
    return parsed.astimezone(datetime_timezone.utc)


def _record_id(value):
    return str(value or "").strip().lower()


def _find_case(case_id):
    case_id = _record_id(case_id)
    try:
        return Case.objects.get(case_id=case_id)
    except Case.DoesNotExist as exc:
        raise ValueError(f"Case not found: {case_id}") from exc


def _find_alert(alert_id):
    alert_id = _record_id(alert_id)
    try:
        return Alert.objects.get(alert_id=alert_id)
    except Alert.DoesNotExist as exc:
        raise ValueError(f"Alert not found: {alert_id}") from exc


def _find_artifact(artifact_id):
    artifact_id = _record_id(artifact_id)
    try:
        return Artifact.objects.get(artifact_id=artifact_id)
    except Artifact.DoesNotExist as exc:
        raise ValueError(f"Artifact not found: {artifact_id}") from exc


def _find_enrichment(enrichment_id):
    enrichment_id = _record_id(enrichment_id)
    try:
        return Enrichment.objects.get(enrichment_id=enrichment_id)
    except Enrichment.DoesNotExist as exc:
        raise ValueError(f"Enrichment not found: {enrichment_id}") from exc


def _find_knowledge(knowledge_id):
    knowledge_id = _record_id(knowledge_id)
    try:
        return Knowledge.objects.get(knowledge_id=knowledge_id)
    except Knowledge.DoesNotExist as exc:
        raise ValueError(f"Knowledge not found: {knowledge_id}") from exc


def _find_playbook(playbook_id):
    playbook_id = _record_id(playbook_id)
    try:
        return Playbook.objects.get(playbook_id=playbook_id)
    except Playbook.DoesNotExist as exc:
        raise ValueError(f"Playbook not found: {playbook_id}") from exc


def _find_comment_target(target_id):
    target_id = _record_id(target_id)
    if target_id.startswith("case_"):
        return _find_case(target_id)
    if target_id.startswith("alert_"):
        return _find_alert(target_id)
    if target_id.startswith("artifact_"):
        return _find_artifact(target_id)
    if target_id.startswith("enrichment_"):
        return _find_enrichment(target_id)
    if target_id.startswith("knowledge_"):
        return _find_knowledge(target_id)
    if target_id.startswith("playbook_"):
        return _find_playbook(target_id)
    raise ValueError("target_id must start with one of: case_, alert_, artifact_, enrichment_, knowledge_, playbook_")


def _current_user(ctx):
    if ctx is None:
        raise ValueError("MCP write tool requires an authenticated MCP request")
    request = _current_request(ctx)
    scope = getattr(request, "scope", {}) if request is not None else {}
    user = scope.get("user")
    if user is None or not getattr(user, "is_authenticated", False):
        raise ValueError("MCP write tool requires an authenticated MCP user")
    return user


def _current_business_writer(ctx):
    user = _current_user(ctx)
    if not is_business_writer(user):
        raise ValueError("MCP write tool requires an admin or user role")
    return user


def _normalize_file_key(file_key):
    text = str(file_key or "").strip()
    if not text:
        raise ValueError("file_key is required")
    try:
        return UUID(text)
    except ValueError as exc:
        raise ValueError(f"Invalid file_key: {text}") from exc


def _find_attachment_by_file_key(file_key):
    normalized_key = _normalize_file_key(file_key)
    try:
        return Attachment.objects.get(access_key=normalized_key)
    except Attachment.DoesNotExist as exc:
        raise ValueError(f"Attachment not found for file_key: {normalized_key}") from exc


def _attachments_from_file_keys(file_keys):
    normalized_keys = []
    seen_keys = set()
    for item in _list(file_keys):
        key = _normalize_file_key(item)
        if key not in seen_keys:
            normalized_keys.append(key)
            seen_keys.add(key)
    if not normalized_keys:
        return []

    attachments = {
        item.access_key: item
        for item in Attachment.objects.filter(access_key__in=normalized_keys)
    }
    missing_keys = [str(key) for key in normalized_keys if key not in attachments]
    if missing_keys:
        raise ValueError(f"Attachment not found for file_key: {', '.join(missing_keys)}")
    return [attachments[key] for key in normalized_keys]


def _content_type_for_record(record):
    return ContentType.objects.get_for_model(record, for_concrete_model=False)


def _parent_comment_for_target(content_object, parent_id):
    if parent_id in (None, ""):
        return None
    try:
        parent = Comment.objects.get(pk=int(parent_id))
    except (TypeError, ValueError, Comment.DoesNotExist) as exc:
        raise ValueError(f"Parent comment not found: {parent_id}") from exc

    content_type = _content_type_for_record(content_object)
    if parent.content_type_id != content_type.id or parent.object_id != str(content_object.pk):
        raise ValueError("parent_id must belong to the same target")
    return parent


def _mention_users(mentions):
    users = []
    seen_ids = set()
    user_model = get_user_model()
    for item in _list(mentions):
        text = str(item or "").strip()
        if not text:
            continue
        user = user_model.objects.filter(username=text).first()
        if user is None and text.isdigit():
            user = user_model.objects.filter(pk=int(text)).first()
        if user is None:
            raise ValueError(f"Mention user not found: {text}")
        if user.id not in seen_ids:
            users.append(user)
            seen_ids.add(user.id)
    return users


def list_cases(case_id=None, status=None, severity=None, confidence=None, verdict=None, correlation_uid=None, title=None, tags=None, include_related=True,
               limit=10, include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, ctx: Context = None):
    queryset = Case.objects.all().order_by("-created_at")
    if case_id:
        queryset = queryset.filter(case_id=_record_id(case_id))
    if status_values := _list(status):
        queryset = queryset.filter(status__in=status_values)
    if severity_values := _list(severity):
        queryset = queryset.filter(severity__in=severity_values)
    if confidence_values := _list(confidence):
        queryset = queryset.filter(confidence__in=confidence_values)
    if verdict_values := _list(verdict):
        queryset = queryset.filter(verdict__in=verdict_values)
    if correlation_uid:
        queryset = queryset.filter(correlation_uid=correlation_uid)
    if title:
        queryset = queryset.filter(title__icontains=title)
    if tag_values := _list(tags):
        for tag in tag_values:
            queryset = queryset.filter(tags__contains=[tag])
    comments_kwargs = _comments_kwargs(include_comments, comments_limit, ctx)
    return [
        serialize_case(item, include_related=_bool(include_related), **comments_kwargs)
        for item in queryset[:_limit(limit)]
    ]


def update_case(case_id, severity_ai=None, confidence_ai=None, impact_ai=None, priority_ai=None, verdict_ai=None, summary=None, ctx: Context = None):
    case = _find_case(case_id)
    updates = {}
    for field_name, value in {
        "severity_ai": severity_ai,
        "confidence_ai": confidence_ai,
        "impact_ai": impact_ai,
        "priority_ai": priority_ai,
        "verdict_ai": verdict_ai,
        "summary": summary,
    }.items():
        if value is not None:
            setattr(case, field_name, value)
            updates[field_name] = value
    with audit_actor(_current_user(ctx)):
        case.full_clean()
        case.save(update_fields=[*updates.keys(), "updated_at"] if updates else ["updated_at"])
    return serialize_case(case, include_related=True)


def get_file(file_key, ctx: Context = None):
    return serialize_attachment(_find_attachment_by_file_key(file_key), request=_current_request(ctx))


def add_comment(target_id, body="", file_keys=None, parent_id=None, mentions=None, ctx: Context = None):
    user = _current_business_writer(ctx)
    content_object = _find_comment_target(target_id)
    attachments = _attachments_from_file_keys(file_keys)
    body_text = str(body or "")
    if not body_text.strip() and not attachments:
        raise ValueError("body or file_keys are required")
    comment = create_record_comment(
        author=user,
        content_object=content_object,
        body=body_text,
        parent=_parent_comment_for_target(content_object, parent_id),
        mentions=_mention_users(mentions),
        attachments=attachments,
    )
    return serialize_comment(comment, request=_current_request(ctx))


def list_alerts(alert_id=None, status=None, severity=None, confidence=None, correlation_uid=None, include_related=False,
                limit=10, include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, ctx: Context = None):
    include_related = _bool(include_related, default=False)
    queryset = Alert.objects.select_related("case").all().order_by("-created_at")
    if include_related:
        queryset = queryset.prefetch_related("artifacts", "enrichments")
    if alert_id:
        queryset = queryset.filter(alert_id=_record_id(alert_id))
    if status_values := _list(status):
        queryset = queryset.filter(status__in=status_values)
    if severity_values := _list(severity):
        queryset = queryset.filter(severity__in=severity_values)
    if confidence_values := _list(confidence):
        queryset = queryset.filter(confidence__in=confidence_values)
    if correlation_uid:
        queryset = queryset.filter(correlation_uid=correlation_uid)
    comments_kwargs = _comments_kwargs(include_comments, comments_limit, ctx)
    return [
        serialize_alert(item, include_related=include_related, **comments_kwargs)
        for item in queryset[:_limit(limit)]
    ]


def list_artifacts(artifact_id=None, type=None, role=None, value=None, include_related=False, limit=10,
                   include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, ctx: Context = None):
    include_related = _bool(include_related, default=False)
    queryset = Artifact.objects.all().order_by("-created_at")
    if include_related:
        queryset = queryset.prefetch_related("enrichments")
    if artifact_id:
        queryset = queryset.filter(artifact_id=_record_id(artifact_id))
    if type_values := _list(type):
        queryset = queryset.filter(type__in=type_values)
    if role_values := _list(role):
        queryset = queryset.filter(role__in=role_values)
    if value:
        queryset = queryset.filter(value=value)
    comments_kwargs = _comments_kwargs(include_comments, comments_limit, ctx)
    return [
        serialize_artifact(item, include_enrichments=include_related, **comments_kwargs)
        for item in queryset[:_limit(limit)]
    ]


def create_enrichment(target_id, name="", type="Other", value="", uid="", desc="", data="", ctx: Context = None):
    target_id = _record_id(target_id)
    payload = _json_object(data, "data")
    enrichment = Enrichment(
        name=name,
        type=type,
        provider=EnrichmentProvider.MCP,
        value=value,
        uid=uid,
        desc=desc,
        data=payload,
    )
    if target_id.startswith("case_"):
        enrichment.case = _find_case(target_id)
    elif target_id.startswith("alert_"):
        enrichment.alert = _find_alert(target_id)
    elif target_id.startswith("artifact_"):
        enrichment.artifact = _find_artifact(target_id)
    else:
        raise ValueError("target_id must start with one of: case_, alert_, artifact_")
    with audit_actor(_current_user(ctx)):
        enrichment.full_clean()
        enrichment.save()
    return serialize_enrichment(enrichment)


def list_playbook_templates():
    return list_playbook_definition_records(include_path=False)


def execute_playbook(name, case_id, user_input=None, ctx: Context = None):
    user = _current_user(ctx)
    with audit_actor(user):
        playbook = create_pending_playbook_run(name=name, case=_find_case(case_id), user=user, user_input=user_input)
    return serialize_playbook(playbook)


def list_playbooks(playbook_id=None, job_status=None, case_id=None, include_related=False, limit=10,
                   include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, ctx: Context = None):
    include_related = _bool(include_related, default=False)
    queryset = Playbook.objects.select_related("case").all().order_by("-created_at")
    if playbook_id:
        queryset = queryset.filter(playbook_id=_record_id(playbook_id))
    if job_status_values := _list(job_status):
        queryset = queryset.filter(job_status__in=job_status_values)
    if case_id:
        queryset = queryset.filter(case__case_id=_record_id(case_id))
    comments_kwargs = _comments_kwargs(include_comments, comments_limit, ctx)
    return [
        serialize_playbook(item, include_related=include_related, **comments_kwargs)
        for item in queryset[:_limit(limit)]
    ]


def update_knowledge(knowledge_id, title=None, body=None, expires_at=None, tags=None, ctx: Context = None):
    knowledge = _find_knowledge(knowledge_id)
    if title is not None:
        knowledge.title = title
    if body is not None:
        knowledge.body = body
    if expires_at is not None:
        knowledge.expires_at = _parse_timezone_aware_datetime(expires_at, "expires_at")
    if tags is not None:
        knowledge.tags = _list(tags)
    with audit_actor(_current_user(ctx)):
        knowledge.full_clean()
        knowledge.save()
    return serialize_knowledge(knowledge)


def search_knowledge(keyword, limit=10, include_comments=False, comments_limit=DEFAULT_COMMENTS_LIMIT, ctx: Context = None):
    keywords = _list(keyword)
    queryset = Knowledge.objects.none()
    for item in keywords:
        queryset = queryset | Knowledge.objects.filter(title__icontains=item)
        queryset = queryset | Knowledge.objects.filter(body__icontains=item)
        queryset = queryset | Knowledge.objects.filter(tags__contains=[item])
    comments_kwargs = _comments_kwargs(include_comments, comments_limit, ctx)
    return [
        serialize_knowledge(item, **comments_kwargs)
        for item in queryset.order_by("-created_at")[:_limit(limit)]
    ]


def read_stream_message_by_id(stream_name, message_id):
    return RedisStreamClient().read_stream_message_by_id(stream_name, message_id)


def read_stream_head(stream_name, n=3):
    return RedisStreamClient().read_stream_head(stream_name, _limit(n))


def ti_query(indicator, artifact_type="Unknown", provider=None):
    return query_indicator(indicator, artifact_type=artifact_type, provider=provider).model_dump()


def cmdb_lookup(artifact_type, artifact_value, provider=None):
    return lookup_artifact_context(artifact_type, artifact_value, provider=provider).model_dump()


def siem_explore_schema(target_index=None):
    result = siem_service.explore_schema(SchemaExplorerInput(target_index=target_index))
    if isinstance(result, list):
        return [item.model_dump() for item in result]
    return result.model_dump()


def siem_keyword_search(keyword, time_range_start, time_range_end, time_field="@timestamp", index_name=None):
    results = siem_service.keyword_search(
        KeywordSearchInput(
            keyword=keyword,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            time_field=time_field,
            index_name=index_name,
        )
    )
    return [item.model_dump() for item in results]


def siem_adaptive_query(index_name, time_range_start, time_range_end, time_field="@timestamp", filters=None, aggregation_fields=None):
    result = siem_service.execute_adaptive_query(
        AdaptiveQueryInput(
            index_name=index_name,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            time_field=time_field,
            filters=filters or {},
            aggregation_fields=aggregation_fields or [],
        )
    )
    return result.model_dump()


def siem_discover_index_fields(index_name, backend, time_range_start, time_range_end, doc_limit=10000, max_samples_per_field=20):
    return siem_service.discover_index_fields(
        DiscoverIndexFieldsInput(
            index_name=index_name,
            backend=backend,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            doc_limit=doc_limit,
            max_samples_per_field=max_samples_per_field,
        )
    ).model_dump()


def siem_execute_spl(query, time_range_start, time_range_end, limit=100, time_field="@timestamp", index_name=None):
    return siem_service.execute_spl(
        SPLQueryInput(
            query=query,
            limit=limit,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            time_field=time_field,
            index_name=index_name,
        )
    ).model_dump()


def siem_execute_esql(query, time_range_start, time_range_end, limit=100, time_field="@timestamp", index_name=None):
    return siem_service.execute_esql(
        ESQLQueryInput(
            query=query,
            limit=limit,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            time_field=time_field,
            index_name=index_name,
        )
    ).model_dump()


def _async_tool(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        return await sync_to_async(func, thread_sensitive=True)(*args, **kwargs)

    wrapper.__signature__ = signature(func)
    return wrapper


MCP_TOOL_FUNCTIONS = [
    read_stream_message_by_id,
    read_stream_head,
    list_cases,
    update_case,
    get_file,
    add_comment,
    list_alerts,
    list_artifacts,
    create_enrichment,
    list_playbook_templates,
    list_playbooks,
    execute_playbook,
    update_knowledge,
    search_knowledge,
    siem_explore_schema,
    siem_keyword_search,
    siem_adaptive_query,
    siem_discover_index_fields,
    siem_execute_spl,
    siem_execute_esql,
    ti_query,
    cmdb_lookup,
]

REGISTERED_MCP_TOOLS = [_async_tool(tool) for tool in MCP_TOOL_FUNCTIONS]
