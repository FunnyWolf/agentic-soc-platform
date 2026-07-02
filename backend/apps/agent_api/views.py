import json
import mimetypes

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from rest_framework import parsers, permissions, status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.views import APIView

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.accounts.models import UserApiKey
from apps.alerts.models import Alert
from apps.artifacts.models import Artifact
from apps.attachments.models import Attachment
from apps.audit.context import audit_actor
from apps.cases.models import Case
from apps.comments.models import Comment
from apps.comments.services import create_record_comment
from apps.common.cursor_pagination import paginate_created_at_cursor
from apps.common.redis_stream import RedisStreamClient
from apps.enrichments.models import Enrichment, EnrichmentProvider
from apps.knowledge.models import Knowledge
from apps.agentic.services.playbooks import create_pending_playbook_run, list_playbook_definitions
from apps.playbooks.models import Playbook
from integrations.cmdb.service import lookup_artifact_context
from integrations.siem import service as siem_service
from integrations.siem.models import (
    AdaptiveQueryInput,
    DiscoverIndexFieldsInput,
    ESQLQueryInput,
    KeywordSearchInput,
    SPLQueryInput,
    SchemaExplorerInput,
)
from integrations.threat_intel.service import query_indicator

from .responses import agent_response, pagination_meta
from .serializers import (
    serialize_alert,
    serialize_artifact,
    serialize_attachment,
    serialize_case,
    serialize_comment,
    serialize_enrichment,
    serialize_knowledge,
    serialize_playbook,
)
from .utils import bool_param, list_param, parse_tags, parse_timezone_aware_datetime


API_VERSION = "v1"
MIN_CLI_VERSION = "0.1.0"
SERVER_VERSION = "0.1.0"
FOUNDATION_CAPABILITIES = [
    "agent.version",
    "case.list",
    "case.show",
    "case.update_ai",
    "alert.list",
    "alert.show",
    "artifact.list",
    "artifact.show",
    "knowledge.search",
    "knowledge.show",
    "knowledge.update",
    "comment.list",
    "comment.add",
    "file.upload",
    "file.info",
    "file.read_text",
    "enrichment.create",
    "playbook.template.list",
    "playbook.list",
    "playbook.show",
    "playbook.run",
    "siem.schema",
    "siem.search.keyword",
    "siem.query.adaptive",
    "siem.fields.discover",
    "siem.query.spl",
    "siem.query.esql",
    "ti.query",
    "cmdb.lookup",
    "dev.stream.head",
    "dev.stream.read",
]


class AgentVersionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        api_key = request.auth if isinstance(request.auth, UserApiKey) else None
        data = {
            "api_version": API_VERSION,
            "server_version": getattr(settings, "ASP_VERSION", SERVER_VERSION),
            "min_cli_version": MIN_CLI_VERSION,
            "capabilities": FOUNDATION_CAPABILITIES,
            "user": {
                "username": request.user.username,
                "email": request.user.email,
                "role": request.user.role,
                "is_superuser": request.user.is_superuser,
            },
            "api_key": _api_key_payload(api_key),
        }
        return agent_response(request, operation="agent.version", data=data)


def _api_key_payload(api_key):
    if api_key is None:
        return None
    return {
        "name": api_key.name,
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "last_used_at": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
    }


class CaseListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Case.objects.all()
        if statuses := list_param(request.query_params, "status"):
            queryset = queryset.filter(status__in=statuses)
        if severities := list_param(request.query_params, "severity"):
            queryset = queryset.filter(severity__in=severities)
        if confidences := list_param(request.query_params, "confidence"):
            queryset = queryset.filter(confidence__in=confidences)
        if verdicts := list_param(request.query_params, "verdict"):
            queryset = queryset.filter(verdict__in=verdicts)
        if correlation_uid := request.query_params.get("correlation_uid"):
            queryset = queryset.filter(correlation_uid=correlation_uid)
        if title := request.query_params.get("title"):
            queryset = queryset.filter(title__icontains=title)
        for tag in parse_tags(request.query_params):
            queryset = queryset.filter(tags__contains=[tag])

        include_related = bool_param(request.query_params.get("include_related"), default=False)
        if include_related:
            queryset = queryset.prefetch_related("alerts")
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_case(case, include_related=include_related) for case in page.results]
        return agent_response(request, operation="case.list", data=data, pagination=pagination_meta(page))


class CaseDetailView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def get(self, request, case_id):
        case = _find_case(case_id)
        include_related = bool_param(request.query_params.get("include_related"), default=True)
        if include_related:
            case = Case.objects.prefetch_related("alerts").get(pk=case.pk)
        return agent_response(request, operation="case.show", data=serialize_case(case, include_related=include_related))


class CaseAIAnalysisView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def patch(self, request, case_id):
        case = _find_case(case_id)
        allowed_fields = {"severity_ai", "confidence_ai", "impact_ai", "priority_ai", "verdict_ai", "summary"}
        updates = {field: request.data[field] for field in allowed_fields if field in request.data}
        if not updates:
            raise ValidationError({"detail": "At least one AI analysis field is required."})
        for field, value in updates.items():
            setattr(case, field, value)
        with audit_actor(request.user):
            case.full_clean()
            case.save(update_fields=[*updates.keys(), "updated_at"])
        return agent_response(request, operation="case.update_ai", data=serialize_case(case, include_related=True), status=status.HTTP_200_OK)


class AlertListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Alert.objects.select_related("case")
        if statuses := list_param(request.query_params, "status"):
            queryset = queryset.filter(status__in=statuses)
        if severities := list_param(request.query_params, "severity"):
            queryset = queryset.filter(severity__in=severities)
        if confidences := list_param(request.query_params, "confidence"):
            queryset = queryset.filter(confidence__in=confidences)
        if correlation_uid := request.query_params.get("correlation_uid"):
            queryset = queryset.filter(correlation_uid=correlation_uid)
        if case_id := request.query_params.get("case_id"):
            queryset = queryset.filter(case__case_id=_record_id(case_id))
        include_related = bool_param(request.query_params.get("include_related"), default=False)
        if include_related:
            queryset = queryset.prefetch_related("artifacts")
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_alert(alert, include_related=include_related) for alert in page.results]
        return agent_response(request, operation="alert.list", data=data, pagination=pagination_meta(page))


class AlertDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, alert_id):
        alert = _find_alert(alert_id)
        include_related = bool_param(request.query_params.get("include_related"), default=True)
        if include_related:
            alert = Alert.objects.select_related("case").prefetch_related("artifacts").get(pk=alert.pk)
        return agent_response(request, operation="alert.show", data=serialize_alert(alert, include_related=include_related))


class ArtifactListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Artifact.objects.all()
        if types := list_param(request.query_params, "type"):
            queryset = queryset.filter(type__in=types)
        if roles := list_param(request.query_params, "role"):
            queryset = queryset.filter(role__in=roles)
        if value := request.query_params.get("value"):
            queryset = queryset.filter(value=value)
        include_related = bool_param(request.query_params.get("include_related"), default=False)
        if include_related:
            queryset = queryset.prefetch_related("alerts", "alerts__case")
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_artifact(artifact, include_related=include_related) for artifact in page.results]
        return agent_response(request, operation="artifact.list", data=data, pagination=pagination_meta(page))


class ArtifactDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, artifact_id):
        artifact = _find_artifact(artifact_id)
        include_related = bool_param(request.query_params.get("include_related"), default=True)
        if include_related:
            artifact = Artifact.objects.prefetch_related("alerts", "alerts__case").get(pk=artifact.pk)
        return agent_response(request, operation="artifact.show", data=serialize_artifact(artifact, include_related=include_related))


class KnowledgeListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Knowledge.objects.select_related("case")
        if keyword := request.query_params.get("keyword"):
            terms = [item.strip() for item in keyword.split(",") if item.strip()]
            query = Q()
            for term in terms:
                query |= Q(title__icontains=term) | Q(body__icontains=term) | Q(tags__contains=[term])
            queryset = queryset.filter(query)
        if source := request.query_params.get("source"):
            queryset = queryset.filter(source=source)
        if case_id := request.query_params.get("case_id"):
            queryset = queryset.filter(case__case_id=_record_id(case_id))
        for tag in parse_tags(request.query_params):
            queryset = queryset.filter(tags__contains=[tag])
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_knowledge(knowledge) for knowledge in page.results]
        return agent_response(request, operation="knowledge.search", data=data, pagination=pagination_meta(page))


class KnowledgeDetailView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def get(self, request, knowledge_id):
        return agent_response(request, operation="knowledge.show", data=serialize_knowledge(_find_knowledge(knowledge_id)))

    def patch(self, request, knowledge_id):
        knowledge = _find_knowledge(knowledge_id)
        allowed_fields = {"title", "body", "expires_at", "tags"}
        updates = {field: request.data[field] for field in allowed_fields if field in request.data}
        if not updates:
            raise ValidationError({"detail": "At least one knowledge field is required."})
        if "expires_at" in updates:
            updates["expires_at"] = parse_timezone_aware_datetime(updates["expires_at"], "expires_at")
        for field, value in updates.items():
            setattr(knowledge, field, value)
        with audit_actor(request.user):
            knowledge.full_clean()
            knowledge.save(update_fields=[*updates.keys(), "updated_at"])
        return agent_response(request, operation="knowledge.update", data=serialize_knowledge(knowledge))


class CommentListCreateView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def get(self, request):
        target_id = request.query_params.get("target_id")
        if not target_id:
            raise ValidationError({"target_id": "This query parameter is required."})
        target = _find_comment_target(target_id)
        content_type = _content_type_for_record(target)
        queryset = Comment.objects.filter(
            content_type=content_type,
            object_id=str(target.pk),
        ).select_related("author", "content_type", "parent").prefetch_related("mentions", "attachments").order_by("-created_at", "-id")
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_comment(comment, request=request) for comment in reversed(page.results)]
        return agent_response(request, operation="comment.list", data=data, pagination=pagination_meta(page))

    def post(self, request):
        target_id = request.data.get("target_id")
        if not target_id:
            raise ValidationError({"target_id": "This field is required."})
        target = _find_comment_target(target_id)
        attachments = _attachments_from_file_keys(request.data.get("file_keys") or request.data.get("file_key"))
        body = str(request.data.get("body") or "")
        if not body.strip() and not attachments:
            raise ValidationError({"detail": "body or file_keys are required."})
        comment = create_record_comment(
            author=request.user,
            content_object=target,
            body=body,
            parent=_parent_comment_for_target(target, request.data.get("parent_id")),
            mentions=_mention_users(request.data.get("mentions")),
            attachments=attachments,
        )
        return agent_response(request, operation="comment.add", data=serialize_comment(comment, request=request), status=status.HTTP_201_CREATED)


class FileUploadView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]

    def post(self, request):
        if "file" not in request.FILES:
            raise ValidationError({"file": "This field is required."})
        uploaded = request.FILES["file"]
        attachment = Attachment.objects.create(
            uploaded_by=request.user,
            file=uploaded,
            filename=uploaded.name,
            size=uploaded.size,
        )
        return agent_response(request, operation="file.upload", data=serialize_attachment(attachment, request=request), status=status.HTTP_201_CREATED)


class FileDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_key):
        return agent_response(request, operation="file.info", data=serialize_attachment(_find_attachment(file_key), request=request))


class FileReadTextView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_key):
        attachment = _find_attachment(file_key)
        max_bytes = _max_text_bytes(request.query_params.get("max_bytes"))
        content_type = mimetypes.guess_type(attachment.filename)[0] or "application/octet-stream"
        if not _is_text_content_type(content_type):
            raise ValidationError({"file_key": f"File is not a supported text type: {content_type}"})
        with attachment.file.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]
        data = {
            **serialize_attachment(attachment, request=request),
            "text": raw.decode("utf-8", errors="replace"),
            "truncated": truncated,
            "max_bytes": max_bytes,
        }
        return agent_response(request, operation="file.read_text", data=data)


class EnrichmentCreateView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def post(self, request):
        target = _find_enrichment_target(request.data.get("target_id"))
        enrichment = Enrichment(
            name=request.data.get("name", ""),
            type=request.data.get("type", "Other"),
            provider=EnrichmentProvider.ASP,
            uid=request.data.get("uid", ""),
            value=request.data.get("value", ""),
            desc=request.data.get("desc", ""),
            data=_json_object(request.data.get("data", {}), "data"),
        )
        if isinstance(target, Case):
            enrichment.case = target
        elif isinstance(target, Alert):
            enrichment.alert = target
        elif isinstance(target, Artifact):
            enrichment.artifact = target
        with audit_actor(request.user):
            enrichment.full_clean()
            enrichment.save()
        return agent_response(request, operation="enrichment.create", data=serialize_enrichment(enrichment), status=status.HTTP_201_CREATED)


class PlaybookTemplateListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return agent_response(request, operation="playbook.template.list", data=list_playbook_definitions(include_path=False))


class PlaybookListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Playbook.objects.select_related("case").all()
        if playbook_id := request.query_params.get("playbook_id"):
            queryset = queryset.filter(playbook_id=_record_id(playbook_id))
        if case_id := request.query_params.get("case_id"):
            queryset = queryset.filter(case__case_id=_record_id(case_id))
        if statuses := list_param(request.query_params, "job_status"):
            queryset = queryset.filter(job_status__in=statuses)
        include_related = bool_param(request.query_params.get("include_related"), default=False)
        page = paginate_created_at_cursor(queryset, request)
        data = [serialize_playbook(playbook, include_related=include_related) for playbook in page.results]
        return agent_response(request, operation="playbook.list", data=data, pagination=pagination_meta(page))


class PlaybookDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, playbook_id):
        playbook = _find_playbook(playbook_id)
        include_related = bool_param(request.query_params.get("include_related"), default=True)
        if include_related:
            playbook = Playbook.objects.select_related("case").get(pk=playbook.pk)
        return agent_response(request, operation="playbook.show", data=serialize_playbook(playbook, include_related=include_related))


class PlaybookRunView(APIView):
    permission_classes = [IsBusinessWriterOrReadOnly]

    def post(self, request):
        name = request.data.get("name")
        case_id = request.data.get("case_id")
        if not name:
            raise ValidationError({"name": "This field is required."})
        if not case_id:
            raise ValidationError({"case_id": "This field is required."})
        try:
            with audit_actor(request.user):
                playbook = create_pending_playbook_run(
                    name=name,
                    case=_find_case(case_id),
                    user=request.user,
                    user_input=request.data.get("user_input", ""),
                )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        return agent_response(request, operation="playbook.run", data=serialize_playbook(playbook), status=status.HTTP_201_CREATED)


class SIEMSchemaView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        result = siem_service.explore_schema(SchemaExplorerInput(target_index=request.query_params.get("target_index")))
        return agent_response(request, operation="siem.schema", data=_dump(result))


class SIEMKeywordSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        result = siem_service.keyword_search(KeywordSearchInput(**request.data))
        return agent_response(request, operation="siem.search.keyword", data=_dump(result))


class SIEMAdaptiveQueryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        result = siem_service.execute_adaptive_query(AdaptiveQueryInput(**request.data))
        return agent_response(request, operation="siem.query.adaptive", data=_dump(result))


class SIEMDiscoverFieldsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        result = siem_service.discover_index_fields(DiscoverIndexFieldsInput(**request.data))
        return agent_response(request, operation="siem.fields.discover", data=_dump(result))


class SIEMSPLQueryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        result = siem_service.execute_spl(SPLQueryInput(**request.data))
        return agent_response(request, operation="siem.query.spl", data=_dump(result))


class SIEMESQLQueryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        result = siem_service.execute_esql(ESQLQueryInput(**request.data))
        return agent_response(request, operation="siem.query.esql", data=_dump(result))


class ThreatIntelQueryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            result = query_indicator(
                request.data.get("indicator"),
                artifact_type=request.data.get("artifact_type", "Unknown"),
                provider=request.data.get("provider"),
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        return agent_response(request, operation="ti.query", data=_dump(result))


class CMDBLookupView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            result = lookup_artifact_context(
                request.data.get("artifact_type"),
                request.data.get("artifact_value"),
                provider=request.data.get("provider"),
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        return agent_response(request, operation="cmdb.lookup", data=_dump(result))


class DevStreamHeadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        stream_name = request.query_params.get("stream_name")
        if not stream_name:
            raise ValidationError({"stream_name": "This query parameter is required."})
        n = _bounded_int(request.query_params.get("n"), default=3, maximum=100)
        data = RedisStreamClient().read_stream_head(stream_name, n)
        return agent_response(request, operation="dev.stream.head", data=data)


class DevStreamReadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        stream_name = request.query_params.get("stream_name")
        message_id = request.query_params.get("message_id")
        if not stream_name:
            raise ValidationError({"stream_name": "This query parameter is required."})
        if not message_id:
            raise ValidationError({"message_id": "This query parameter is required."})
        data = RedisStreamClient().read_stream_message_by_id(stream_name, message_id)
        return agent_response(request, operation="dev.stream.read", data=data)


def _record_id(value):
    return str(value or "").strip().lower()


def _find_case(case_id):
    try:
        return Case.objects.get(case_id=_record_id(case_id))
    except Case.DoesNotExist as exc:
        raise NotFound(f"Case not found: {case_id}") from exc


def _find_alert(alert_id):
    try:
        return Alert.objects.select_related("case").get(alert_id=_record_id(alert_id))
    except Alert.DoesNotExist as exc:
        raise NotFound(f"Alert not found: {alert_id}") from exc


def _find_artifact(artifact_id):
    try:
        return Artifact.objects.get(artifact_id=_record_id(artifact_id))
    except Artifact.DoesNotExist as exc:
        raise NotFound(f"Artifact not found: {artifact_id}") from exc


def _find_knowledge(knowledge_id):
    try:
        return Knowledge.objects.select_related("case").get(knowledge_id=_record_id(knowledge_id))
    except Knowledge.DoesNotExist as exc:
        raise NotFound(f"Knowledge not found: {knowledge_id}") from exc


def _find_playbook(playbook_id):
    try:
        return Playbook.objects.select_related("case").get(playbook_id=_record_id(playbook_id))
    except Playbook.DoesNotExist as exc:
        raise NotFound(f"Playbook not found: {playbook_id}") from exc


def _find_attachment(file_key):
    try:
        return Attachment.objects.get(access_key=file_key)
    except (Attachment.DoesNotExist, ValueError) as exc:
        raise NotFound(f"File not found: {file_key}") from exc


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
    raise ValidationError({"target_id": "Must start with case_, alert_, artifact_, enrichment_, knowledge_, or playbook_."})


def _find_enrichment_target(target_id):
    target_id = _record_id(target_id)
    if target_id.startswith("case_"):
        return _find_case(target_id)
    if target_id.startswith("alert_"):
        return _find_alert(target_id)
    if target_id.startswith("artifact_"):
        return _find_artifact(target_id)
    raise ValidationError({"target_id": "Must start with case_, alert_, or artifact_."})


def _find_enrichment(enrichment_id):
    try:
        return Enrichment.objects.select_related("case", "alert", "artifact").get(enrichment_id=_record_id(enrichment_id))
    except Enrichment.DoesNotExist as exc:
        raise NotFound(f"Enrichment not found: {enrichment_id}") from exc


def _content_type_for_record(record):
    return ContentType.objects.get_for_model(record, for_concrete_model=False)


def _parent_comment_for_target(content_object, parent_id):
    if parent_id in (None, ""):
        return None
    try:
        parent = Comment.objects.get(pk=int(parent_id))
    except (TypeError, ValueError, Comment.DoesNotExist) as exc:
        raise NotFound(f"Parent comment not found: {parent_id}") from exc
    content_type = _content_type_for_record(content_object)
    if parent.content_type_id != content_type.id or parent.object_id != str(content_object.pk):
        raise ValidationError({"parent_id": "Must belong to the same target."})
    return parent


def _mention_users(mentions):
    users = []
    seen_ids = set()
    user_model = get_user_model()
    for item in _coerce_list(mentions):
        text = str(item or "").strip()
        if not text:
            continue
        user = user_model.objects.filter(username=text).first()
        if user is None and text.isdigit():
            user = user_model.objects.filter(pk=int(text)).first()
        if user is None:
            raise ValidationError({"mentions": f"User not found: {text}"})
        if user.id not in seen_ids:
            users.append(user)
            seen_ids.add(user.id)
    return users


def _attachments_from_file_keys(file_keys):
    keys = _coerce_list(file_keys)
    attachments = []
    for key in keys:
        attachments.append(_find_attachment(key))
    return attachments


def _coerce_list(value):
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, list):
                return decoded
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return [value]


def _json_object(value, field_name):
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValidationError({field_name: "Must be a valid JSON object."}) from exc
        if isinstance(payload, dict):
            return payload
    raise ValidationError({field_name: "Must be a valid JSON object."})


def _max_text_bytes(value):
    try:
        parsed = int(value or 65536)
    except (TypeError, ValueError):
        parsed = 65536
    return max(1, min(parsed, 262144))


def _is_text_content_type(content_type):
    return (
        content_type.startswith("text/")
        or content_type in {"application/json", "application/xml", "application/yaml", "application/x-yaml"}
    )


def _bounded_int(value, *, default, maximum):
    try:
        parsed = int(value or default)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def _dump(value):
    if isinstance(value, list):
        return [_dump(item) for item in value]
    if isinstance(value, dict):
        return {key: _dump(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return value
