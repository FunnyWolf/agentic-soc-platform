import csv
import io
import json

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.db.models import CharField, Q, Value
from django.db.models.functions import Cast, Coalesce, Concat
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin
from apps.common.cursor_pagination import cursor_response_payload, paginate_created_at_cursor
from apps.common.readable_ids import format_readable_id, parse_readable_id_number
from .helpers import readable_label
from .models import AuditLog
EXPORT_MAX_ROWS = 50000
EXPORT_MAX_ROWS = 50000

RESOURCE_MODEL_TO_KEY = {
    "case": "cases",
    "alert": "alerts",
    "artifact": "artifacts",
    "enrichment": "enrichments",
    "playbook": "playbooks",
    "knowledge": "knowledge",
    "user": "users",
    "llmproviderconfig": "llm-providers",
    "threatintelalienvaultotxconfig": "threat-intel-otx",
    "threatintelopencticonfig": "threat-intel-opencti",
    "siemsplunkconfig": "siem-splunk",
    "siemelkconfig": "siem-elk",
    "ldapconfig": "ldap",
    "runtimeconfig": "runtime",
}

RESOURCE_LABELS = {
    "case": "Case",
    "alert": "Alert",
    "artifact": "Artifact",
    "enrichment": "Enrichment",
    "playbook": "Playbook",
    "knowledge": "Knowledge",
    "user": "User",
    "llmproviderconfig": "LLM Provider",
    "threatintelalienvaultotxconfig": "AlienVault OTX Settings",
    "threatintelopencticonfig": "OpenCTI Settings",
    "siemsplunkconfig": "Splunk Settings",
    "siemelkconfig": "ELK Settings",
    "ldapconfig": "LDAP Settings",
    "runtimeconfig": "Runtime Settings",
}


def foreign_key_field(model, field_name):
    try:
        field = model._meta.get_field(field_name)
    except FieldDoesNotExist:
        return None
    if getattr(field, "many_to_one", False) and getattr(field, "remote_field", None):
        return field
    return None


def related_labels(field, values):
    related_model = field.remote_field.model
    if not isinstance(related_model, type):
        return {}
    lookup_values = [value for value in values if value not in (None, "")]
    if not lookup_values:
        return {}
    return {
        str(obj.pk): readable_label(obj)
        for obj in related_model._default_manager.filter(pk__in=lookup_values)
    }


def display_changes(log):
    changes = log.changes or {}
    model = log.content_type.model_class()
    if not model or not isinstance(changes, dict):
        return changes

    display = {}
    for field_name, raw_change in changes.items():
        if not isinstance(raw_change, dict):
            display[field_name] = raw_change
            continue

        field = foreign_key_field(model, field_name)
        if not field:
            display[field_name] = raw_change
            continue

        labels = related_labels(
            field,
            [raw_change[key] for key in ("from", "to") if key in raw_change],
        )
        display_change = dict(raw_change)
        for key in ("from", "to"):
            if key in display_change:
                display_change[key] = labels.get(str(display_change[key]), display_change[key])
        display[field_name] = display_change
    return display


def datetime_param(params, name):
    raw_value = params.get(name)
    if not raw_value:
        return None
    value = parse_datetime(raw_value)
    if value is None:
        raise ValidationError({name: "Invalid datetime."})
    if timezone.is_naive(value):
        return timezone.make_aware(value)
    return value


def _json_text(value):
    return json.dumps(value or {}, ensure_ascii=False, sort_keys=True)


def _readable_id(log):
    return format_readable_id("audit", log.id)


def _actor_name(log):
    if not log.actor:
        return ""
    return log.actor.get_full_name() or log.actor.username


def _resource_label(content_type):
    return RESOURCE_LABELS.get(content_type.model, content_type.model.replace("_", " ").title())


def _resource_key(content_type):
    return RESOURCE_MODEL_TO_KEY.get(content_type.model, f"{content_type.model}s")


def _changed_field_names(log):
    return list((log.changes or {}).keys())


def _field_summary(log):
    metadata = log.metadata or {}
    relation = metadata.get("relation")
    if relation:
        return str(relation)
    field_names = _changed_field_names(log)
    if not field_names:
        return ""
    if len(field_names) == 1:
        return field_names[0]
    return f"{len(field_names)} fields"


def _log_summary(log):
    actor = _actor_name(log) if log.actor else "system"
    resource = _resource_label(log.content_type)
    field = _field_summary(log)
    if field:
        return f"{actor} {log.action} {resource} {log.object_id} ({field})"
    return f"{actor} {log.action} {resource} {log.object_id}"


def audit_log_payload(log):
    metadata = log.metadata or {}
    return {
        "id": log.id,
        "readable_id": _readable_id(log),
        "title": _readable_id(log),
        "action": log.action,
        "actor": log.actor.username if log.actor else None,
        "actor_id": log.actor_id,
        "actor_name": _actor_name(log),
        "content_type": log.content_type.model,
        "content_type_model": log.content_type.model,
        "content_type_app": log.content_type.app_label,
        "resource_type": log.content_type.model,
        "resource_key": _resource_key(log.content_type),
        "resource_label": _resource_label(log.content_type),
        "object_id": log.object_id,
        "field_summary": _field_summary(log),
        "summary": _log_summary(log),
        "related_resource": metadata.get("related_resource") or "",
        "related_id": metadata.get("related_id") or "",
        "related_label": metadata.get("related_label") or "",
        "relation": metadata.get("relation") or "",
        "changes": log.changes,
        "display_changes": display_changes(log),
        "metadata": metadata,
        "changes_json": _json_text(log.changes),
        "metadata_json": _json_text(metadata),
        "created_at": log.created_at,
    }


def _values(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(value)]


def _text_q(field, operator, value):
    values = _values(value)
    if operator == "is_empty":
        return Q(**{field: ""}) | Q(**{f"{field}__isnull": True})
    if operator == "is_not_empty":
        return ~(Q(**{field: ""}) | Q(**{f"{field}__isnull": True}))
    if not values:
        raise ValidationError("Filter value is required.")
    if operator == "eq":
        return Q(**{field: values[0]})
    if operator == "neq":
        return ~Q(**{field: values[0]})
    if operator == "contains":
        return Q(**{f"{field}__icontains": values[0]})
    if operator == "not_contains":
        return ~Q(**{f"{field}__icontains": values[0]})
    if operator == "contains_all":
        query = Q()
        for item in values:
            query &= Q(**{f"{field}__icontains": item})
        return query
    raise ValidationError(f"Unsupported filter operator: {operator}")


def _select_q(field, operator, value):
    values = _values(value)
    if operator == "is_empty":
        return Q(**{field: ""}) | Q(**{f"{field}__isnull": True})
    if operator == "is_not_empty":
        return ~(Q(**{field: ""}) | Q(**{f"{field}__isnull": True}))
    if not values:
        raise ValidationError("Filter value is required.")
    if operator == "is":
        return Q(**{field: values[0]})
    if operator == "is_not":
        return ~Q(**{field: values[0]})
    if operator == "is_one_of":
        return Q(**{f"{field}__in": values})
    if operator == "is_not_any_of":
        return ~Q(**{f"{field}__in": values})
    raise ValidationError(f"Unsupported filter operator: {operator}")


def _date_q(field, operator, value):
    values = _values(value)
    if operator == "is_empty":
        return Q(**{f"{field}__isnull": True})
    if operator == "is_not_empty":
        return Q(**{f"{field}__isnull": False})
    if not values:
        raise ValidationError("Filter value is required.")
    if operator in {"between", "not_between"}:
        if len(values) != 2:
            raise ValidationError("Range filters require two values.")
        query = Q(**{f"{field}__gte": values[0], f"{field}__lte": values[1]})
        return ~query if operator == "not_between" else query
    lookup = {
        "eq": "",
        "neq": "",
        "lt": "__lt",
        "gt": "__gt",
        "lte": "__lte",
        "gte": "__gte",
    }.get(operator)
    if lookup is None:
        raise ValidationError(f"Unsupported filter operator: {operator}")
    query = Q(**{f"{field}{lookup}": values[0]})
    return ~query if operator == "neq" else query


def _field_filter_q(operator, value):
    values = _values(value)
    if operator == "is_empty":
        return Q(changes={}) & (Q(metadata__relation="") | Q(metadata__relation__isnull=True))
    if operator == "is_not_empty":
        return ~_field_filter_q("is_empty", None)
    if not values:
        raise ValidationError("Filter value is required.")
    if operator in {"is", "eq"}:
        return Q(changes__has_key=values[0]) | Q(metadata__relation=values[0])
    if operator in {"is_not", "neq"}:
        return ~(Q(changes__has_key=values[0]) | Q(metadata__relation=values[0]))
    if operator == "contains":
        return Q(changes_text__icontains=values[0]) | Q(metadata__relation__icontains=values[0])
    if operator == "not_contains":
        return ~(Q(changes_text__icontains=values[0]) | Q(metadata__relation__icontains=values[0]))
    if operator == "is_one_of":
        query = Q()
        for item in values:
            query |= Q(changes__has_key=item) | Q(metadata__relation=item)
        return query
    if operator == "is_not_any_of":
        query = Q()
        for item in values:
            query |= Q(changes__has_key=item) | Q(metadata__relation=item)
        return ~query
    raise ValidationError(f"Unsupported filter operator: {operator}")


def _actor_filter_q(operator, value):
    values = _values(value)
    if operator == "is_empty":
        return Q(actor__isnull=True)
    if operator == "is_not_empty":
        return Q(actor__isnull=False)
    if not values:
        raise ValidationError("Filter value is required.")

    include_system = "system" in values
    user_values = [item for item in values if item != "system"]
    query = Q()
    if include_system:
        query |= Q(actor__isnull=True)
    if user_values:
        query |= Q(actor_id__in=user_values)

    if operator in {"is", "is_one_of"}:
        return query
    if operator in {"is_not", "is_not_any_of"}:
        return ~query
    raise ValidationError(f"Unsupported filter operator: {operator}")


def _advanced_filter_condition(item):
    field = str(item.get("field") or "")
    operator = str(item.get("operator") or "")
    value = item.get("value")
    if field == "field":
        return _field_filter_q(operator, value)
    if field == "resource_type":
        return _select_q("content_type__model", operator, value)
    if field == "actor":
        return _actor_filter_q(operator, value)
    field_map = {
        "action": ("select", "action"),
        "object_id": ("text", "object_id"),
        "related_resource": ("text", "metadata__related_resource"),
        "related_id": ("text", "metadata__related_id"),
        "related_label": ("text", "metadata__related_label"),
        "relation": ("text", "metadata__relation"),
        "changes": ("text", "changes_text"),
        "metadata": ("text", "metadata_text"),
        "created_at": ("date", "created_at"),
    }
    field_config = field_map.get(field)
    if not field_config:
        raise ValidationError(f"Unsupported filter field: {field}")
    value_type, lookup_field = field_config
    if value_type == "select":
        return _select_q(lookup_field, operator, value)
    if value_type == "date":
        return _date_q(lookup_field, operator, value)
    return _text_q(lookup_field, operator, value)


def _apply_advanced_filters(queryset, raw_filters):
    if not raw_filters:
        return queryset
    try:
        filters = json.loads(raw_filters)
    except json.JSONDecodeError as exc:
        raise ValidationError("advanced_filters must be valid JSON.") from exc
    if not isinstance(filters, list):
        raise ValidationError("advanced_filters must be a list.")

    combined = Q()
    has_condition = False
    for item in filters:
        if not isinstance(item, dict):
            raise ValidationError("Each advanced filter must be an object.")
        condition = _advanced_filter_condition(item)
        if not has_condition:
            combined = condition
            has_condition = True
        elif item.get("connector") == "or":
            combined |= condition
        else:
            combined &= condition
    return queryset.filter(combined).distinct() if has_condition else queryset


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = AuditLog.objects.select_related("actor", "content_type")
        params = self.request.query_params
        ct = params.get("content_type")
        oid = params.get("object_id")
        if ct and oid:
            try:
                ct_model = ContentType.objects.get(model=ct)
                qs = qs.filter(content_type=ct_model, object_id=oid)
            except ContentType.DoesNotExist:
                qs = qs.none()

        action = params.get("action")
        if action:
            qs = qs.filter(action=action)

        actor = params.get("actor")
        if actor == "system":
            qs = qs.filter(actor__isnull=True)
        elif actor:
            qs = qs.filter(actor_id=actor)

        field = params.get("field")
        if field:
            qs = qs.filter(Q(changes__has_key=field) | Q(metadata__relation=field))

        created_after = datetime_param(params, "created_after")
        if created_after:
            qs = qs.filter(created_at__gte=created_after)

        created_before = datetime_param(params, "created_before")
        if created_before:
            qs = qs.filter(created_at__lte=created_before)

        return qs

    def list(self, request, *args, **kwargs):
        page = paginate_created_at_cursor(self.get_queryset(), request)
        data = [
            {
                "id": log.id,
                "action": log.action,
                "actor": log.actor.username if log.actor else None,
                "actor_id": log.actor_id,
                "actor_name": log.actor.get_full_name() if log.actor else "",
                "changes": log.changes,
                "display_changes": display_changes(log),
                "metadata": log.metadata,
                "created_at": log.created_at,
            }
            for log in page.results
        ]
        return Response(cursor_response_payload(page, data))


class AdminAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    pagination_class = None
    ordering_fields = (
        "created_at",
        "action",
        "object_id",
        "content_type__model",
        "actor__username",
    )

    def base_queryset(self):
        return AuditLog.objects.select_related("actor", "content_type").annotate(
            changes_text=Cast("changes", output_field=CharField()),
            metadata_text=Cast("metadata", output_field=CharField()),
            actor_display=Concat(
                Coalesce("actor__first_name", Value("")),
                Value(" "),
                Coalesce("actor__last_name", Value("")),
                output_field=CharField(),
            ),
        )

    def get_queryset(self):
        queryset = self.base_queryset()
        params = self.request.query_params

        action_value = params.get("action")
        if action_value:
            queryset = queryset.filter(action=action_value)

        actor = params.get("actor")
        if actor == "system":
            queryset = queryset.filter(actor__isnull=True)
        elif actor:
            queryset = queryset.filter(actor_id=actor)

        resource_type = params.get("resource_type")
        if resource_type:
            queryset = queryset.filter(content_type__model__in=_values(resource_type))

        created_after = datetime_param(params, "created_after")
        if created_after:
            queryset = queryset.filter(created_at__gte=created_after)

        created_before = datetime_param(params, "created_before")
        if created_before:
            queryset = queryset.filter(created_at__lte=created_before)

        search = (params.get("search") or "").strip()
        if search:
            search_query = (
                Q(action__icontains=search)
                | Q(object_id__icontains=search)
                | Q(content_type__model__icontains=search)
                | Q(content_type__app_label__icontains=search)
                | Q(actor__username__icontains=search)
                | Q(actor__email__icontains=search)
                | Q(actor_display__icontains=search)
                | Q(changes_text__icontains=search)
                | Q(metadata_text__icontains=search)
            )
            readable_id_number = parse_readable_id_number(search.lower(), "audit")
            if readable_id_number:
                search_query |= Q(id=readable_id_number)
            queryset = queryset.filter(search_query)

        queryset = _apply_advanced_filters(queryset, params.get("advanced_filters"))

        ordering = params.get("ordering")
        if ordering:
            field_name = ordering[1:] if ordering.startswith("-") else ordering
            if field_name not in self.ordering_fields:
                raise ValidationError({"ordering": "Unsupported ordering field."})
            return queryset.order_by(ordering, "-id")
        return queryset.order_by("-created_at", "-id")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page_number = request.query_params.get("page")
        page_size = request.query_params.get("page_size")
        if page_number is not None or page_size is not None:
            from apps.common.pagination import StandardResultsSetPagination

            paginator = StandardResultsSetPagination()
            page = paginator.paginate_queryset(queryset, request, view=self)
            data = [audit_log_payload(log) for log in page]
            return paginator.get_paginated_response(data)

        data = [audit_log_payload(log) for log in queryset[:100]]
        return Response({"count": queryset.count(), "results": data})

    def retrieve(self, request, *args, **kwargs):
        log = get_object_or_404(self.base_queryset(), pk=kwargs.get("pk"))
        return Response(audit_log_payload(log))

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        queryset = self.get_queryset()

        total = queryset.count()
        if total > EXPORT_MAX_ROWS:
            raise ValidationError({
                "detail": f"Export matches {total} rows. Narrow the filters to {EXPORT_MAX_ROWS} rows or fewer."
            })

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "audit_id",
            "created_at",
            "actor",
            "actor_id",
            "action",
            "resource_type",
            "object_id",
            "field_or_relation",
            "related_resource",
            "related_id",
            "related_label",
            "changes_json",
            "metadata_json",
        ])
        for log in queryset[:EXPORT_MAX_ROWS]:
            metadata = log.metadata or {}
            writer.writerow([
                _readable_id(log),
                log.created_at.isoformat(),
                log.actor.username if log.actor else "system",
                log.actor_id or "",
                log.action,
                log.content_type.model,
                log.object_id,
                _field_summary(log),
                metadata.get("related_resource") or "",
                metadata.get("related_id") or "",
                metadata.get("related_label") or "",
                _json_text(log.changes),
                _json_text(metadata),
            ])

        filename = timezone.now().strftime("audit-logs-%Y%m%d-%H%M%S.csv")
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
