import logging

from .services import send_system_message

logger = logging.getLogger(__name__)

MAX_REMARK_LENGTH = 500


def _user_display_name(user):
    if not user:
        return "System"
    return user.get_full_name() or user.username


def _record_label(record, readable_id_field):
    readable_id = getattr(record, readable_id_field, "") or ""
    title = getattr(record, "title", "") or getattr(record, "name", "") or ""
    if readable_id and title:
        return f"{readable_id.upper()} / {title}"
    return readable_id.upper() or title or str(record.pk)


def _truncate(value, limit=MAX_REMARK_LENGTH):
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _string_id(value):
    if value is None:
        return None
    return str(value)


def _wants_notification(user, field_name):
    return bool(
        user
        and getattr(user, "is_active", False)
        and getattr(user, field_name, True)
    )


def notify_playbook_completion(playbook):
    user = None
    try:
        user = getattr(playbook, "user", None)
        if not _wants_notification(user, "notify_on_playbook_completion"):
            return None

        case = getattr(playbook, "case", None)
        playbook_label = _record_label(playbook, "playbook_id")
        lines = [
            f"Playbook {playbook_label} finished with status {playbook.job_status}.",
        ]
        if case:
            lines.append(f"Case: {_record_label(case, 'case_id')}")
        if playbook.remark:
            lines.extend(["", f"Remark: {_truncate(playbook.remark)}"])

        return send_system_message(
            recipients=[user],
            body="\n".join(lines),
            content_object=playbook,
            metadata={
                "source": "playbook_completion",
                "playbook_id": playbook.playbook_id,
                "playbook_pk": _string_id(playbook.pk),
                "case_id": getattr(case, "case_id", ""),
                "case_pk": _string_id(getattr(case, "pk", None)),
                "status": playbook.job_status,
            },
        )
    except Exception:
        logger.exception(
            "Failed to send playbook completion notification: playbook_id=%s user_id=%s",
            getattr(playbook, "pk", None),
            getattr(user, "pk", None),
        )
        return None


def notify_case_assignment(case, *, previous_assignee_id=None, actor=None):
    assignee_id = None
    try:
        assignee = getattr(case, "assignee", None)
        assignee_id = getattr(assignee, "id", None)
        if not assignee_id or assignee_id == previous_assignee_id:
            return None
        if actor and getattr(actor, "id", None) == assignee_id:
            return None
        if not _wants_notification(assignee, "notify_on_case_assignment"):
            return None

        case_label = _record_label(case, "case_id")
        actor_name = _user_display_name(actor)
        body = f"{actor_name} assigned Case {case_label} to you."

        return send_system_message(
            recipients=[assignee],
            body=body,
            content_object=case,
            metadata={
                "source": "case_assignment",
                "case_id": case.case_id,
                "case_pk": _string_id(case.pk),
                "actor_id": getattr(actor, "pk", None),
                "previous_assignee_id": previous_assignee_id,
                "assignee_id": assignee_id,
            },
        )
    except Exception:
        logger.exception(
            "Failed to send case assignment notification: case_id=%s user_id=%s",
            getattr(case, "pk", None),
            assignee_id,
        )
        return None
