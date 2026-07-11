from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver

from apps.common.models import BaseModel
from .context import get_current_actor
from .helpers import readable_label, write_relation_event
from .models import AuditLog

RELATION_FK_FIELDS = {
    "alert": {"case": "alerts"},
    "playbook": {"case": "playbooks"},
    "enrichment": {"case": "enrichments", "alert": "enrichments", "artifact": "enrichments"},
}


def audit_model(sender):
    return isinstance(sender, type) and issubclass(sender, BaseModel) and not sender._meta.abstract


def serialize_value(value):
    if hasattr(value, "pk"):
        return str(value.pk)
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def relation_fields(sender):
    return RELATION_FK_FIELDS.get(sender._meta.model_name, {})


def relation_parent(instance, field_name):
    try:
        return getattr(instance, field_name, None)
    except ObjectDoesNotExist:
        return None


def changed_fields(sender, before, after):
    changes = {}
    ignored_fields = {"created_at", "updated_at"}
    for field in sender._meta.concrete_fields:
        if field.name in ignored_fields:
            continue
        old_value = serialize_value(getattr(before, field.name))
        new_value = serialize_value(getattr(after, field.name))
        if old_value != new_value:
            changes[field.name] = {"from": old_value, "to": new_value}
    return changes


def write_fk_relation_events(sender, before, after, created=False):
    for field_name, relation in relation_fields(sender).items():
        old_parent = None if created or before is None else getattr(before, field_name, None)
        new_parent = getattr(after, field_name, None)
        if old_parent == new_parent:
            continue
        if old_parent:
            write_relation_event(old_parent, "unlinked", relation, after)
        if new_parent:
            write_relation_event(new_parent, "linked", relation, after)


def write_delete_relation_events(sender, instance):
    parents = getattr(instance, "_audit_delete_relation_parents", {})
    for field_name, relation in relation_fields(sender).items():
        parent = parents.get(field_name) or relation_parent(instance, field_name)
        if parent:
            write_relation_event(parent, "deleted", relation, instance)


@receiver(pre_save)
def capture_previous_state(sender, instance, **kwargs):
    if not audit_model(sender) or not instance.pk:
        instance._audit_previous = None
        return
    instance._audit_previous = sender.objects.filter(pk=instance.pk).first()


@receiver(pre_delete)
def capture_delete_relation_parents(sender, instance, **kwargs):
    if not audit_model(sender):
        return
    parents = {}
    for field_name in relation_fields(sender):
        parent = relation_parent(instance, field_name)
        if parent is not None:
            parents[field_name] = parent
    instance._audit_delete_relation_parents = parents

@receiver(post_save)
def log_save(sender, instance, created, **kwargs):
    if not audit_model(sender):
        return
    action = "create" if created else "update"
    previous = getattr(instance, "_audit_previous", None)
    changes = {} if created or previous is None else changed_fields(sender, previous, instance)
    if not created and not changes:
        return
    AuditLog.objects.create(
        content_type=ContentType.objects.get_for_model(sender),
        object_id=str(instance.id),
        action=action,
        actor=get_current_actor(),
        changes=changes,
    )
    write_fk_relation_events(sender, previous, instance, created=created)

@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    if not audit_model(sender):
        return
    AuditLog.objects.create(
        content_type=ContentType.objects.get_for_model(sender),
        object_id=str(instance.id),
        action="delete",
        actor=get_current_actor(),
        metadata={"deleted_label": readable_label(instance)},
    )
    write_delete_relation_events(sender, instance)


@receiver(m2m_changed)
def log_many_to_many_change(sender, instance, action, reverse, model, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return
    if not isinstance(instance, BaseModel):
        return

    field_name = None
    for field in instance._meta.many_to_many:
        if field.remote_field.through is sender:
            field_name = field.name
            break
    if not field_name:
        return

    if action == "post_clear":
        return

    relation_action = "linked" if action == "post_add" else "unlinked"
    for related_object in model.objects.filter(pk__in=pk_set or []):
        write_relation_event(instance, relation_action, field_name, related_object)
