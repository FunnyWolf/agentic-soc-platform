import hashlib


def inbox_group_name(user_id):
    return f"inbox.user.{user_id}"


def comments_group_name(content_type, object_id):
    identity = f"{content_type}:{object_id}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"comments.record.{digest}"

