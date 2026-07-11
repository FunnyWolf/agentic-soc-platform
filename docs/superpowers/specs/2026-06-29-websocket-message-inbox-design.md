# WebSocket Message and Inbox Design

## Context

The current Inbox and comment flows use REST APIs for writes and cursor-based reads. `InboxDrawer` also polls unread count every 60 seconds. This design replaces polling with a WebSocket realtime channel while keeping REST as the durable source of truth for creation, pagination, manual refresh, and reconnect recovery.

The scope covers both:

- Inbox user/system messages, including unread count, new messages, replies, deletes, mark-read, and mark-all-read state.
- Resource comments in `DiscussionThread`, including new comments and deleted comments for the currently viewed record.

## Chosen approach

Use Django Channels with `channels-redis`.

Reasons:

- The backend already runs an ASGI service and uses Redis.
- Channels keeps authentication, ORM access, serializers, permissions, and transaction handling inside the Django ecosystem.
- User-level Inbox groups and record-level comment groups map naturally to Channels groups.
- REST endpoints can remain stable, reducing migration risk.

Rejected alternatives:

- Handwritten Starlette WebSocket handling would avoid dependencies but would duplicate JWT auth, connection management, group subscription, and Django permission integration.
- SSE would be simpler for one-way events but is not the requested WebSocket direction and is less flexible for dynamic subscribe/unsubscribe.

## Architecture

Add a dedicated realtime module, such as `apps.realtime`, responsible for:

- WebSocket consumers.
- Event type definitions and payload shape.
- Broadcast helpers used by Inbox and Comments.
- Subscription permission checks.

`apps.inbox` and `apps.comments` remain owners of their domain writes. They emit realtime events only after successful database commits. They do not manage socket connections directly.

Expose a single WebSocket endpoint:

```text
/ws/events/
```

ASGI should route `/ws/events/` to Channels while preserving the existing Django HTTP app and the existing `/api/mcp` ASGI mount.

Redis is used as the Channels channel layer through the existing Redis configuration.

## Groups and subscriptions

Each authenticated connection automatically joins its Inbox group:

```text
inbox.user.<user_id>
```

The frontend can subscribe and unsubscribe to resource comment groups as the user opens or leaves a record detail view:

```text
comments.<content_type>.<object_id>
```

Inbox events are only sent to the affected user's group. Comment events are sent only to the matching resource group.

WebSocket messages are not used for domain writes. Creating comments, sending messages, deleting messages, and marking messages read continue to use existing REST endpoints.

## Event envelope

All server-to-client events use a common envelope:

```json
{
  "type": "inbox.message_created",
  "event_id": "uuid-or-stable-id",
  "occurred_at": "2026-06-29T03:13:11Z",
  "actor_id": 1,
  "payload": {}
}
```

`event_id` lets the frontend deduplicate events. `occurred_at` helps decide whether reconnect recovery needs a REST refresh. `payload` contains a typed body for each event.

## Inbox events

The Inbox realtime channel supports:

- `inbox.message_created`: carries a complete serialized `InboxMessage`.
- `inbox.message_deleted`: carries `message_id`.
- `inbox.message_read`: carries `message_id` and `read_at`.
- `inbox.all_read`: carries `read_at` and enough state for the frontend to mark loaded items as read.
- `inbox.unread_count_changed`: carries the latest unread count and is the authoritative badge value.

The frontend should still call `fetchInboxUnreadCount()` once after login or reconnect. After that, `inbox.unread_count_changed` updates the badge. When the drawer is open, message events update the loaded list in place. Manual refresh remains available.

## Comment events

The comment realtime channel supports:

- `comment.created`: carries a complete serialized `RecordComment`.
- `comment.deleted`: carries `comment_id`.

`DiscussionThread` continues to use REST for initial load, cursor pagination, and manual refresh. While mounted, it subscribes to its current `content_type` and `object_id`; on unmount or record switch, it unsubscribes.

If search is active, the component still applies local filtering to the current loaded list after realtime updates.

## Consistency and transactions

Broadcasts must be scheduled with `transaction.on_commit()` so clients only receive events after the corresponding database state is committed.

For events that include serialized objects, serialization should happen after commit or from a freshly loaded object so payloads match what REST readers can retrieve.

The client treats REST as the source of truth. WebSocket updates are incremental hints that keep already-loaded UI state fresh.

## Authentication and reconnect behavior

The frontend authenticates the WebSocket connection with the current JWT. Because browser WebSocket APIs cannot set arbitrary headers, the implementation can use either a query token or a supported subprotocol-based token exchange. The design does not require HTTPS/WSS as a functional prerequisite, though production deployments may still choose WSS.

If authentication fails, the server closes the socket with a clear close code. The frontend should surface login expiration through existing auth behavior.

Reconnect behavior is hybrid:

- Initial data and pagination remain REST-based.
- While disconnected, UI keeps existing data and can show a non-blocking realtime connection warning.
- On reconnect, the frontend refreshes unread count and any currently open Inbox/comment view via REST, then resumes incremental events.
- Event handlers deduplicate by `event_id` and entity id to avoid double-inserting the current user's own writes.

## Frontend integration

Add a global realtime connection layer, for example `RealtimeProvider` plus `useRealtime`.

Responsibilities:

- Connect after login and disconnect on logout.
- Maintain connection status.
- Send heartbeat or respond to server ping if needed.
- Reconnect with backoff.
- Dispatch typed events to subscribers.
- Track comment subscriptions for mounted `DiscussionThread` instances.

`InboxDrawer` changes:

- Remove the 60-second unread polling timer.
- Load unread count once after login/reconnect.
- Use realtime unread-count events for the badge.
- Use realtime message events to update currently loaded rows.
- Keep manual refresh and REST pagination.

`DiscussionThread` changes:

- Subscribe to the current record group while mounted.
- Apply `comment.created` and `comment.deleted` events to loaded comments.
- Keep REST for create/delete, initial load, pagination, search, and manual refresh.

## Deployment and documentation

Add the Channels dependencies and route `/ws/events/` to the ASGI service. Deployment documentation only needs to mention that `/ws/` must be proxied to the ASGI service; it does not need to describe the internal Channels or Redis details.

No database migration is expected because the design does not require new model fields.

## Validation plan

Backend validation:

- WebSocket rejects unauthenticated or invalid JWT connections.
- Authenticated connections join only their user Inbox group.
- Comment subscribe/unsubscribe targets the requested record group.
- Inbox create, reply, delete, mark-read, and mark-all-read emit events after commit.
- Comment create and delete emit events only to the matching record group.

Frontend validation:

- Inbox badge updates without polling.
- Open Inbox list receives new, deleted, and read-state updates.
- Comment thread receives new and deleted comments for the subscribed record only.
- Reconnect triggers REST refresh for unread count and currently open data.
- Duplicate events do not create duplicate rows.

