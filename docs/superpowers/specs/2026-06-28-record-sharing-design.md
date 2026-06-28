# Record Sharing Design

## Context

The platform already has authenticated detail routes for every supported record resource:

- `/cases/:rowId`
- `/alerts/:rowId`
- `/artifacts/:rowId`
- `/enrichments/:rowId`
- `/playbooks/:rowId`
- `/knowledge/:rowId`

`App.tsx` routes these URLs to `ResourceDetailRoute`, which loads the relevant `ResourceConfig` and renders the existing `RecordDetailModal`. The detail modal fetches the record through the configured detail endpoint, such as `/api/cases/{id}/`, and displays the normal Basic view and tabs.

This means record sharing does not need a new detail page or a backend share-token system for the first version. The missing pieces are a visible copy-link action and preserving the requested deep link across authentication redirects.

## Goals

1. Let users copy a URL for any record type that already has a detail route.
2. Require normal authentication and existing read permissions; a share link must not grant new access.
3. Reuse the existing detail modal presentation.
4. Open shared links on the Basic tab.
5. Keep current list-page behavior unchanged: opening a record from a list does not update the address bar.
6. Preserve the destination URL when unauthenticated users log in, including after token-expiry redirects.

## Non-goals

1. No public links.
2. No share tokens, expiry, revocation, or per-link ACLs.
3. No database schema changes.
4. No new full-page record detail layout.
5. No restoration of detail sub-tabs such as Case Alerts or Investigation.

## Recommended approach

Use a generic authenticated deep-link design.

The share button copies an absolute URL built from the current origin, the resource key, and the row ID:

```text
{origin}/{resourceKey}/{rowId}
```

Examples:

```text
https://example.local/cases/123
https://example.local/alerts/456
```

The copied link is only a deep link into the existing application. When another user opens it, the current authentication and permission model decides whether the record can be read.

## Components

### Record share URL helper

Add a small frontend helper, for example `frontend/src/utils/recordShare.ts`.

Responsibilities:

- Maintain the allow-list of resource keys that have detail routes.
- Build a path from `{ resourceKey, rowId }`.
- Build an absolute URL from `window.location.origin`.
- Encode `rowId` safely for URL path usage.

Keeping URL construction outside `RecordDetailModal` prevents routing details from leaking into the modal and makes future URL shape changes localized.

### `RecordDetailModal`

Add a Share action to the existing modal header.

Responsibilities:

- Show the action only when `rowId` is available and the resource is shareable.
- Copy the generated absolute URL to the clipboard.
- Show a success or failure message using the existing Ant Design message pattern.
- Leave the current address bar unchanged when the modal was opened from a list page.

This makes sharing work for both list-opened modals and direct-route modals.

### Protected route redirect

Update `ProtectedRoute` in `App.tsx` so unauthenticated users are redirected to login with the requested location:

```text
/login?next={encoded current pathname + search + hash}
```

The login page should validate `next` before navigating. Only same-origin relative paths that start with `/` should be accepted. Invalid values fall back to `/`.

### Login page

After a successful login, `Login.tsx` should navigate to the validated `next` path instead of always navigating to `/`.

### Axios 401 interceptor

When an API response returns 401, the interceptor should clear auth state and redirect to:

```text
/login?next={encoded current pathname + search + hash}
```

This preserves the current deep link when a token expires while the user is already on a record URL.

## Data flow

### Copying a link

1. User opens a record detail modal.
2. User clicks Share.
3. The modal calls the share URL helper with `config.key` and `rowId`.
4. The helper returns an absolute URL such as `https://host/cases/123`.
5. The modal writes the URL to the clipboard and shows a confirmation.

### Opening a shared link while authenticated

1. Browser opens `/cases/123`.
2. `App.tsx` matches the `cases/:rowId` route.
3. `ProtectedRoute` allows access because a token is present.
4. `ResourceDetailRoute` loads the `cases` resource config.
5. `RecordDetailModal` opens and fetches `/api/cases/123/`.
6. The Basic tab is displayed.

### Opening a shared link while unauthenticated

1. Browser opens `/cases/123`.
2. `ProtectedRoute` redirects to `/login?next=%2Fcases%2F123`.
3. User logs in.
4. `Login.tsx` validates and navigates to `/cases/123`.
5. The existing authenticated shared-link flow runs.

## Error handling

The first version should reuse the existing detail-loading behavior where possible.

- Missing record: keep the current 404 behavior that warns the user and closes the modal.
- Unauthorized or insufficient permission: show a clear permission message, then close the modal or leave the normal empty state.
- Clipboard failure: show an error message and do not change application state.
- Invalid `next`: ignore it and navigate to `/`.

The design must not silently grant access or bypass backend permissions.

## Complexity assessment

Overall complexity is low to medium.

Low-complexity parts:

- Existing detail routes already support direct record URLs.
- Existing `ResourceDetailRoute` already adapts route params into `RecordDetailModal`.
- Existing backend detail APIs already enforce authentication.
- No database migration is required.

Medium-risk parts:

- Login redirect handling must avoid open redirects.
- The 401 interceptor must preserve useful deep links without causing redirect loops.
- The share helper must only generate routes for resources that are actually routable.

## Validation

Manual validation should cover:

1. An authenticated user opens `/cases/{id}` and sees the detail modal.
2. An unauthenticated user opens `/cases/{id}`, logs in, and returns to the same record.
3. A user opens a record from a list, clicks Share, and the copied URL opens the same record in a new tab.
4. A token-expired user on a record URL is redirected to login and then back to that record.
5. Unsupported resource keys do not produce share URLs.

Frontend build validation is not required unless explicitly requested.
