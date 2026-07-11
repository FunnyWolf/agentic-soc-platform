# v0.4.0 Release Design

## Context

The project is preparing release `v0.4.0` with the title:

```text
I always have a choice
```

The current repository already contains release automation:

- `.github/workflows/release.yml` listens for pushed tags matching `v*`.
- `.github/workflows/docker.yml` builds and pushes backend and frontend images to GHCR.
- `deploy/package-asp-compose.sh` creates the downloadable Docker Compose package.
- `deploy/release-docs.json` maps release versions to public documentation slugs.

The documentation repository is stored as the `asf-doc` submodule. Current docs contain a partial Chinese `0.4.0 - Less Is More` draft and navigation entries pointing to `0_4_0_Less_Is_More`. The English release page for `0.4.0` does not exist yet.

The current local branch is `dev` tracking `origin/dev`. The main repository has an unrelated dirty `TODO.md`; release work must not include it.

## Goals

1. Prepare release notes for `0.4.0 - I always have a choice`.
2. Keep Chinese and English release documentation structurally consistent.
3. Update release documentation slug references so GitHub Release links point to the correct page.
4. Use the existing `v*` release workflow without expanding the automation scope.
5. Build the final release from a tag named `v0.4.0`.
6. Avoid including unrelated local changes.

## Non-goals

1. Do not redesign the release workflow.
2. Do not add support for unprefixed release tags.
3. Do not introduce a new changelog generator.
4. Do not run the VitePress docs build unless explicitly requested.
5. Do not force-push or rewrite an already-pushed release tag without a separate decision.

## Release materials

### Documentation repository (`asf-doc`)

Rename the current `0.4.0` release page slug from:

```text
0_4_0_Less_Is_More
```

to:

```text
0_4_0_I_always_have_a_choice
```

Required documentation updates:

- `docs/zh/release/0_4_0_I_always_have_a_choice/index.md`
- `docs/en/release/0_4_0_I_always_have_a_choice/index.md`
- `docs/.vitepress/config/zh.ts`
- `docs/.vitepress/config/en.ts`

The Chinese release page should be drafted first, then the English page should mirror the same structure and content.

### Main repository

Update `deploy/release-docs.json` so version `0.4.0` maps to the new slug:

```json
"0.4.0": "0_4_0_I_always_have_a_choice"
```

After the `asf-doc` release documentation is committed, update and commit the submodule pointer in the main repository.

## Release notes content

Release notes should be derived from commits between `0.3.0` and the final release commit.

Use these sections:

1. **New Features**
   - Custom Console and runtime custom-definition management.
   - Tags preview/settings support.
   - Authenticated record share links.
   - Dashboard and workspace experience improvements.

2. **Improvements**
   - Inbox notification and resource-label refinements.
   - Runtime settings cleanup and naming consistency.
   - User-management safety improvements.
   - Activity feed pagination and detail-view usability improvements.

3. **Deployment and Release Engineering**
   - Docker Compose package improvements.
   - CI and release workflow readiness.
   - GHCR image and compose package release path.

4. **Developer Notes**
   - Explain the theme behind "I always have a choice": ASP should make platform behavior configurable and extensible without locking users into a single workflow.
   - Describe the move toward low-cost customization through Custom Console, custom module/playbook definitions, SIEM YAML, and runtime refresh/validation.
   - Describe why authenticated deep links and visual tag previews improve day-to-day analyst workflows.

## Release automation

Keep `.github/workflows/release.yml` unchanged.

The release is triggered by pushing an annotated tag:

```text
v0.4.0
```

The release workflow will:

1. Parse `version=0.4.0` from the tag.
2. Read the release docs slug from `deploy/release-docs.json`.
3. Build and push:
   - `ghcr.io/<owner>/<repo>/asp-backend:0.4.0`
   - `ghcr.io/<owner>/<repo>/asp-frontend:0.4.0`
   - `latest` tags for both images.
4. Build `asp-compose-0.4.0.tar.gz`.
5. Create the GitHub Release with the compose archive and release notes link.

The previous `0.3.0` tag is unprefixed, but this release should use `v0.4.0` because the existing workflow only listens for `v*`.

## Validation plan

Before pushing the release tag:

1. Confirm `v0.4.0` does not already exist locally or remotely.
2. Confirm `deploy/release-docs.json` resolves `0.4.0` to the new slug.
3. Confirm both Chinese and English release pages exist at the mapped slug.
4. Confirm the docs navigation points to the new title and slug.
5. Confirm `asf-doc` is committed and the main repository submodule pointer is committed.
6. Confirm the main repository has no unexpected dirty files included in release commits.
7. Run a compose package validation using the existing package script and archive checks.

Do not run the VitePress docs build unless explicitly requested.

## Publish sequence

1. Commit the `asf-doc` release documentation changes.
2. Commit the main repository release mapping and submodule pointer changes.
3. Push the `asf-doc` commit.
4. Push the main repository release-preparation commit.
5. Create annotated tag `v0.4.0` with message `v0.4.0 - I always have a choice`.
6. Push tag `v0.4.0` to trigger the Release workflow.
7. Watch the Release workflow until it succeeds or fails.

## Failure handling

- If validation fails before the tag is pushed, fix the release-preparation commits before creating the tag.
- If the Release workflow fails after the tag is pushed, inspect the failed job logs first.
- Prefer rerunning the failed workflow after fixing transient infrastructure issues.
- If the tag points to the wrong commit or release inputs are wrong, pause and decide whether to delete and recreate the tag. Do not force-rewrite the release tag silently.
- If GitHub Release creation succeeds but docs are wrong, fix docs in `asf-doc` and update the release body manually or through a follow-up automation change.
