# Release Runbook

This runbook is the reusable checklist for preparing and publishing ASP releases. For future release requests, read this document first, then follow the flow below.

## Information the user should provide

Before changing files or creating a tag, collect these decisions:

| Item                         | Required | Notes                                                                                                                                                   |
|------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Version                      | Yes      | Example: `0.4.0`. The release workflow expects a pushed tag named `v<version>`, such as `v0.4.0`. The CLI PyPI package version must use the same version without `v`. |
| Release title                | Yes      | Example: `I always have a choice`.                                                                                                                      |
| Release scope                | Yes      | Choose whether to only prepare release files, or also push commits and create the release tag.                                                          |
| Base version/tag             | Usually  | Default to the latest release tag, but confirm if the release should use another base.                                                                  |
| Release notes source         | Yes      | Usually derive from commits since the previous release; the user may also provide curated highlights.                                                   |
| Developer notes raw material | Usually | Ask the user for background, opinions, tradeoffs, complaints, lessons learned, or loose thoughts. The input can be fragmented; organize it into a coherent developer note. |
| Documentation language scope | Yes | Default: update Chinese release notes first, then mirror to English. |
| Images or attachments        | Optional | If release notes need images, use simple names like `img.png`, `img_1.png`, and avoid extra placeholder descriptions unless requested.                  |
| Validation level             | Yes      | Confirm whether to run only targeted release checks or broader backend/frontend CI checks. Do not run VitePress docs build unless explicitly requested. |
| Publish permission           | Yes      | Confirm before pushing commits, pushing tags, or triggering GitHub Actions release workflows.                                                           |
| PyPI publishing readiness    | First CLI release | Confirm PyPI Trusted Publishing or pending publisher is configured for `asp-cli`. No PyPI token should be committed or stored in GitHub Secrets for the normal release path. |

## Release files and systems

Check these areas for every release:

| Area                        | Path                                                                           | Purpose                                                                                     |
|-----------------------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Release workflow            | `.github/workflows/release.yml`                                                | Creates the GitHub Release on `v*` tags, resolves release docs URL, builds compose package, and publishes the CLI package to PyPI. |
| Docker image workflow       | `.github/workflows/docker.yml`                                                 | Builds and pushes backend/frontend GHCR images.                                             |
| CI workflow                 | `.github/workflows/ci.yml`                                                     | Defines backend, frontend, and compose package validation.                                  |
| Release docs mapping        | `deploy/release-docs.json`                                                     | Maps version numbers such as `0.4.0` to public release doc slugs.                           |
| Compose packaging           | `deploy/package-asp-compose.sh`                                                | Builds `asp-compose-<version>.tar.gz`.                                                      |
| Compose template            | `deploy/asp-compose/`                                                          | Files included in the downloadable release package.                                         |
| CLI package metadata        | `cli/pyproject.toml`                                                           | Defines the `asp-cli` PyPI package metadata and release version.                            |
| CLI release docs            | `cli/README.md`                                                               | Documents PyPI publishing through GitHub Actions and manual fallback.                       |
| Chinese release notes       | `asf-doc/docs/zh/release/<slug>/index.md`                                      | Primary release notes source. Draft Chinese first.                                          |
| English release notes       | `asf-doc/docs/en/release/<slug>/index.md`                                      | English mirror of the Chinese release notes.                                                |
| Docs navigation             | `asf-doc/docs/.vitepress/config/zh.ts`, `asf-doc/docs/.vitepress/config/en.ts` | Adds or updates the changelog nav item.                                                     |
| Main docs submodule pointer | `asf-doc` entry in main repo                                                   | Must be committed in the main repo after committing inside `asf-doc`.                       |

## Naming conventions

- Git tag: `v<version>`, for example `v0.4.0`.
- Version in workflow output and `deploy/release-docs.json`: no `v`, for example `0.4.0`.
- CLI PyPI package version: no `v`, for example `cli/pyproject.toml` should contain `version = "0.4.0"` and publishes as `asp-cli==0.4.0`.
- Release doc slug: use underscores and keep it stable after publishing, for example `0_4_0_I_always_have_a_choice`.
- GitHub Release title: `v<version> - <title>`, for example `v0.4.0 - I always have a choice`.
- Compose archive: `asp-compose-<version>.tar.gz`.
- GHCR image tags:
    - `ghcr.io/<owner>/<repo>/asp-backend:<version>`
    - `ghcr.io/<owner>/<repo>/asp-frontend:<version>`
    - `latest` is also pushed for non-`dev` versions by the current Docker workflow.

## Standard release flow

1. **Inspect current state**
    - Check main repo status and branch.
    - Check `asf-doc` status and branch.
    - Check latest release tags and whether `v<version>` already exists locally or remotely.
    - Check whether `asp-cli==<version>` already exists on PyPI, because PyPI versions are immutable.
    - Check recent release workflow runs if a release was attempted before.
    - Identify unrelated dirty files and exclude them from release commits.

2. **Confirm release decisions**
    - Ask for missing user-provided information from the table above.
    - Confirm whether this task should stop after preparation or push the release tag.
    - Confirm the tag name before creating or pushing it.
    - Confirm PyPI Trusted Publishing is configured before the first CLI release.

3. **Prepare release notes**
    - Generate candidate highlights from commits between the previous release tag and the planned release commit.
    - Ask the user for raw material for **Developer Notes**. This section is not just a change summary; it can include background, motivation, opinions, lessons learned, tradeoffs, and complaints.
    - Treat the user's Developer Notes input as source material even when it is scattered or informal. Preserve the intent, but rewrite it into a coherent developer voice.
    - Write Chinese release notes first under `asf-doc/docs/zh/release/<slug>/index.md`.
    - Create the matching English page under `asf-doc/docs/en/release/<slug>/index.md`.
    - Keep Chinese and English sections structurally aligned.
    - Update VitePress changelog navigation in both `zh.ts` and `en.ts`.

4. **Update release mapping**
    - Update `deploy/release-docs.json` so the version points to the release doc slug.
    - Ensure the slug path exists in both Chinese and English docs when both languages are in scope.

5. **Update package versions**
    - Update `cli/pyproject.toml` to the release version without `v`.
    - Do not manually add a leading `v` to Python package metadata; PyPI versions should be PEP 440 versions such as `0.4.0`.
    - The CLI runtime version is resolved from package metadata or `cli/pyproject.toml`, so no separate hard-coded CLI version should need updating.

6. **Commit in the correct order**
    - Commit `asf-doc` changes inside the `asf-doc` repository.
    - Commit the main repository changes, including:
        - `deploy/release-docs.json`
        - `cli/pyproject.toml` if the release version changed
        - the updated `asf-doc` submodule pointer
    - Do not include unrelated local files.
    - Include the required `Co-authored-by` trailer when creating commits.

7. **Validate before tag**
    - Confirm `deploy/release-docs.json` can resolve the release version to the intended slug.
    - Confirm `cli/pyproject.toml` version exactly matches the release version without `v`.
    - Confirm release docs and navigation reference the same title and slug.
    - Build and check the CLI package metadata when practical.
    - Run the compose package validation path used by CI when practical.
    - Do not run VitePress build unless explicitly requested.
    - Confirm the final release commit is the commit that should receive the tag.

8. **Publish**
    - Push the `asf-doc` release notes commit.
    - Push the main repository release-preparation commit.
    - Create an annotated tag:

      ```bash
      git tag -a v<version> -m "v<version> - <title>"
      ```

    - Push the tag:

      ```bash
      git push origin v<version>
      ```

    - Monitor the GitHub Actions Release workflow.
    - Confirm the `publish-cli` job either publishes `asp-cli` to PyPI or fails with an actionable PyPI configuration/version error.

9. **Post-release checks**
    - Confirm the GitHub Release exists.
    - Confirm the compose archive is attached.
    - Confirm backend and frontend images exist in GHCR with the version tag.
    - Confirm `asp-cli==<version>` exists on PyPI.
    - Confirm the release body links to the expected release notes URL.
    - Confirm the public docs site has or will deploy the release page.

## Release notes structure

Use this default structure unless the user requests another format:

```markdown
# <version> - <title>

## New Features

## Improvements

## Deployment and Release Engineering

## Developer Notes
```

### Developer Notes writing rules

Developer Notes are usually provided by the user. They may be fragmented, informal, or spoken in the order the user remembers things. Convert that material into a readable developer note:

- Preserve the user's intent, stance, and tone.
- Write from a developer/product-builder perspective, not like marketing copy.
- Include background and reasoning, not only "what changed".
- It is acceptable to include tradeoffs, frustrations, lessons learned, and opinions when the user provides them.
- Organize scattered points into a coherent flow with clear paragraphs.
- Do not invent personal feelings or motivations that the user did not provide.
- If the supplied material is too thin, ask one focused follow-up question before drafting.

For small patch releases, this can be shortened to:

```markdown
# <version> - <title>

## Changes

## Fixes
```

## Validation commands

Useful checks:

```bash
git status --short
git tag --list --sort=-creatordate
git ls-remote --tags origin "v<version>"
```

Release docs mapping check:

```bash
python -c "import json; c=json.load(open('deploy/release-docs.json', encoding='utf-8')); print(c['releases']['<version>'])"
```

CLI package version check:

```bash
python - <<'PY'
import tomllib
from pathlib import Path

expected = "<version>"
actual = tomllib.loads(Path("cli/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
if actual != expected:
    raise SystemExit(f"cli/pyproject.toml version {actual!r} must match {expected!r}")
print(actual)
PY
```

CLI package build check:

```bash
cd cli
rm -rf dist
uv build
uvx twine check dist/*
uv run asp --version
cd ..
```

Compose package check:

```bash
bash ./deploy/package-asp-compose.sh --version <version> --output-dir dist-release-check
test -f dist-release-check/asp-compose-<version>.tar.gz
rm -rf dist-release-check/unpacked
mkdir -p dist-release-check/unpacked
tar -xzf dist-release-check/asp-compose-<version>.tar.gz -C dist-release-check/unpacked
```

Clean up temporary validation output after checking:

```bash
rm -rf dist-release-check
rm -rf cli/dist
```

## Failure handling

- If validation fails before the tag is pushed, fix the release-preparation commit before creating the tag.
- If the tag has not been pushed, delete and recreate the local tag after fixing the target commit.
- If the tag has been pushed and the Release workflow fails, inspect failed job logs before changing anything.
- Prefer rerunning failed workflow jobs for transient infrastructure failures.
- If the pushed tag points to the wrong commit or release inputs are wrong, stop and ask before deleting or recreating the remote tag.
- If GitHub Release creation succeeds but release notes are wrong, update docs and then update the GitHub Release body through a follow-up change.
- If `publish-cli` fails because PyPI Trusted Publishing is not configured, configure the trusted or pending publisher for project `asp-cli`, workflow `release.yml`, environment `pypi`, then rerun the failed job.
- If `publish-cli` fails because the PyPI version already exists, do not try to overwrite it. Stop and decide whether to cut a new patch version.

## Quick prompt for future releases

When starting a future release, ask the user:

```text
Please provide the release version, title, whether I should push the tag, the base release/tag, release-note highlights if any, raw Developer Notes thoughts, documentation language scope, validation level, and whether docs build should be skipped.
```
