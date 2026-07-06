# Release Runbook

This runbook is the agent protocol for preparing and publishing ASP releases. The user should be able to start a normal release with only:

```text
Release v<version>, title is <title>.
```

The release is standardized by `deploy/release-manifest.json` and `deploy/release_tool.py`. Do not rely on memory or a manual checklist for deterministic version updates.

## Release configuration source

`deploy/release-manifest.json` is the current release configuration source.

Required fields:

| Field | Purpose |
| --- | --- |
| `version` | Release version without `v`, for example `0.5.1`. |
| `title` | Human release title, for example `Winter is Coming`. |
| `previousVersion` | Previous release version without `v`; default this from the latest remote `v*` tag unless the user gives a different base. |
| `baseTag` | Optional override for the commit range base; default is `v<previousVersion>`. |
| `releaseDocSlug` | Stable release notes slug under `asp-doc/docs/<lang>/release/`. Auto-fill from version/title unless the user requests another slug. |
| `releaseDocsBaseUrl` | Public release docs base URL, currently `https://asp.viperrtp.com/release`. |
| `surfaces` | Named release surfaces managed by `deploy/release_tool.py`. |

Current managed surfaces:

| Surface | Managed files |
| --- | --- |
| `cli_version` | `cli/pyproject.toml` |
| `compose_env_example` | `deploy/asp-compose/.env.example` |
| `quickstart_deployment_docs` | `asp-doc/docs/zh/asp/quick-start/deployment/index.md`, `asp-doc/docs/en/asp/quick-start/deployment/index.md` |
| `quickstart_upgrade_docs` | `asp-doc/docs/zh/asp/quick-start/upgrade/index.md`, `asp-doc/docs/en/asp/quick-start/upgrade/index.md` |
| `release_notes_pages` | `asp-doc/docs/zh/release/<slug>/index.md`, `asp-doc/docs/en/release/<slug>/index.md` |
| `vitepress_nav` | `asp-doc/docs/.vitepress/config/zh.ts`, `asp-doc/docs/.vitepress/config/en.ts` |

`deploy/release-docs.json` is no longer used. The Release workflow resolves the release notes URL from the manifest.

## Standard release flow for agents

1. **Inspect state**
    - Check main repo status and branch.
    - Check `asp-doc` status and branch.
    - If `asp-doc` is missing or uninitialized, ask the user to run or approve:

      ```bash
      git submodule update --init asp-doc
      ```

    - Check latest remote release tags and whether the requested tag already exists.
    - Check whether `asp-cli==<version>` already exists on PyPI, because PyPI versions are immutable.
    - Identify unrelated dirty files and do not include them in release commits.

2. **Update the manifest**
    - Normalize the requested tag `v<version>` to manifest `version`.
    - Set `title` from the user request.
    - Infer `previousVersion` from the latest remote `v*` tag unless the user provided another base.
    - Auto-fill `releaseDocSlug` from version/title unless the user requested a specific slug.
    - Keep `releaseDocsBaseUrl` and the standard `surfaces` list unless there is a deliberate release-process change.

3. **Prepare deterministic files**
    - Run:

      ```bash
      python deploy/release_tool.py prepare
      ```

    - This updates CLI version, compose image tags, deployment/upgrade docs generated blocks, release page skeletons, and VitePress changelog nav.
    - Do not manually edit generated release blocks except by changing the manifest or tool.

4. **Write release notes**
    - Generate candidate highlights from commits between `baseTag`/`v<previousVersion>` and the planned release commit.
    - Ask the user once for optional Developer Notes raw material or curated highlights. It is acceptable for the user to provide nothing.
    - Write the Chinese release page first:

      ```text
      asp-doc/docs/zh/release/<releaseDocSlug>/index.md
      ```

    - Then write the matching English page:

      ```text
      asp-doc/docs/en/release/<releaseDocSlug>/index.md
      ```

    - Keep Chinese and English pages structurally aligned.
    - Do not put the full release narrative in the GitHub Release body; the workflow creates a minimal body that links to the docs page and lists downloads/images.

5. **Validate before commits**
    - Run:

      ```bash
      python deploy/release_tool.py check
      python deploy/release_tool.py show
      ```

    - Build/check CLI package metadata when practical:

      ```bash
      cd cli
      uv build
      uvx twine check dist/*
      uv run asp --version
      cd ..
      ```

    - Run the compose package validation path when practical:

      ```bash
      bash ./deploy/package-asp-compose.sh --version <version> --output-dir dist-release-check
      test -f dist-release-check/asp-compose-<version>.tar.gz
      rm -rf dist-release-check/unpacked
      mkdir -p dist-release-check/unpacked
      tar -xzf dist-release-check/asp-compose-<version>.tar.gz -C dist-release-check/unpacked
      ```

    - Clean temporary validation output:

      ```bash
      rm -rf dist-release-check
      rm -rf cli/dist
      ```

    - Do not run VitePress docs build unless the user explicitly asks.
    - Frontend changes do not require `npm build` validation unless the user explicitly asks.

6. **Commit in the correct order**
    - Commit release docs changes inside `asp-doc`.
    - Commit main repository release-preparation changes, including:
        - `deploy/release-manifest.json`
        - `deploy/release_tool.py` if changed
        - workflow/runbook changes if changed
        - `cli/pyproject.toml`
        - `deploy/asp-compose/.env.example`
        - the `asp-doc` submodule pointer
    - Do not include unrelated local files.
    - Include the required `Co-authored-by` trailer when creating commits.

7. **Ask for publish permission**
    - Before pushing commits or tags, ask for explicit permission.
    - Confirm the tag name `v<version>`.
    - For the first CLI release in a new environment, confirm PyPI Trusted Publishing is configured for project `asp-cli`, workflow `release.yml`, environment `pypi`.

8. **Publish**
    - Push the `asp-doc` release notes commit.
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

9. **Post-release checks**
    - Confirm the GitHub Release exists.
    - Confirm the compose archive is attached.
    - Confirm backend and frontend images exist in GHCR with the version tag.
    - Confirm `asp-cli==<version>` exists on PyPI.
    - Confirm the release body links to the expected release notes URL from `python deploy/release_tool.py show`.
    - Confirm the public docs site has or will deploy the release page.

## Naming conventions

- Git tag: `v<version>`, for example `v0.5.1`.
- Manifest version and CLI PyPI package version: no `v`, for example `0.5.1`.
- Release doc slug: explicit and stable after publishing, usually generated from version/title, for example `0_5_1_Winter_is_Coming`.
- GitHub Release title: `v<version> - <title>`.
- Compose archive: `asp-compose-<version>.tar.gz`.
- GHCR image tags:
    - `ghcr.io/<owner>/<repo>/asp-backend:<version>`
    - `ghcr.io/<owner>/<repo>/asp-frontend:<version>`
    - `latest` is also pushed for non-`dev` versions by the Docker workflow.

## Generated blocks

The quick-start deployment and upgrade pages contain generated blocks:

```markdown
<!-- release:<name>:start -->
...
<!-- release:<name>:end -->
```

Only `deploy/release_tool.py prepare` should update these blocks. If `check` reports a stale generated block, update the manifest if needed and rerun `prepare`.

## Release notes writing rules

Release notes are generated by the agent, not by `release_tool.py`. The tool only creates missing page skeletons and checks titles/nav/paths.

Default Chinese structure:

```markdown
# <version> - <title>

## 新功能

## 优化

## 修复

## 部署和发布工程

## 升级说明

## 开发者笔记
```

Default English structure:

```markdown
# <version> - <title>

## New Features

## Improvements

## Fixes

## Deployment and Release Engineering

## Upgrade Notes

## Developer Notes
```

Developer Notes may include background, motivation, opinions, lessons learned, tradeoffs, and complaints when the user provides them. Preserve the user's intent and tone, but organize fragmented material into readable paragraphs. Do not invent personal feelings or motivations.

## Failure handling

- If `prepare` or `check` fails, fix the manifest or managed source files before committing.
- If validation fails before the tag is pushed, fix the release-preparation commit before creating the tag.
- If the tag has not been pushed, delete and recreate the local tag after fixing the target commit.
- If the tag has been pushed and the Release workflow fails, inspect failed job logs before changing anything.
- Prefer rerunning failed workflow jobs for transient infrastructure failures.
- If a pushed tag points to the wrong commit or release inputs are wrong, stop and ask before deleting or recreating the remote tag.
- If GitHub Release creation succeeds but docs are wrong, update docs and let the public docs deploy; update the GitHub Release body only if the minimal link/download/image body is wrong.
- If `publish-cli` fails because PyPI Trusted Publishing is not configured, configure the trusted or pending publisher for project `asp-cli`, workflow `release.yml`, environment `pypi`, then rerun the failed job.
- If `publish-cli` fails because the PyPI version already exists, do not try to overwrite it. Stop and decide whether to cut a new patch version.

## Minimal prompt for future releases

The user can start with:

```text
Release v<version>, title is <title>.
```

The agent should infer the base from the latest release tag, prepare deterministic files from the manifest, ask once for optional release-note context, and ask again only for publish permission.
