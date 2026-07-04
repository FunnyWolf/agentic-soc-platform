# ASP CLI

Command line client for Agentic SOC Platform.

`asp-cli` provides the `asp` command for SOC analysts and automation agents to authenticate with an ASP server, inspect cases and alerts, add comments, upload files, run playbooks, and query investigation integrations.

## Install

```powershell
pipx install asp-cli
```

## Quick start

```powershell
asp auth login --api-url https://asp.example.com --api-key asp_xxx
asp doctor
asp case list
```

`asp auth login` verifies the API URL and API key against the ASP server before writing local settings.

For automation and skills, prefer stable JSON output:

```powershell
asp case list --output json
```

## Publish to PyPI

The GitHub release workflow publishes `asp-cli` to PyPI automatically when a `v<version>` tag is pushed. The CLI package version does not include the leading `v` and must match the main release version, so update `version` in `pyproject.toml` before creating the tag.

For example, release tag `v0.1.0` publishes PyPI version `0.1.0`.

### Automatic publishing

The workflow uses PyPI Trusted Publishing, so it does not need a PyPI API token in the repository or GitHub Secrets. Configure PyPI once with a trusted publisher:

- PyPI project: `asp-cli`
- Owner/repository: `FunnyWolf/agentic-soc-platform`
- Workflow: `release.yml`
- Environment: `pypi`

If the PyPI project does not exist yet, add the same entry under PyPI's pending publishers before the first release.

Release steps:

```powershell
# Update cli\pyproject.toml first, for example: version = "0.1.0"
git tag v0.1.0
git push origin v0.1.0
```

### Manual fallback

Manual publishing requires a PyPI API token. Keep it local and do not commit it:

```powershell
cd cli
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
uv build
uvx twine check dist\*
$env:UV_PUBLISH_TOKEN = "pypi-..."
uv publish --token $env:UV_PUBLISH_TOKEN
```

After publishing, verify the package can be installed:

```powershell
pipx install --force asp-cli
asp --version
```
