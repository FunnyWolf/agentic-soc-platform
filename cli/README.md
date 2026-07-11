# ASP CLI

Command line client for Agentic SOC Platform.

`asp-cli` provides the `asp` command for SOC analysts and automation agents to authenticate with an ASP server, inspect cases and alerts, add comments, upload files, run playbooks, and query investigation integrations.

## Install

```powershell
pipx install asp-cli
```

## Upgrade

```powershell
pipx upgrade asp-cli
```

Install a specific version:

```powershell
pipx install asp-cli==0.5.0 --force
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

## Documentation

Full CLI documentation: https://asp.viperrtp.com/asp/integrations/cli/
