from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "asp_cli"

import httpx
import jmespath
import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import (
    clear_auth,
    get_config_value,
    read_settings,
    redact_secret,
    resolve_config,
    save_auth,
    set_config_value,
)
from .errors import CliError, EXIT_AUTH, EXIT_CONFIG, EXIT_NETWORK, EXIT_USAGE
from .api_client import AspClient
from .output import OutputFormat, emit_error, emit_success, key_value_table

console = Console()
err_console = Console(stderr=True)


@dataclass
class RuntimeOptions:
    api_url: str | None
    api_key: str | None
    output: OutputFormat
    query: str | None
    verbose: bool


app = typer.Typer(no_args_is_help=True, help="ASP command line client.")
auth_app = typer.Typer(no_args_is_help=True, help="Authenticate and inspect the current ASP session.")
config_app = typer.Typer(no_args_is_help=True, help="Read and write ASP CLI settings.")
completion_app = typer.Typer(no_args_is_help=True, help="Show shell completion installation commands.")
case_app = typer.Typer(no_args_is_help=True, help="List, show, and update ASP cases.")
alert_app = typer.Typer(no_args_is_help=True, help="List and show ASP alerts.")
artifact_app = typer.Typer(no_args_is_help=True, help="List and show ASP artifacts.")
knowledge_app = typer.Typer(no_args_is_help=True, help="Search, show, and update ASP knowledge.")
comment_app = typer.Typer(no_args_is_help=True, help="List and add ASP comments.")
file_app = typer.Typer(no_args_is_help=True, help="Upload, inspect, download, and read ASP files.")
enrichment_app = typer.Typer(no_args_is_help=True, help="Create ASP enrichments.")
playbook_app = typer.Typer(no_args_is_help=True, help="List and run ASP playbooks.")
playbook_template_app = typer.Typer(no_args_is_help=True, help="List playbook templates.")
siem_app = typer.Typer(no_args_is_help=True, help="Search and query ASP SIEM integrations.")
siem_schema_app = typer.Typer(no_args_is_help=True, help="Explore SIEM schema metadata.")
siem_search_app = typer.Typer(no_args_is_help=True, help="Run SIEM search workflows.")
siem_query_app = typer.Typer(no_args_is_help=True, help="Run structured or raw SIEM queries.")
siem_fields_app = typer.Typer(no_args_is_help=True, help="Discover live SIEM fields.")
ti_app = typer.Typer(no_args_is_help=True, help="Query threat intelligence providers.")
cmdb_app = typer.Typer(no_args_is_help=True, help="Look up asset context from CMDB providers.")
dev_app = typer.Typer(no_args_is_help=True, help="Advanced developer and debugging commands.")
dev_stream_app = typer.Typer(no_args_is_help=True, help="Inspect Redis streams.")

app.add_typer(auth_app, name="auth")
app.add_typer(config_app, name="config")
app.add_typer(completion_app, name="completion")
app.add_typer(case_app, name="case")
app.add_typer(alert_app, name="alert")
app.add_typer(artifact_app, name="artifact")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(comment_app, name="comment")
app.add_typer(file_app, name="file")
app.add_typer(enrichment_app, name="enrichment")
playbook_app.add_typer(playbook_template_app, name="template")
app.add_typer(playbook_app, name="playbook")
siem_app.add_typer(siem_schema_app, name="schema")
siem_app.add_typer(siem_search_app, name="search")
siem_app.add_typer(siem_query_app, name="query")
siem_app.add_typer(siem_fields_app, name="fields")
app.add_typer(siem_app, name="siem")
app.add_typer(ti_app, name="ti")
app.add_typer(cmdb_app, name="cmdb")
dev_app.add_typer(dev_stream_app, name="stream")
app.add_typer(dev_app, name="dev")


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Show CLI version and exit.")] = False,
    api_url: Annotated[str | None, typer.Option("--api-url", help="Temporarily override the ASP base URL.")] = None,
    api_key: Annotated[str | None, typer.Option("--api-key", help="Temporarily override the ASP API key.")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", help="Output format.")] = OutputFormat.human,
    query: Annotated[str | None, typer.Option("--query", help="JMESPath query applied to JSON data.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show redacted request diagnostics.")] = False,
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()
    ctx.obj = RuntimeOptions(api_url=api_url, api_key=api_key, output=output, query=query, verbose=verbose)


@auth_app.command("login")
def auth_login(
    ctx: typer.Context,
    api_url: Annotated[str, typer.Option("--api-url", help="ASP base URL, for example https://asp.example.com.")],
    api_key: Annotated[str, typer.Option("--api-key", help="ASP user API key.")],
    local: Annotated[bool, typer.Option("--local", help="Write .asp/settings.json in the current directory.")] = False,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "auth.login", output, lambda runtime, out: _auth_login(runtime, out, api_url, api_key, local))


@auth_app.command("status")
def auth_status(
    ctx: typer.Context,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "auth.status", output, _auth_status)


@auth_app.command("logout")
def auth_logout(
    ctx: typer.Context,
    local: Annotated[bool, typer.Option("--local", help="Remove auth from local .asp/settings.json instead of global settings.")] = False,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "auth.logout", output, lambda runtime, out: _auth_logout(runtime, out, local))


@config_app.command("list")
def config_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "config.list", output, _config_list)


@config_app.command("get")
def config_get(
    ctx: typer.Context,
    key: Annotated[str, typer.Argument(help="Config key: api_url or api_key.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "config.get", output, lambda runtime, out: _config_get(runtime, out, key))


@config_app.command("set")
def config_set(
    ctx: typer.Context,
    key: Annotated[str, typer.Argument(help="Config key: api_url or api_key.")],
    value: Annotated[str, typer.Argument(help="Config value.")],
    local: Annotated[bool, typer.Option("--local", help="Write local .asp/settings.json instead of global settings.")] = False,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "config.set", output, lambda runtime, out: _config_set(runtime, out, key, value, local))


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "doctor", output, _doctor)


@case_app.command("list")
def case_list(
    ctx: typer.Context,
    status: Annotated[str | None, typer.Option("--status", help="Case status filter. Repeat values with commas.")] = None,
    severity: Annotated[str | None, typer.Option("--severity", help="Case severity filter. Repeat values with commas.")] = None,
    confidence: Annotated[str | None, typer.Option("--confidence", help="Case confidence filter. Repeat values with commas.")] = None,
    verdict: Annotated[str | None, typer.Option("--verdict", help="Case verdict filter. Repeat values with commas.")] = None,
    correlation_uid: Annotated[str | None, typer.Option("--correlation-uid", help="Case correlation UID.")] = None,
    title: Annotated[str | None, typer.Option("--title", help="Title substring filter.")] = None,
    tags: Annotated[str | None, typer.Option("--tags", help="Comma-separated tag filters.")] = None,
    include_related: Annotated[bool, typer.Option("--include-related", help="Include related alerts.")] = False,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "case.list",
        output,
        lambda runtime, out: _list_cases(
            runtime,
            out,
            status=status,
            severity=severity,
            confidence=confidence,
            verdict=verdict,
            correlation_uid=correlation_uid,
            title=title,
            tags=tags,
            include_related=include_related,
            cursor=cursor,
            page_size=page_size,
        ),
    )


@case_app.command("show")
def case_show(
    ctx: typer.Context,
    case_id: Annotated[str, typer.Argument(help="Case ID, for example case_000001.")],
    include_related: Annotated[bool, typer.Option("--include-related/--no-include-related", help="Include related alerts.")] = True,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "case.show", output, lambda runtime, out: _show_case(runtime, out, case_id, include_related))


@case_app.command("update-ai")
def case_update_ai(
    ctx: typer.Context,
    case_id: Annotated[str, typer.Argument(help="Case ID, for example case_000001.")],
    severity_ai: Annotated[str | None, typer.Option("--severity-ai", help="AI-assessed severity.")] = None,
    confidence_ai: Annotated[str | None, typer.Option("--confidence-ai", help="AI-assessed confidence.")] = None,
    impact_ai: Annotated[str | None, typer.Option("--impact-ai", help="AI-assessed impact.")] = None,
    priority_ai: Annotated[str | None, typer.Option("--priority-ai", help="AI-assessed priority.")] = None,
    verdict_ai: Annotated[str | None, typer.Option("--verdict-ai", help="AI-assessed verdict.")] = None,
    summary: Annotated[str | None, typer.Option("--summary", help="Case summary.")] = None,
    summary_file: Annotated[Path | None, typer.Option("--summary-file", help="Read summary from file.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "case.update_ai",
        output,
        lambda runtime, out: _update_case_ai(
            runtime,
            out,
            case_id,
            severity_ai=severity_ai,
            confidence_ai=confidence_ai,
            impact_ai=impact_ai,
            priority_ai=priority_ai,
            verdict_ai=verdict_ai,
            summary=summary,
            summary_file=summary_file,
        ),
    )


@alert_app.command("list")
def alert_list(
    ctx: typer.Context,
    status: Annotated[str | None, typer.Option("--status", help="Alert status filter. Repeat values with commas.")] = None,
    severity: Annotated[str | None, typer.Option("--severity", help="Alert severity filter. Repeat values with commas.")] = None,
    confidence: Annotated[str | None, typer.Option("--confidence", help="Alert confidence filter. Repeat values with commas.")] = None,
    case_id: Annotated[str | None, typer.Option("--case-id", help="Linked case ID.")] = None,
    correlation_uid: Annotated[str | None, typer.Option("--correlation-uid", help="Correlation UID.")] = None,
    include_related: Annotated[bool, typer.Option("--include-related", help="Include related artifacts.")] = False,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "alert.list",
        output,
        lambda runtime, out: _list_alerts(
            runtime,
            out,
            status=status,
            severity=severity,
            confidence=confidence,
            case_id=case_id,
            correlation_uid=correlation_uid,
            include_related=include_related,
            cursor=cursor,
            page_size=page_size,
        ),
    )


@alert_app.command("show")
def alert_show(
    ctx: typer.Context,
    alert_id: Annotated[str, typer.Argument(help="Alert ID, for example alert_000001.")],
    include_related: Annotated[bool, typer.Option("--include-related/--no-include-related", help="Include related artifacts.")] = True,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "alert.show", output, lambda runtime, out: _show_alert(runtime, out, alert_id, include_related))


@artifact_app.command("list")
def artifact_list(
    ctx: typer.Context,
    type: Annotated[str | None, typer.Option("--type", help="Artifact type filter. Repeat values with commas.")] = None,
    role: Annotated[str | None, typer.Option("--role", help="Artifact role filter. Repeat values with commas.")] = None,
    value: Annotated[str | None, typer.Option("--value", help="Exact artifact value.")] = None,
    include_related: Annotated[bool, typer.Option("--include-related", help="Include related alerts.")] = False,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "artifact.list",
        output,
        lambda runtime, out: _list_artifacts(
            runtime,
            out,
            type=type,
            role=role,
            value=value,
            include_related=include_related,
            cursor=cursor,
            page_size=page_size,
        ),
    )


@artifact_app.command("show")
def artifact_show(
    ctx: typer.Context,
    artifact_id: Annotated[str, typer.Argument(help="Artifact ID, for example artifact_000001.")],
    include_related: Annotated[bool, typer.Option("--include-related/--no-include-related", help="Include related alerts.")] = True,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "artifact.show", output, lambda runtime, out: _show_artifact(runtime, out, artifact_id, include_related))


@knowledge_app.command("search")
def knowledge_search(
    ctx: typer.Context,
    keyword: Annotated[str | None, typer.Argument(help="Keyword to search in title, body, or tags.")] = None,
    source: Annotated[str | None, typer.Option("--source", help="Knowledge source filter.")] = None,
    case_id: Annotated[str | None, typer.Option("--case-id", help="Linked case ID.")] = None,
    tags: Annotated[str | None, typer.Option("--tags", help="Comma-separated tag filters.")] = None,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "knowledge.search",
        output,
        lambda runtime, out: _search_knowledge(
            runtime,
            out,
            keyword=keyword,
            source=source,
            case_id=case_id,
            tags=tags,
            cursor=cursor,
            page_size=page_size,
        ),
    )


@knowledge_app.command("show")
def knowledge_show(
    ctx: typer.Context,
    knowledge_id: Annotated[str, typer.Argument(help="Knowledge ID, for example knowledge_000001.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "knowledge.show", output, lambda runtime, out: _show_knowledge(runtime, out, knowledge_id))


@knowledge_app.command("update")
def knowledge_update(
    ctx: typer.Context,
    knowledge_id: Annotated[str, typer.Argument(help="Knowledge ID, for example knowledge_000001.")],
    title: Annotated[str | None, typer.Option("--title", help="Knowledge title.")] = None,
    body: Annotated[str | None, typer.Option("--body", help="Knowledge body.")] = None,
    body_file: Annotated[Path | None, typer.Option("--body-file", help="Read body from file.")] = None,
    expires_at: Annotated[str | None, typer.Option("--expires-at", help="ISO 8601 datetime with timezone.")] = None,
    tags: Annotated[str | None, typer.Option("--tags", help="Comma-separated tags.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "knowledge.update",
        output,
        lambda runtime, out: _update_knowledge(
            runtime,
            out,
            knowledge_id,
            title=title,
            body=body,
            body_file=body_file,
            expires_at=expires_at,
            tags=tags,
        ),
    )


@comment_app.command("list")
def comment_list(
    ctx: typer.Context,
    target_id: Annotated[str, typer.Argument(help="Target record ID, for example case_000001.")],
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "comment.list", output, lambda runtime, out: _list_comments(runtime, out, target_id, cursor, page_size))


@comment_app.command("add")
def comment_add(
    ctx: typer.Context,
    target_id: Annotated[str, typer.Argument(help="Target record ID, for example case_000001.")],
    body: Annotated[str | None, typer.Option("--body", help="Comment body.")] = None,
    body_file: Annotated[Path | None, typer.Option("--body-file", help="Read comment body from file.")] = None,
    file_key: Annotated[str | None, typer.Option("--file-key", help="Attachment file_key. Use commas for multiple keys.")] = None,
    parent_id: Annotated[int | None, typer.Option("--parent-id", help="Parent comment ID for replies.")] = None,
    mentions: Annotated[str | None, typer.Option("--mentions", help="Comma-separated usernames or user IDs.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "comment.add",
        output,
        lambda runtime, out: _add_comment(
            runtime,
            out,
            target_id,
            body=body,
            body_file=body_file,
            file_key=file_key,
            parent_id=parent_id,
            mentions=mentions,
        ),
    )


@file_app.command("upload")
def file_upload(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(help="Local file path to upload.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "file.upload", output, lambda runtime, out: _upload_file(runtime, out, path))


@file_app.command("info")
def file_info(
    ctx: typer.Context,
    file_key: Annotated[str, typer.Argument(help="Attachment file_key.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "file.info", output, lambda runtime, out: _file_info(runtime, out, file_key))


@file_app.command("download")
def file_download(
    ctx: typer.Context,
    file_key: Annotated[str, typer.Argument(help="Attachment file_key.")],
    output_path: Annotated[Path | None, typer.Option("--output-path", "-o", help="Local output path.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "file.download", output, lambda runtime, out: _download_file(runtime, out, file_key, output_path))


@file_app.command("read-text")
def file_read_text(
    ctx: typer.Context,
    file_key: Annotated[str, typer.Argument(help="Attachment file_key.")],
    max_bytes: Annotated[int, typer.Option("--max-bytes", min=1, max=262144, help="Maximum bytes to read.")] = 65536,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "file.read_text", output, lambda runtime, out: _read_file_text(runtime, out, file_key, max_bytes))


@enrichment_app.command("create")
def enrichment_create(
    ctx: typer.Context,
    target_id: Annotated[str, typer.Argument(help="Target case_, alert_, or artifact_ ID.")],
    name: Annotated[str, typer.Option("--name", help="Enrichment name.")] = "",
    type: Annotated[str, typer.Option("--type", help="Enrichment type.")] = "Other",
    value: Annotated[str, typer.Option("--value", help="Enrichment value.")] = "",
    uid: Annotated[str, typer.Option("--uid", help="Stable external identifier.")] = "",
    desc: Annotated[str, typer.Option("--desc", help="Enrichment summary.")] = "",
    data_json: Annotated[str | None, typer.Option("--data-json", help="JSON object string.")] = None,
    data_file: Annotated[Path | None, typer.Option("--data-file", help="JSON object file.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "enrichment.create",
        output,
        lambda runtime, out: _create_enrichment(
            runtime,
            out,
            target_id,
            name=name,
            type=type,
            value=value,
            uid=uid,
            desc=desc,
            data_json=data_json,
            data_file=data_file,
        ),
    )


@playbook_template_app.command("list")
def playbook_template_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "playbook.template.list", output, _list_playbook_templates)


@playbook_app.command("list")
def playbook_list(
    ctx: typer.Context,
    case_id: Annotated[str | None, typer.Option("--case-id", help="Linked case ID.")] = None,
    job_status: Annotated[str | None, typer.Option("--job-status", help="Job status filter. Repeat values with commas.")] = None,
    include_related: Annotated[bool, typer.Option("--include-related", help="Include related case.")] = False,
    cursor: Annotated[str | None, typer.Option("--cursor", help="Pagination cursor.")] = None,
    page_size: Annotated[int | None, typer.Option("--page-size", min=1, max=100, help="Page size.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "playbook.list",
        output,
        lambda runtime, out: _list_playbooks(
            runtime,
            out,
            case_id=case_id,
            job_status=job_status,
            include_related=include_related,
            cursor=cursor,
            page_size=page_size,
        ),
    )


@playbook_app.command("show")
def playbook_show(
    ctx: typer.Context,
    playbook_id: Annotated[str, typer.Argument(help="Playbook run ID, for example playbook_000001.")],
    include_related: Annotated[bool, typer.Option("--include-related/--no-include-related", help="Include related case.")] = True,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "playbook.show", output, lambda runtime, out: _show_playbook(runtime, out, playbook_id, include_related))


@playbook_app.command("run")
def playbook_run(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Playbook template name.")],
    case_id: Annotated[str, typer.Argument(help="Case ID, for example case_000001.")],
    user_input: Annotated[str | None, typer.Option("--user-input", help="Playbook user input.")] = None,
    user_input_file: Annotated[Path | None, typer.Option("--user-input-file", help="Read user input from file.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "playbook.run",
        output,
        lambda runtime, out: _run_playbook(
            runtime,
            out,
            name,
            case_id,
            user_input=user_input,
            user_input_file=user_input_file,
        ),
    )


@siem_schema_app.command("list")
def siem_schema_list(
    ctx: typer.Context,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "siem.schema", output, lambda runtime, out: _siem_schema(runtime, out, None))


@siem_schema_app.command("show")
def siem_schema_show(
    ctx: typer.Context,
    target_index: Annotated[str, typer.Argument(help="Registered SIEM index/source name.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "siem.schema", output, lambda runtime, out: _siem_schema(runtime, out, target_index))


@siem_search_app.command("keyword")
def siem_search_keyword(
    ctx: typer.Context,
    keyword: Annotated[str, typer.Argument(help="Keyword or comma-separated AND keyword list.")],
    time_range_start: Annotated[str, typer.Option("--from", help="ISO 8601 start time with timezone.")],
    time_range_end: Annotated[str, typer.Option("--to", help="ISO 8601 end time with timezone.")],
    time_field: Annotated[str, typer.Option("--time-field", help="Time field.")] = "@timestamp",
    index_name: Annotated[str | None, typer.Option("--index-name", help="Optional target index/source.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "siem.search.keyword",
        output,
        lambda runtime, out: _siem_keyword(runtime, out, keyword, time_range_start, time_range_end, time_field, index_name),
    )


@siem_query_app.command("adaptive")
def siem_query_adaptive(
    ctx: typer.Context,
    index_name: Annotated[str, typer.Argument(help="Target SIEM index/source name.")],
    time_range_start: Annotated[str, typer.Option("--from", help="ISO 8601 start time with timezone.")],
    time_range_end: Annotated[str, typer.Option("--to", help="ISO 8601 end time with timezone.")],
    time_field: Annotated[str, typer.Option("--time-field", help="Time field.")] = "@timestamp",
    filters_json: Annotated[str | None, typer.Option("--filters-json", help="Exact-match filters JSON object.")] = None,
    filters_file: Annotated[Path | None, typer.Option("--filters-file", help="Exact-match filters JSON file.")] = None,
    aggregation_fields: Annotated[str | None, typer.Option("--aggregation-fields", help="Comma-separated aggregation fields.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "siem.query.adaptive",
        output,
        lambda runtime, out: _siem_adaptive(runtime, out, index_name, time_range_start, time_range_end, time_field, filters_json, filters_file, aggregation_fields),
    )


@siem_query_app.command("spl")
def siem_query_spl(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Raw SPL query.")],
    time_range_start: Annotated[str, typer.Option("--from", help="ISO 8601 start time with timezone.")],
    time_range_end: Annotated[str, typer.Option("--to", help="ISO 8601 end time with timezone.")],
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000, help="Maximum records.")] = 100,
    time_field: Annotated[str, typer.Option("--time-field", help="Time field.")] = "@timestamp",
    index_name: Annotated[str | None, typer.Option("--index-name", help="Optional index/source label.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "siem.query.spl", output, lambda runtime, out: _siem_raw_query(runtime, out, "spl", query, time_range_start, time_range_end, limit, time_field, index_name))


@siem_query_app.command("esql")
def siem_query_esql(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Raw ES|QL query.")],
    time_range_start: Annotated[str, typer.Option("--from", help="ISO 8601 start time with timezone.")],
    time_range_end: Annotated[str, typer.Option("--to", help="ISO 8601 end time with timezone.")],
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000, help="Maximum records.")] = 100,
    time_field: Annotated[str, typer.Option("--time-field", help="Time field.")] = "@timestamp",
    index_name: Annotated[str | None, typer.Option("--index-name", help="Optional index/source label.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "siem.query.esql", output, lambda runtime, out: _siem_raw_query(runtime, out, "esql", query, time_range_start, time_range_end, limit, time_field, index_name))


@siem_fields_app.command("discover")
def siem_fields_discover(
    ctx: typer.Context,
    index_name: Annotated[str, typer.Argument(help="Target SIEM index/source name.")],
    backend: Annotated[str, typer.Argument(help="Backend: ELK or Splunk.")],
    time_range_start: Annotated[str, typer.Option("--from", help="ISO 8601 start time with timezone.")],
    time_range_end: Annotated[str, typer.Option("--to", help="ISO 8601 end time with timezone.")],
    doc_limit: Annotated[int, typer.Option("--doc-limit", min=1, max=100000, help="Documents to sample.")] = 10000,
    max_samples_per_field: Annotated[int, typer.Option("--max-samples-per-field", min=1, max=100, help="Samples per field.")] = 20,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(
        ctx,
        "siem.fields.discover",
        output,
        lambda runtime, out: _siem_fields_discover(runtime, out, index_name, backend, time_range_start, time_range_end, doc_limit, max_samples_per_field),
    )


@ti_app.command("query")
def ti_query(
    ctx: typer.Context,
    indicator: Annotated[str, typer.Argument(help="Indicator value: IP, domain, URL, hash, etc.")],
    artifact_type: Annotated[str, typer.Option("--artifact-type", help="Artifact type hint.")] = "Unknown",
    provider: Annotated[str | None, typer.Option("--provider", help="Optional provider name.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "ti.query", output, lambda runtime, out: _ti_query(runtime, out, indicator, artifact_type, provider))


@cmdb_app.command("lookup")
def cmdb_lookup(
    ctx: typer.Context,
    artifact_type: Annotated[str, typer.Argument(help="Artifact type.")],
    artifact_value: Annotated[str, typer.Argument(help="Artifact value.")],
    provider: Annotated[str | None, typer.Option("--provider", help="Optional provider name.")] = None,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "cmdb.lookup", output, lambda runtime, out: _cmdb_lookup(runtime, out, artifact_type, artifact_value, provider))


@dev_stream_app.command("head")
def dev_stream_head(
    ctx: typer.Context,
    stream_name: Annotated[str, typer.Argument(help="Redis stream name.")],
    n: Annotated[int, typer.Option("-n", min=1, max=100, help="Number of messages.")] = 3,
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "dev.stream.head", output, lambda runtime, out: _dev_stream_head(runtime, out, stream_name, n))


@dev_stream_app.command("read")
def dev_stream_read(
    ctx: typer.Context,
    stream_name: Annotated[str, typer.Argument(help="Redis stream name.")],
    message_id: Annotated[str, typer.Argument(help="Redis stream message ID.")],
    output: Annotated[OutputFormat | None, typer.Option("--output", help="Output format.")] = None,
) -> None:
    run_command(ctx, "dev.stream.read", output, lambda runtime, out: _dev_stream_read(runtime, out, stream_name, message_id))


@completion_app.command("powershell")
def completion_powershell() -> None:
    console.print("Run this command to install PowerShell completion:")
    console.print("asp --install-completion powershell", style="cyan")


@completion_app.command("bash")
def completion_bash() -> None:
    console.print("Run this command to install Bash completion:")
    console.print("asp --install-completion bash", style="cyan")


@completion_app.command("zsh")
def completion_zsh() -> None:
    console.print("Run this command to install Zsh completion:")
    console.print("asp --install-completion zsh", style="cyan")


def run_command(ctx: typer.Context, operation: str, output: OutputFormat | None, handler) -> None:
    runtime = runtime_options(ctx)
    out = output or runtime.output
    try:
        if runtime.query and out != OutputFormat.json:
            raise CliError("query_requires_json", "--query requires --output json", {}, EXIT_USAGE)
        handler(runtime, out)
    except CliError as exc:
        emit_error(err_console if out == OutputFormat.human else console, output=out, error=exc, operation=operation)
        raise typer.Exit(exc.exit_code) from exc


def runtime_options(ctx: typer.Context) -> RuntimeOptions:
    if isinstance(ctx.obj, RuntimeOptions):
        return ctx.obj
    parent = ctx.parent
    while parent is not None:
        if isinstance(parent.obj, RuntimeOptions):
            return parent.obj
        parent = parent.parent
    return RuntimeOptions(api_url=None, api_key=None, output=OutputFormat.human, query=None, verbose=False)


def _auth_login(runtime: RuntimeOptions, output: OutputFormat, api_url: str, api_key: str, local: bool) -> None:
    path = save_auth(api_url=api_url, api_key=api_key, local=local)
    data = {
        "scope": "local" if local else "global",
        "settings_path": str(path),
        "api_url": api_url.rstrip("/"),
        "api_key": redact_secret(api_key),
    }
    if output == OutputFormat.human:
        console.print(key_value_table("ASP auth saved", list(data.items())))
        console.print("Next: run [cyan]asp doctor[/cyan].")
        return
    emit_runtime_success(runtime, output=output, operation="auth.login", data=data)


def _auth_status(runtime: RuntimeOptions, output: OutputFormat) -> None:
    config = _require_config(runtime)
    client = AspClient(api_url=config.api_url or "", api_key=config.api_key, verbose=runtime.verbose, console=err_console)
    payload = client.version()
    data = {
        "api_url": config.api_url,
        "api_url_source": config.sources.get("api_url"),
        "api_key_source": config.sources.get("api_key"),
        "api_key": redact_secret(config.api_key),
        "server": payload.get("data", {}),
    }
    if output == OutputFormat.human:
        server = data["server"]
        user = server.get("user") or {}
        console.print(
            key_value_table(
                "ASP auth status",
                [
                    ("API URL", data["api_url"]),
                    ("API URL source", data["api_url_source"]),
                    ("API key source", data["api_key_source"]),
                    ("API key", data["api_key"]),
                    ("User", user.get("username")),
                    ("Role", user.get("role")),
                    ("API version", server.get("api_version")),
                ],
            )
        )
        return
    emit_runtime_success(runtime, output=output, operation="auth.status", data=data)


def _auth_logout(runtime: RuntimeOptions, output: OutputFormat, local: bool) -> None:
    path = clear_auth(local=local)
    data = {"scope": "local" if local else "global", "settings_path": str(path)}
    if output == OutputFormat.human:
        console.print(key_value_table("ASP auth removed", list(data.items())))
        return
    emit_runtime_success(runtime, output=output, operation="auth.logout", data=data)


def _config_list(runtime: RuntimeOptions, output: OutputFormat) -> None:
    config = resolve_config(api_url=runtime.api_url, api_key=runtime.api_key)
    global_settings = _redacted_settings(read_settings(config.global_path))
    local_settings = _redacted_settings(read_settings(config.local_path) if config.local_path else {})
    data = {
        "global_path": str(config.global_path),
        "local_path": str(config.local_path) if config.local_path else None,
        "global": global_settings,
        "local": local_settings,
        "resolved": {
            "api_url": config.api_url,
            "api_url_source": config.sources.get("api_url"),
            "api_key": redact_secret(config.api_key),
            "api_key_source": config.sources.get("api_key"),
        },
    }
    if output == OutputFormat.human:
        console.print(key_value_table("ASP config", [
            ("Global path", data["global_path"]),
            ("Local path", data["local_path"]),
            ("Resolved API URL", data["resolved"]["api_url"]),
            ("API URL source", data["resolved"]["api_url_source"]),
            ("Resolved API key", data["resolved"]["api_key"]),
            ("API key source", data["resolved"]["api_key_source"]),
        ]))
        return
    emit_runtime_success(runtime, output=output, operation="config.list", data=data)


def _config_get(runtime: RuntimeOptions, output: OutputFormat, key: str) -> None:
    value, source = get_config_value(key, api_url=runtime.api_url, api_key=runtime.api_key)
    display_value = redact_secret(value) if key == "api_key" else value
    data = {"key": key, "value": display_value, "source": source}
    if output == OutputFormat.human:
        console.print(key_value_table("ASP config value", list(data.items())))
        return
    emit_runtime_success(runtime, output=output, operation="config.get", data=data)


def _config_set(runtime: RuntimeOptions, output: OutputFormat, key: str, value: str, local: bool) -> None:
    path = set_config_value(key, value, local=local)
    data = {"key": key, "scope": "local" if local else "global", "settings_path": str(path)}
    if output == OutputFormat.human:
        console.print(key_value_table("ASP config saved", list(data.items())))
        return
    emit_runtime_success(runtime, output=output, operation="config.set", data=data)


def _doctor(runtime: RuntimeOptions, output: OutputFormat) -> None:
    config = _require_config(runtime)
    client = AspClient(api_url=config.api_url or "", api_key=config.api_key, verbose=runtime.verbose, console=err_console)
    checks = []
    ok = True

    try:
        health = client.health()
        checks.append({"name": "health", "ok": True, "detail": health.get("status", "ok")})
    except CliError as exc:
        ok = False
        checks.append({"name": "health", "ok": False, "detail": exc.message})

    version_payload = None
    try:
        version_payload = client.version()
        checks.append({"name": "auth", "ok": True, "detail": "authenticated"})
        checks.append({"name": "version", "ok": True, "detail": version_payload.get("data", {}).get("api_version")})
    except CliError as exc:
        ok = False
        checks.append({"name": "auth", "ok": False, "detail": exc.message})

    data = {
        "ok": ok,
        "api_url": config.api_url,
        "api_url_source": config.sources.get("api_url"),
        "api_key_source": config.sources.get("api_key"),
        "checks": checks,
        "server": version_payload.get("data") if version_payload else None,
    }

    if output == OutputFormat.human:
        console.print(key_value_table("ASP doctor", [
            ("Overall", "ok" if ok else "failed"),
            ("API URL", data["api_url"]),
            ("API URL source", data["api_url_source"]),
            ("API key source", data["api_key_source"]),
        ]))
        for check in checks:
            style = "green" if check["ok"] else "red"
            console.print(f"{check['name']}: {check['detail']}", style=style)
    else:
        emit_runtime_success(runtime, output=output, operation="doctor", data=data)

    if not ok:
        raise typer.Exit(1)


def _list_cases(runtime: RuntimeOptions, output: OutputFormat, **filters) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/cases/", _clean_params(filters))
    _emit_agent_payload(runtime, output, "case.list", payload, lambda data, meta: _list_table(
        "ASP cases",
        ["case_id", "title", "severity", "status", "verdict", "priority", "created_at"],
        data,
        meta,
    ))


def _show_case(runtime: RuntimeOptions, output: OutputFormat, case_id: str, include_related: bool) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/cases/{case_id}/", {"include_related": include_related})
    _emit_agent_payload(runtime, output, "case.show", payload, lambda data, _meta: _detail_table(
        "ASP case",
        data,
        ["case_id", "title", "severity", "confidence", "impact", "priority", "status", "verdict", "severity_ai", "confidence_ai", "impact_ai", "priority_ai", "verdict_ai", "summary", "correlation_uid", "tags", "created_at"],
    ))


def _update_case_ai(runtime: RuntimeOptions, output: OutputFormat, case_id: str, **fields) -> None:
    summary_file = fields.pop("summary_file")
    if summary_file is not None:
        fields["summary"] = _read_text_file(summary_file)
    body = {key: value for key, value in fields.items() if value is not None}
    if not body:
        raise CliError("missing_update_fields", "At least one AI analysis field is required", {}, EXIT_USAGE)
    payload = _agent_request(runtime, "PATCH", f"/api/agent/v1/cases/{case_id}/ai-analysis/", json=body)
    _emit_agent_payload(runtime, output, "case.update_ai", payload, lambda data, _meta: _detail_table(
        "Updated ASP case AI analysis",
        data,
        ["case_id", "severity_ai", "confidence_ai", "impact_ai", "priority_ai", "verdict_ai", "summary"],
    ))


def _list_alerts(runtime: RuntimeOptions, output: OutputFormat, **filters) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/alerts/", _clean_params(filters))
    _emit_agent_payload(runtime, output, "alert.list", payload, lambda data, meta: _list_table(
        "ASP alerts",
        ["alert_id", "case_id", "title", "severity", "status", "confidence", "created_at"],
        data,
        meta,
    ))


def _show_alert(runtime: RuntimeOptions, output: OutputFormat, alert_id: str, include_related: bool) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/alerts/{alert_id}/", {"include_related": include_related})
    _emit_agent_payload(runtime, output, "alert.show", payload, lambda data, _meta: _detail_table(
        "ASP alert",
        data,
        ["alert_id", "case_id", "title", "severity", "confidence", "impact", "status", "correlation_uid", "source_uid", "rule_id", "rule_name", "created_at"],
    ))


def _list_artifacts(runtime: RuntimeOptions, output: OutputFormat, **filters) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/artifacts/", _clean_params(filters))
    _emit_agent_payload(runtime, output, "artifact.list", payload, lambda data, meta: _list_table(
        "ASP artifacts",
        ["artifact_id", "type", "role", "name", "value", "created_at"],
        data,
        meta,
    ))


def _show_artifact(runtime: RuntimeOptions, output: OutputFormat, artifact_id: str, include_related: bool) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/artifacts/{artifact_id}/", {"include_related": include_related})
    _emit_agent_payload(runtime, output, "artifact.show", payload, lambda data, _meta: _detail_table(
        "ASP artifact",
        data,
        ["artifact_id", "type", "role", "name", "value", "created_at"],
    ))


def _search_knowledge(runtime: RuntimeOptions, output: OutputFormat, **filters) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/knowledge/", _clean_params(filters))
    _emit_agent_payload(runtime, output, "knowledge.search", payload, lambda data, meta: _list_table(
        "ASP knowledge",
        ["knowledge_id", "title", "source", "case_id", "tags", "created_at"],
        data,
        meta,
    ))


def _show_knowledge(runtime: RuntimeOptions, output: OutputFormat, knowledge_id: str) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/knowledge/{knowledge_id}/", {})
    _emit_agent_payload(runtime, output, "knowledge.show", payload, lambda data, _meta: _detail_table(
        "ASP knowledge",
        data,
        ["knowledge_id", "title", "source", "case_id", "tags", "expires_at", "body", "created_at"],
    ))


def _update_knowledge(runtime: RuntimeOptions, output: OutputFormat, knowledge_id: str, **fields) -> None:
    body_file = fields.pop("body_file")
    if body_file is not None:
        fields["body"] = _read_text_file(body_file)
    if fields.get("tags") is not None:
        fields["tags"] = _split_csv(fields["tags"])
    body = {key: value for key, value in fields.items() if value is not None}
    if not body:
        raise CliError("missing_update_fields", "At least one knowledge field is required", {}, EXIT_USAGE)
    payload = _agent_request(runtime, "PATCH", f"/api/agent/v1/knowledge/{knowledge_id}/", json=body)
    _emit_agent_payload(runtime, output, "knowledge.update", payload, lambda data, _meta: _detail_table(
        "Updated ASP knowledge",
        data,
        ["knowledge_id", "title", "source", "case_id", "tags", "expires_at", "body"],
    ))


def _list_comments(runtime: RuntimeOptions, output: OutputFormat, target_id: str, cursor: str | None, page_size: int | None) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/comments/", _clean_params({
        "target_id": target_id,
        "cursor": cursor,
        "page_size": page_size,
    }))
    _emit_agent_payload(runtime, output, "comment.list", payload, lambda data, meta: _list_table(
        "ASP comments",
        ["id", "author", "body", "parent_id", "created_at"],
        data,
        meta,
    ))


def _add_comment(runtime: RuntimeOptions, output: OutputFormat, target_id: str, **fields) -> None:
    body_file = fields.pop("body_file")
    if body_file is not None:
        fields["body"] = _read_text_file(body_file)
    body = {
        "target_id": target_id,
        "body": fields.get("body") or "",
        "file_keys": _split_csv(fields.get("file_key")),
        "parent_id": fields.get("parent_id"),
        "mentions": _split_csv(fields.get("mentions")),
    }
    if not body["body"].strip() and not body["file_keys"]:
        raise CliError("missing_comment_content", "Comment body or file_key is required", {}, EXIT_USAGE)
    payload = _agent_request(runtime, "POST", "/api/agent/v1/comments/", json=body)
    _emit_agent_payload(runtime, output, "comment.add", payload, lambda data, _meta: _detail_table(
        "ASP comment added",
        data,
        ["id", "author", "body", "parent_id", "created_at"],
    ))


def _upload_file(runtime: RuntimeOptions, output: OutputFormat, path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise CliError("file_not_found", f"File not found: {path}", {"path": str(path)}, EXIT_USAGE)
    with path.open("rb") as handle:
        payload = _agent_request(runtime, "POST", "/api/agent/v1/files/", files={"file": (path.name, handle)})
    _emit_agent_payload(runtime, output, "file.upload", payload, lambda data, _meta: _detail_table(
        "ASP file uploaded",
        data,
        ["file_key", "filename", "size", "content_type", "download_url"],
    ))


def _file_info(runtime: RuntimeOptions, output: OutputFormat, file_key: str) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/files/{file_key}/", {})
    _emit_agent_payload(runtime, output, "file.info", payload, lambda data, _meta: _detail_table(
        "ASP file",
        data,
        ["file_key", "filename", "size", "content_type", "download_url", "uploaded_at"],
    ))


def _download_file(runtime: RuntimeOptions, output: OutputFormat, file_key: str, output_path: Path | None) -> None:
    info = _agent_get(runtime, f"/api/agent/v1/files/{file_key}/", {})
    data = info.get("data") or {}
    target_path = output_path or Path(data.get("filename") or file_key)
    try:
        response = httpx.get(data["download_url"], timeout=60.0)
        response.raise_for_status()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(response.content)
    except (KeyError, httpx.HTTPError, OSError) as exc:
        raise CliError("file_download_failed", f"Unable to download file: {file_key}", {"file_key": file_key}, EXIT_NETWORK) from exc
    result = {**data, "output_path": str(target_path)}
    if output == OutputFormat.human:
        console.print(key_value_table("ASP file downloaded", [
            ("file_key", result.get("file_key")),
            ("filename", result.get("filename")),
            ("output_path", result.get("output_path")),
            ("size", result.get("size")),
        ]))
        return
    emit_runtime_success(runtime, output=output, operation="file.download", data=result, meta=info.get("meta"))


def _read_file_text(runtime: RuntimeOptions, output: OutputFormat, file_key: str, max_bytes: int) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/files/{file_key}/read-text/", {"max_bytes": max_bytes})
    _emit_agent_payload(runtime, output, "file.read_text", payload, lambda data, _meta: data.get("text", ""))


def _create_enrichment(runtime: RuntimeOptions, output: OutputFormat, target_id: str, **fields) -> None:
    data_file = fields.pop("data_file")
    data_json = fields.pop("data_json")
    body = {"target_id": target_id, **fields}
    if data_file is not None:
        body["data"] = _read_json_object_file(data_file)
    elif data_json is not None:
        body["data"] = _read_json_object_text(data_json)
    else:
        body["data"] = {}
    payload = _agent_request(runtime, "POST", "/api/agent/v1/enrichments/", json=body)
    _emit_agent_payload(runtime, output, "enrichment.create", payload, lambda data, _meta: _detail_table(
        "ASP enrichment created",
        data,
        ["enrichment_id", "target_id", "name", "type", "provider", "uid", "value", "desc", "created_at"],
    ))


def _list_playbook_templates(runtime: RuntimeOptions, output: OutputFormat) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/playbooks/templates/", {})
    _emit_agent_payload(runtime, output, "playbook.template.list", payload, lambda data, _meta: _list_table(
        "ASP playbook templates",
        ["name", "description", "tags"],
        data,
    ))


def _list_playbooks(runtime: RuntimeOptions, output: OutputFormat, **filters) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/playbooks/", _clean_params(filters))
    _emit_agent_payload(runtime, output, "playbook.list", payload, lambda data, meta: _list_table(
        "ASP playbooks",
        ["playbook_id", "case_id", "name", "job_status", "job_id", "created_at"],
        data,
        meta,
    ))


def _show_playbook(runtime: RuntimeOptions, output: OutputFormat, playbook_id: str, include_related: bool) -> None:
    payload = _agent_get(runtime, f"/api/agent/v1/playbooks/{playbook_id}/", {"include_related": include_related})
    _emit_agent_payload(runtime, output, "playbook.show", payload, lambda data, _meta: _detail_table(
        "ASP playbook",
        data,
        ["playbook_id", "case_id", "name", "user_input", "job_status", "job_id", "remark", "created_at"],
    ))


def _run_playbook(runtime: RuntimeOptions, output: OutputFormat, name: str, case_id: str, **fields) -> None:
    user_input_file = fields.get("user_input_file")
    user_input = _read_text_file(user_input_file) if user_input_file is not None else (fields.get("user_input") or "")
    payload = _agent_request(runtime, "POST", "/api/agent/v1/playbooks/run/", json={
        "name": name,
        "case_id": case_id,
        "user_input": user_input,
    })
    _emit_agent_payload(runtime, output, "playbook.run", payload, lambda data, _meta: _detail_table(
        "ASP playbook queued",
        data,
        ["playbook_id", "case_id", "name", "job_status", "created_at"],
    ))


def _siem_schema(runtime: RuntimeOptions, output: OutputFormat, target_index: str | None) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/siem/schema/", _clean_params({"target_index": target_index}))
    if target_index:
        renderer = lambda data, _meta: _siem_schema_detail(data)
    else:
        renderer = lambda data, _meta: _list_table(
            "ASP SIEM schema",
            ["name", "backend", "description", "default_aggregation_fields"],
            data,
        )
    _emit_agent_payload(runtime, output, "siem.schema", payload, renderer)


def _siem_keyword(runtime: RuntimeOptions, output: OutputFormat, keyword: str, time_range_start: str, time_range_end: str, time_field: str, index_name: str | None) -> None:
    body = {
        "keyword": _split_csv(keyword) if "," in keyword else keyword,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "time_field": time_field,
        "index_name": index_name,
    }
    payload = _agent_request(runtime, "POST", "/api/agent/v1/siem/search/keyword/", json=_clean_params(body))
    _emit_agent_payload(runtime, output, "siem.search.keyword", payload, _siem_query_table)


def _siem_adaptive(
    runtime: RuntimeOptions,
    output: OutputFormat,
    index_name: str,
    time_range_start: str,
    time_range_end: str,
    time_field: str,
    filters_json: str | None,
    filters_file: Path | None,
    aggregation_fields: str | None,
) -> None:
    filters = {}
    if filters_file is not None:
        filters = _read_json_object_file(filters_file)
    elif filters_json is not None:
        filters = _read_json_object_text(filters_json)
    payload = _agent_request(runtime, "POST", "/api/agent/v1/siem/query/adaptive/", json={
        "index_name": index_name,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "time_field": time_field,
        "filters": filters,
        "aggregation_fields": _split_csv(aggregation_fields),
    })
    _emit_agent_payload(runtime, output, "siem.query.adaptive", payload, _siem_query_table)


def _siem_raw_query(
    runtime: RuntimeOptions,
    output: OutputFormat,
    kind: str,
    query: str,
    time_range_start: str,
    time_range_end: str,
    limit: int,
    time_field: str,
    index_name: str | None,
) -> None:
    payload = _agent_request(runtime, "POST", f"/api/agent/v1/siem/query/{kind}/", json=_clean_params({
        "query": query,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "limit": limit,
        "time_field": time_field,
        "index_name": index_name,
    }))
    _emit_agent_payload(runtime, output, f"siem.query.{kind}", payload, _siem_query_table)


def _siem_fields_discover(runtime: RuntimeOptions, output: OutputFormat, index_name: str, backend: str, time_range_start: str, time_range_end: str, doc_limit: int, max_samples_per_field: int) -> None:
    payload = _agent_request(runtime, "POST", "/api/agent/v1/siem/fields/discover/", json={
        "index_name": index_name,
        "backend": backend,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "doc_limit": doc_limit,
        "max_samples_per_field": max_samples_per_field,
    })
    _emit_agent_payload(runtime, output, "siem.fields.discover", payload, lambda data, _meta: _detail_table(
        "ASP SIEM fields",
        data,
        ["backend", "index_name", "total_fields"],
    ))


def _ti_query(runtime: RuntimeOptions, output: OutputFormat, indicator: str, artifact_type: str, provider: str | None) -> None:
    payload = _agent_request(runtime, "POST", "/api/agent/v1/threat-intel/query/", json=_clean_params({
        "indicator": indicator,
        "artifact_type": artifact_type,
        "provider": provider,
    }))
    _emit_agent_payload(runtime, output, "ti.query", payload, lambda data, _meta: _detail_table(
        "ASP threat intelligence",
        data,
        ["indicator", "indicator_type", "aggregated_risk_level", "errors"],
    ))


def _cmdb_lookup(runtime: RuntimeOptions, output: OutputFormat, artifact_type: str, artifact_value: str, provider: str | None) -> None:
    payload = _agent_request(runtime, "POST", "/api/agent/v1/cmdb/lookup/", json=_clean_params({
        "artifact_type": artifact_type,
        "artifact_value": artifact_value,
        "provider": provider,
    }))
    _emit_agent_payload(runtime, output, "cmdb.lookup", payload, lambda data, _meta: _detail_table(
        "ASP CMDB lookup",
        data,
        ["artifact_type", "artifact_value", "errors"],
    ))


def _dev_stream_head(runtime: RuntimeOptions, output: OutputFormat, stream_name: str, n: int) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/dev/streams/head/", {"stream_name": stream_name, "n": n})
    _emit_agent_payload(runtime, output, "dev.stream.head", payload, lambda data, _meta: _list_table(
        "ASP stream head",
        ["message_id", "data"],
        data,
    ))


def _dev_stream_read(runtime: RuntimeOptions, output: OutputFormat, stream_name: str, message_id: str) -> None:
    payload = _agent_get(runtime, "/api/agent/v1/dev/streams/message/", {"stream_name": stream_name, "message_id": message_id})
    _emit_agent_payload(runtime, output, "dev.stream.read", payload, lambda data, _meta: _detail_table(
        "ASP stream message",
        data,
        ["message_id", "data"],
    ))


def _agent_get(runtime: RuntimeOptions, path: str, params: dict) -> dict:
    return _agent_request(runtime, "GET", _path_with_query(path, params))


def _agent_request(runtime: RuntimeOptions, method: str, path: str, *, json=None, files=None) -> dict:
    config = _require_config(runtime)
    client = AspClient(api_url=config.api_url or "", api_key=config.api_key, verbose=runtime.verbose, console=err_console)
    return client.request(method, path, json=json, files=files)


def _path_with_query(path: str, params: dict) -> str:
    cleaned = _clean_params(params)
    if not cleaned:
        return path
    return f"{path}?{urlencode(cleaned, doseq=True)}"


def _clean_params(params: dict) -> dict:
    cleaned = {}
    for key, value in params.items():
        if value is None or value is False or value == "":
            continue
        if key == "tags":
            cleaned["tag"] = _split_csv(value)
        elif isinstance(value, str) and "," in value and key in {"status", "severity", "confidence", "verdict", "type", "role"}:
            cleaned[key] = _split_csv(value)
        else:
            cleaned[key] = value
    return cleaned


def _emit_agent_payload(runtime: RuntimeOptions, output: OutputFormat, operation: str, payload: dict, human_renderer) -> None:
    data = payload.get("data")
    meta = payload.get("meta") or {}
    if output == OutputFormat.human:
        console.print(human_renderer(data, meta))
        return
    emit_runtime_success(runtime, output=output, operation=operation, data=data, meta=meta)


def _list_table(title: str, columns: list[str], rows: list[dict], meta: dict | None = None) -> Table:
    table = Table(title=title)
    for column in columns:
        table.add_column(column)
    for row in rows or []:
        table.add_row(*[_format_cell(row.get(column)) for column in columns])
    pagination = (meta or {}).get("pagination") or {}
    if pagination.get("has_more"):
        table.caption = f"More results available. Continue with --cursor {pagination.get('next_cursor')}"
    return table


def _detail_table(title: str, data: dict, fields: list[str]) -> Table:
    return key_value_table(title, [(field, _format_cell(data.get(field))) for field in fields if field in data])


def _siem_schema_detail(data: dict) -> Table:
    table = _detail_table("ASP SIEM schema", data, ["name", "backend", "description"])
    fields = data.get("fields") or []
    table.caption = f"{len(fields)} fields. Use --output json for full field metadata."
    return table


def _siem_query_table(data, _meta) -> Table:
    rows = data if isinstance(data, list) else [data]
    return _list_table(
        "ASP SIEM query",
        ["backend", "index_name", "status", "total_hits", "returned_records", "truncated", "message"],
        rows,
    )


def _format_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}={val}" for key, val in value.items())
    text = str(value)
    return text if len(text) <= 160 else f"{text[:157]}..."


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError("file_read_failed", f"Unable to read file: {path}", {"path": str(path)}, EXIT_USAGE) from exc


def _read_json_object_file(path: Path) -> dict:
    return _read_json_object_text(_read_text_file(path))


def _read_json_object_text(text: str) -> dict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliError("invalid_json", "Expected a valid JSON object", {}, EXIT_USAGE) from exc
    if not isinstance(payload, dict):
        raise CliError("invalid_json", "Expected a valid JSON object", {}, EXIT_USAGE)
    return payload


def _require_config(runtime: RuntimeOptions):
    config = resolve_config(api_url=runtime.api_url, api_key=runtime.api_key)
    missing = []
    if not config.api_url:
        missing.append("api_url")
    if not config.api_key:
        missing.append("api_key")
    if missing:
        raise CliError(
            "missing_config",
            "ASP API URL and API key are required. Run: asp auth login --api-url <url> --api-key <key>",
            {"missing": missing},
            EXIT_AUTH if "api_key" in missing else EXIT_CONFIG,
        )
    return config


def _redacted_settings(settings: dict) -> dict:
    redacted = dict(settings)
    if "api_key" in redacted:
        redacted["api_key"] = redact_secret(str(redacted["api_key"]))
    return redacted


def apply_query(data, query: str | None):
    if not query:
        return data
    return jmespath.search(query, data)


def emit_runtime_success(
    runtime: RuntimeOptions,
    *,
    output: OutputFormat,
    operation: str,
    data,
    meta: dict | None = None,
    human: str | None = None,
) -> None:
    emit_success(
        console,
        output=output,
        operation=operation,
        data=apply_query(data, runtime.query) if output == OutputFormat.json else data,
        meta=meta,
        human=human,
    )


def run() -> None:
    app()


if __name__ == "__main__":
    run()
