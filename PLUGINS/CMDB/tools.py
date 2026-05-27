from __future__ import annotations

from typing import Annotated, Any

from PLUGINS.Mock.CMDB.CMDB import cmdb_instance
from PLUGINS.SIRP.sirpcoremodel import ArtifactType


def lookup_cmdb_context_tool(
        artifact_type: Annotated[ArtifactType, "ArtifactType value. Only CMDB-related ArtifactType values are supported."],
        artifact_value: Annotated[str, "Artifact value observed in a SOC alert, for example IP, hostname, user, email, subnet, port or resource UID."],
) -> Annotated[dict[str, Any], "Deterministic mock CMDB context for SOC alert investigation."]:
    """
    Query the mock CMDB with a SIRP ArtifactType and artifact value.

    Supported ArtifactType values: Hostname, IP Address, MAC Address, User Name,
    User, Account, Email Address, Email, Endpoint, Device, Resource UID, Resource,
    Port, Subnet and Serial Number. Unsupported types return a structured error.
    """
    results = cmdb_instance.lookup(artifact_type, artifact_value)  # change to your real CMDB interface
    return results
