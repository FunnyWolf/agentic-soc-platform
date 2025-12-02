import json
from typing import Annotated

from langchain_core.tools import tool

from PLUGINS.Mock.CMDB import CMDB


class CMDBAgent(object):

    @staticmethod
    @tool("cmdb_query_asset")
    def query_asset(
            ip: Annotated[str, "The IP address to search for (e.g., '10.67.3.130')"],
            hostname: Annotated[str, "The hostname to search for (e.g., 'WEB-SRV-01')"],
            owner: Annotated[str, "The email or name of the asset owner."]
    ) -> Annotated[str, "A dictionary containing asset details"]:
        """
        Query internal asset information from CMDB.
        """
        logs = CMDB.query_asset(ip, hostname, owner)
        return json.dumps(logs)
