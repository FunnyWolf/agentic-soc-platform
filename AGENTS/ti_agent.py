import json
from typing import Annotated, Literal

from langchain_core.tools import tool

from PLUGINS.Mock.TI import TI


class TIAgent(object):

    @staticmethod
    @tool("ti_lookup")
    def lookup(
            ioc_type: Annotated[Literal["ip", "domain", "hash", "url"], "The type of IOC. Supported: 'ip', 'domain', 'hash', 'url'"],
            ioc_value: Annotated[str, "The value of the IOC (e.g., '1.1.1.1' or 'a1b2...')"],
    ) -> Annotated[str, "Threat intelligence report including risk score and categories"]:
        """
        Check Threat Intelligence reputation for an artifact.
        """
        report = TI.lookup(ioc_type, ioc_value)
        return json.dumps(report)
