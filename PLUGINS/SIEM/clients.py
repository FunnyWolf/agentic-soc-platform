import splunklib.client
from elasticsearch import Elasticsearch

from PLUGINS.SIEM.CONFIG import ELK_HOST, ELK_USER, ELK_PASS, SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASS


class ELKClient:
    _instance = None

    @classmethod
    def get_client(cls):
        if cls._instance is None:
            cls._instance = Elasticsearch(
                ELK_HOST,
                basic_auth=(ELK_USER, ELK_PASS),
                verify_certs=False,
                request_timeout=30
            )
        return cls._instance


class SplunkClient:
    """Splunk 连接单例工厂 (新增)"""
    _instance = None

    @classmethod
    def get_service(cls):
        if cls._instance is None:
            cls._instance = splunklib.client.connect(
                host=SPLUNK_HOST,
                port=SPLUNK_PORT,
                username=SPLUNK_USER,
                password=SPLUNK_PASS,
                scheme="https",
                verify=False
            )
        return cls._instance
