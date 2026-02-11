import splunklib.client

from PLUGINS.Splunk.CONFIG import SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASS


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
