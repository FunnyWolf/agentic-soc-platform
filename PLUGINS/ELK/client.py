from elasticsearch import Elasticsearch

from PLUGINS.ELK.CONFIG import ELK_HOST, ELK_KEY


class ELKClient:
    _instance = None

    @classmethod
    def get_client(cls):
        if cls._instance is None:
            cls._instance = Elasticsearch(
                ELK_HOST,
                api_key=ELK_KEY,
                verify_certs=False,
                request_timeout=30
            )
        return cls._instance
