from qdrant_client import QdrantClient

from PLUGINS.Qdrant.CONFIG import QDRANT_URL, QDRANT_API_KEY


class Qdrant(object):

    def __init__(self):
        pass

    @staticmethod
    def get_client():
        client = QdrantClient(
            url=QDRANT_URL,
            api_key=QDRANT_API_KEY
        )
        return client
