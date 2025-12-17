import os

import urllib3
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
from langchain_openai import OpenAIEmbeddings

from Lib.configs import BASE_DIR
from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_TYPE, EMBEDDINGS_BASE_URL, EMBEDDINGS_MODEL, EMBEDDINGS_API_KEY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EmbeddingsAPI(object):

    def __init__(self):

        self.client_type = EMBEDDINGS_TYPE
        if self.client_type not in ['openai', 'ollama']:
            raise ValueError(f"Invalid EMBEDDINGS_TYPE in CONFIG.py: '{self.client_type}'. Must be 'openai' or 'ollama'.")

        self.api_key = EMBEDDINGS_API_KEY
        self.base_url = EMBEDDINGS_BASE_URL
        self.model = EMBEDDINGS_MODEL
        self.embeddings = None
        self.init_embeddings()

    def init_embeddings(self) -> None | OpenAIEmbeddings | OllamaEmbeddings:
        if self.client_type == 'openai':
            # noinspection PyTypeChecker
            self.embeddings = OpenAIEmbeddings(
                base_url=EMBEDDINGS_BASE_URL,
                model=EMBEDDINGS_MODEL,
                api_key=EMBEDDINGS_API_KEY,
                check_embedding_ctx_length=False
            )
            return

        elif self.client_type == 'ollama':
            self.embeddings = OllamaEmbeddings(base_url=EMBEDDINGS_BASE_URL, model=EMBEDDINGS_MODEL)
            return
        else:
            raise ValueError(f"Unsupported client_type: {self.client_type}")

    def vector_store(self, collection_name: str) -> Chroma:
        db_path = os.path.join(BASE_DIR, 'PLUGINS', "Embeddings", "db", "chroma", collection_name)
        vector_store = Chroma(
            persist_directory=db_path,
            collection_name=collection_name,
            embedding_function=self.embeddings
        )
        return vector_store

    def add_document(self, collection_name: str, ids: str, page_content: str, metadata: dict):
        vector_store = self.vector_store(collection_name)
        document = Document(id=ids, page_content=page_content, metadata=metadata)
        vector_store.add_documents([document])

    def update_document(self, collection_name: str, ids: str, page_content: str, metadata: dict):
        vector_store = self.vector_store(collection_name)
        document = Document(id=ids, page_content=page_content, metadata=metadata)
        vector_store.update_document(ids, document)

    def search_documents(self, collection_name: str, query: str, k: int):
        vector_store = self.vector_store(collection_name)
        results = vector_store.similarity_search_with_score(query, k=k)
        return results
