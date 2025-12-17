import httpx
import urllib3
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
from langchain_openai import OpenAIEmbeddings
from langchain_qdrant import QdrantVectorStore, FastEmbedSparse, RetrievalMode
from qdrant_client import models

from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_TYPE, EMBEDDINGS_BASE_URL, EMBEDDINGS_MODEL, EMBEDDINGS_API_KEY, EMBEDDINGS_SIZE, EMBEDDINGS_PROXY
from PLUGINS.Qdrant.qdrant import Qdrant

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EmbeddingsAPI(object):

    def __init__(self):

        if EMBEDDINGS_TYPE not in ['openai', 'ollama']:
            raise ValueError(f"Invalid EMBEDDINGS_TYPE in CONFIG.py: '{EMBEDDINGS_TYPE}'. Must be 'openai' or 'ollama'.")

        self.dense_model = None
        http_client = httpx.Client(proxy=EMBEDDINGS_PROXY) if EMBEDDINGS_PROXY else None
        if EMBEDDINGS_TYPE == 'openai':
            # noinspection PyTypeChecker
            self.dense_model = OpenAIEmbeddings(
                base_url=EMBEDDINGS_BASE_URL,
                model=EMBEDDINGS_MODEL,
                api_key=EMBEDDINGS_API_KEY,
                check_embedding_ctx_length=False,
                http_client=http_client
            )
        elif EMBEDDINGS_TYPE == 'ollama':
            self.dense_model = OllamaEmbeddings(base_url=EMBEDDINGS_BASE_URL, model=EMBEDDINGS_MODEL)
        else:
            raise ValueError(f"Unsupported client_type: {EMBEDDINGS_TYPE}")

        self.sparse_model = FastEmbedSparse(model_name="Qdrant/bm25")
        self.vector_client = Qdrant.get_client()

    def vector_store(self, collection_name: str) -> QdrantVectorStore:
        if not self.vector_client.collection_exists(collection_name):
            self.vector_client.create_collection(
                collection_name=collection_name,
                vectors_config=models.VectorParams(
                    size=EMBEDDINGS_SIZE,
                    distance=models.Distance.COSINE
                ),
                # 配置稀疏向量
                sparse_vectors_config={
                    "qdrant-sparse": models.SparseVectorParams(
                        index=models.SparseIndexParams(on_disk=True)
                    )
                }
            )
        vector_store = QdrantVectorStore(
            client=self.vector_client,
            collection_name=collection_name,
            embedding=self.dense_model,
            sparse_embedding=self.sparse_model,
            sparse_vector_name="qdrant-sparse",
            retrieval_mode=RetrievalMode.HYBRID
        )
        return vector_store

    def add_document(self, collection_name: str, page_content: str, metadata: dict):
        vector_store = self.vector_store(collection_name)
        document = Document(page_content=page_content, metadata=metadata)
        vector_store.add_documents([document])

    def search_documents(self, collection_name: str, query: str, k: int):
        vector_store = self.vector_store(collection_name)
        results = vector_store.similarity_search_with_score(query, k=k)
        return results
