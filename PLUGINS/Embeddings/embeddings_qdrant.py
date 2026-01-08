# uncomment the code to set a custom Hugging Face endpoint if needed.
# import os
# os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
import os
import uuid

import httpx
import torch
import urllib3
from langchain_classic.retrievers import ContextualCompressionRetriever
from langchain_classic.retrievers.document_compressors import CrossEncoderReranker
from langchain_community.cross_encoders import HuggingFaceCrossEncoder
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
from langchain_openai import OpenAIEmbeddings
from langchain_qdrant import QdrantVectorStore, FastEmbedSparse, RetrievalMode
from qdrant_client import models

from Lib.configs import BASE_DIR
from Lib.log import logger
from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_TYPE, EMBEDDINGS_BASE_URL, EMBEDDINGS_MODEL, EMBEDDINGS_API_KEY, EMBEDDINGS_SIZE, EMBEDDINGS_PROXY
from PLUGINS.Qdrant.qdrant import Qdrant

# 检查 GPU 是否可用
device = "cuda" if torch.cuda.is_available() else "cpu"
logger.info(f"Using device for embeddings and reranker: {device}")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EmbeddingsAPI(object):

    def __init__(self):
        # you need to use Docker/huggingface/download_model.py to download the bm25 model first
        self.sparse_model = FastEmbedSparse(model_name="Qdrant/bm25",
                                            cache_dir=os.path.join(BASE_DIR, 'Docker', 'Huggingface', 'bm25'),
                                            local_files_only=True)
        self.dense_model = self.get_dense_model()
        self.vector_client = Qdrant.get_client()
        self.rerank_model = HuggingFaceCrossEncoder(model_name=os.path.join(BASE_DIR, 'Docker', 'Huggingface', 'bge-reranker-v2-m3'),
                                                    model_kwargs={
                                                        'local_files_only': True,
                                                        'device': device
                                                    })

    @staticmethod
    def get_dense_model():
        if EMBEDDINGS_TYPE not in ['openai', 'ollama']:
            raise ValueError(f"Invalid EMBEDDINGS_TYPE in CONFIG.py: '{EMBEDDINGS_TYPE}'. Must be 'openai' or 'ollama'.")
        http_client = httpx.Client(proxy=EMBEDDINGS_PROXY) if EMBEDDINGS_PROXY else None
        if EMBEDDINGS_TYPE == 'openai':
            # noinspection PyTypeChecker
            dense_model = OpenAIEmbeddings(
                base_url=EMBEDDINGS_BASE_URL,
                model=EMBEDDINGS_MODEL,
                api_key=EMBEDDINGS_API_KEY,
                check_embedding_ctx_length=False,
                http_client=http_client
            )
            return dense_model
        elif EMBEDDINGS_TYPE == 'ollama':
            dense_model = OllamaEmbeddings(base_url=EMBEDDINGS_BASE_URL, model=EMBEDDINGS_MODEL)
            return dense_model
        else:
            raise ValueError(f"Unsupported client_type: {EMBEDDINGS_TYPE}")

    def search_with_rerank(self, collection_name: str, query: str, k: int = 20, top_n: int = 5):
        # 使用封装好的检索器直接查询

        # 获取基础的混合检索器
        base_vector_store = self.vector_store(collection_name)
        base_retriever = base_vector_store.as_retriever(search_kwargs={"k": k})

        # 配置本地 BGE Reranker
        compressor = CrossEncoderReranker(model=self.rerank_model, top_n=top_n)

        # 封装为压缩检索器
        compression_retriever = ContextualCompressionRetriever(
            base_compressor=compressor,
            base_retriever=base_retriever
        )
        result_docs = compression_retriever.invoke(query)
        return result_docs

    def delete_collection(self, collection_name: str):
        if self.vector_client.collection_exists(collection_name):
            self.vector_client.delete_collection(collection_name=collection_name)
            return True
        return False

    def vector_store(self, collection_name: str) -> QdrantVectorStore:
        if not self.vector_client.collection_exists(collection_name):
            self.vector_client.create_collection(
                collection_name=collection_name,
                vectors_config=models.VectorParams(
                    size=EMBEDDINGS_SIZE,
                    distance=models.Distance.COSINE
                ),
                # Configure sparse vectors
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

    def add_document(self, collection_name: str, ids: str, page_content: str, metadata: dict) -> str:
        namespace = uuid.NAMESPACE_DNS
        doc_id = str(uuid.uuid5(namespace, ids))
        vector_store = self.vector_store(collection_name)
        document = Document(id=doc_id, page_content=page_content, metadata=metadata)
        result = vector_store.add_documents([document])
        return result[0]

    def delete_document(self, collection_name: str, ids: str) -> bool | None:
        namespace = uuid.NAMESPACE_DNS
        doc_id = str(uuid.uuid5(namespace, ids))
        vector_store = self.vector_store(collection_name)
        result = vector_store.delete(ids=[doc_id])
        return result

    def search_documents(self, collection_name: str, query: str, k: int) -> list[tuple[Document, float]]:
        vector_store = self.vector_store(collection_name)
        results = vector_store.similarity_search_with_score(query, k=k)
        return results

    def search_documents_with_rerank(self, collection_name: str, query: str, k: int = 20, top_n: int = 5) -> list[Document]:
        """
        手动实现重排序以获取分数
        """
        vector_store = self.vector_store(collection_name)
        initial_docs = vector_store.similarity_search(query, k=k)

        if not initial_docs:
            return []

        # BGE Reranker 需要 [ [query, doc1], [query, doc2], ... ] 的格式
        pairs = [[query, doc.page_content] for doc in initial_docs]
        scores = self.rerank_model.client.predict(pairs)  # 直接调用底层 sentence_transformers 对象的 predict

        #  组合结果并排序
        scored_docs = []
        for i, doc in enumerate(initial_docs):
            # 手动将分数注入 metadata 供后续使用,并同时返回元组
            doc.metadata["rerank_score"] = float(scores[i])
            scored_docs.append(doc)

        # 按分数从大到小排序
        scored_docs.sort(key=lambda x: x.metadata["rerank_score"], reverse=True)

        # 5. 返回前 top_n 个
        return scored_docs[:top_n]


embedding_api_singleton_qdrant = EmbeddingsAPI()
