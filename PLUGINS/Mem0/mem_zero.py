import os

from mem0 import Memory

from Lib.configs import BASE_DIR
from Lib.log import logger
from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_SIZE
from PLUGINS.Embeddings.embeddings_qdrant import EmbeddingsAPI
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.Neo4j.CONFIG import NEO4J_URL, NEO4J_PASSWORD, NEO4J_USER
from PLUGINS.Qdrant.qdrant import Qdrant


class MemZero(object):

    def __init__(self):
        # embeddings
        self.embeddings_model = EmbeddingsAPI.get_dense_model()

        # llm
        llm_api = LLMAPI()
        self.llm_model = llm_api.get_model(tag=["fast"])

        self.vector_store = Qdrant.get_client()
        # your need to download the model from huggingface.co for the first run.
        config = {
            "reranker": {
                "provider": "huggingface",
                "config": {
                    # you need to use Docker/huggingface/download_model.py to download the bge-reranker-v2-m3 model first
                    "model": os.path.join(BASE_DIR, 'Docker', 'Huggingface', 'bge-reranker-v2-m3'),
                    "device": "cpu",
                    "local_files_only": True,

                    # you can use the online model if you have GPU and internet access
                    # "model": "BAAI/bge-reranker-v2-m3",
                    # "device": "cuda",
                }
            },

            "graph_store": {
                "provider": "neo4j",
                "config": {
                    "url": NEO4J_URL,
                    "username": NEO4J_USER,
                    "password": NEO4J_PASSWORD,
                }
            },
            "vector_store": {
                "provider": "qdrant",
                "config": {
                    "collection_name": "knowledge_mem0",
                    "client": self.vector_store,
                    "embedding_model_dims": EMBEDDINGS_SIZE,
                    "on_disk": True,
                }
            },
            "llm": {
                "provider": "langchain",
                "config": {
                    "model": self.llm_model,
                }
            },
            "embedder": {
                "provider": "langchain",
                "config": {
                    "model": self.embeddings_model,
                }
            },

        }

        self.memory = Memory.from_config(config)
        logger.info("MemZero initialized successfully.")

    def add_mem(self, user_id: str, run_id: str, content: str, metadata: dict):
        """
        result = {
                "results": vector_store_result,
                "relations": graph_result,
        }
        """
        result = self.memory.add(content, user_id=user_id, run_id=run_id, metadata=metadata)
        return result

    def search_mem(self, user_id: str, query: str, limit: int = 5, rerank: bool = True):
        """
        result = {"results": [{"id": "...", "memory": "...", "score": 0.8, ...}],"relations":[...]}
        """
        result = self.memory.siem_search_by_natural_language(
            query,
            user_id=user_id,
            limit=limit,
            rerank=rerank,
        )
        return result

    def delete_mem(self, user_id: str, run_id: str):
        result = self.memory.delete_all(user_id=user_id, run_id=run_id)
        return result

    # def demo(self):
    #     conversation = [
    #         {"role": "user", "content": "10.198.125.16是安全部门的扫描器,可能会产生NDR告警,直接忽略"},
    #         {"role": "user", "content": "test@gmail.com是钓鱼模拟邮箱,如果用户上报的钓鱼邮件是这个邮箱,直接降低等级"},
    #     ]
    #
    #     result_add = self.memory.add(conversation, user_id="demo-user")
    #     print(result_add)
    #     print(time.time())
    #     results = self.memory.search(
    #         "test@gmail.com需要安全部门封禁吗?",
    #         user_id="demo-user",
    #         limit=3,
    #         rerank=True,
    #     )
    #     for hit in results["results"]:
    #         print(hit)
    #     print(time.time())
    #
    # def delete(self):
    #     result_delete = self.memory.delete_all(user_id="demo-user")
    #     print(result_delete)


mem_zero_singleton = MemZero()
