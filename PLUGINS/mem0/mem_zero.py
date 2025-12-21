from mem0 import Memory

from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_SIZE
from PLUGINS.Embeddings.embeddings_qdrant import EmbeddingsAPI
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.Qdrant.qdrant import Qdrant
from PLUGINS.neo4j.CONFIG import NEO4J_URL, NEO4J_PASSWORD, NEO4J_USER


class MemZero(object):

    def __init__(self):
        # embeddings
        self.embeddings_model = EmbeddingsAPI.get_dense_model()

        # llm
        llm_api = LLMAPI()
        self.llm_model = llm_api.get_model(tag=["fast"])

        self.vector_store = Qdrant.get_client()

        config = {
            # "reranker": {
            #     "provider": "llm_reranker",
            #     "config": {
            #         "llm": {
            #             "provider": "openai",
            #             "config": {
            #                 "model": "qwen3-rerank",
            #                 # "api_key": "sk-XXX",
            #                 # "openai_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
            #             }
            #         }
            #     }
            # },
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

        memory = Memory.from_config(config)

        conversation = [
            {"role": "user", "content": "chengyu met panqi at GraphConf 2025 in San Francisco."},
            {"role": "assistant", "content": "Great! Logging that connection."},
        ]

        memory.add(conversation, user_id="demo-user")

        results = memory.search(
            "Who did Alice meet at GraphConf?",
            user_id="demo-user",
            limit=3,
            rerank=True,
        )

        for hit in results["results"]:
            print(hit["memory"])
