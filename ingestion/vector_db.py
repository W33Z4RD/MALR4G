# ingestion/vector_db.py
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
from malware_rag_project import config

class VectorDB:
    def __init__(self, path: str = None):
        self.path = path or config.VECTOR_DB_PATH
        self.client = QdrantClient(path=self.path)
        self._initialize_collections()

    def _initialize_collections(self):
        """Create vector store collections if they don't exist."""
        collections = {
            config.CODE_COLLECTION: config.CODE_EMBEDDING_DIM,
            config.TEXT_COLLECTION: config.TEXT_EMBEDDING_DIM
        }
        
        for name, dim in collections.items():
            try:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(size=dim, distance=Distance.COSINE)
                )
                print(f"Created collection: {name}")
            except Exception:
                print(f"Collection {name} already exists or an error occurred.")

    def get_client(self):
        return self.client
