# ingestion/vector_db.py
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
import config

class VectorDB:
    def __init__(self):
        """
        Initializes the VectorDB client.
        """
        self.client = QdrantClient(url=config.QDRANT_URL)
        self._initialize_collections()

    def _initialize_collections(self):
        """Create vector store collections if they don't exist."""
        collections = {
            config.CODE_COLLECTION: config.CODE_EMBEDDING_DIM,
        }
        
        for name, dim in collections.items():
            try:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(
                        size=dim, # The vector dimension, which MUST match the embedding model.
                        distance=Distance.COSINE # The similarity metric to use (Cosine Similarity is good for text/code).
                    )
                )
                print(f"Created collection: {name}")
            except Exception:
                print(f"Collection {name} already exists or an error occurred.")

    def get_client(self):
        return self.client