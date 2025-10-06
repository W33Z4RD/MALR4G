# ingestion/vector_db.py

# This script defines a class to manage the connection to the Qdrant vector database.
# It handles the initialization and configuration of the database collections.

# --- Imports ---

# Import the main client class from the Qdrant library.
from qdrant_client import QdrantClient
# Import specific data models from the library that we need to configure our collections.
from qdrant_client.models import Distance, VectorParams
# Import our project's configuration settings.
import config

# --- The VectorDB Class ---

# This class wraps the Qdrant client to provide a clean interface for our application.
class VectorDB:
    # The `__init__` constructor is called when we create a new `VectorDB` object.
    def __init__(self):
        """
        Initializes the VectorDB client.
        """
        # This creates a client that connects to a Qdrant server instance.
        self.client = QdrantClient(url=config.QDRANT_URL)
        
        # Call the internal method to set up the database collections.
        self._initialize_collections()

    # A method starting with an underscore `_` is conventionally treated as a "private" method.
    # It's intended for internal use by the class, not to be called from outside.
    def _initialize_collections(self):
        """Create vector store collections if they don't exist."""
        
        # Create a dictionary that maps collection names to their required vector dimensions.
        # This makes it easy to loop through and create them.
        collections = {
            config.CODE_COLLECTION: config.CODE_EMBEDDING_DIM,
            config.TEXT_COLLECTION: config.TEXT_EMBEDDING_DIM
        }
        
        # Loop through the key-value pairs in the `collections` dictionary.
        for name, dim in collections.items():
            # We use a `try...except` block because `create_collection` will raise an error
            # if the collection already exists. This is a clean way to handle that case.
            try:
                # Call the Qdrant client's method to create a new collection.
                self.client.create_collection(
                    collection_name=name, # The name of the collection.
                    # `vectors_config` defines the properties of the vectors in this collection.
                    vectors_config=VectorParams(
                        size=dim, # The vector dimension, which MUST match the embedding model.
                        distance=Distance.COSINE # The similarity metric to use (Cosine Similarity is good for text/code).
                    )
                )
                print(f"Created collection: {name}")
            # A bare `except Exception:` will catch any error. In this case, it's okay because
            # the most likely error is that the collection exists, and if so, we don't need to do anything.
            except Exception:
                print(f"Collection {name} already exists or an error occurred.")

    # This is a simple "getter" method.
    # It provides a controlled way for other parts of the application to get the Qdrant client object.
    def get_client(self):
        return self.client