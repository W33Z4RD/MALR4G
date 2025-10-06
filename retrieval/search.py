# retrieval/search.py

# This script defines the search functionality for the application.
# It's responsible for taking a user's query (a piece of suspicious code)
# and finding the most similar items in our vector database.

# --- Imports ---

# Type hints for lists and dictionaries.
from typing import List, Dict
# The main class for encoding text into vectors.
from sentence_transformers import SentenceTransformer
# The main client for interacting with the Qdrant database.
from qdrant_client import QdrantClient

# Import project configuration and helper functions.
import config
from ingestion.preprocessing import extract_code_features

# --- The MalwareSearch Class ---

# This class encapsulates all search-related logic.
class MalwareSearch:
    # The constructor (`__init__`) is called when a new `MalwareSearch` object is created.
    # It requires a Qdrant client and a loaded sentence transformer model.
    def __init__(self, client: QdrantClient, code_embedder: SentenceTransformer):
        # Store the client and embedder as instance attributes to be used by other methods.
        self.client = client
        self.code_embedder = code_embedder

    # This method performs a standard vector similarity search.
    def retrieve_similar(self, query_code: str, top_k: int = 10, filters: Dict = None) -> List[Dict]:
        """Retrieve similar malware samples from the vector store using dense vector search."""
        # Step 1: Convert the user's query code into a vector embedding.
        query_embedding = self.code_embedder.encode(query_code)
        
        # Step 2: Use the Qdrant client to perform the search.
        results = self.client.search(
            collection_name=config.CODE_COLLECTION, # Search in the code collection.
            query_vector=query_embedding.tolist(), # The vector we are searching for.
            limit=top_k, # The maximum number of results to return.
            query_filter=filters # An optional filter to apply to the search (e.g., only search for a specific language).
        )
        
        # Step 3: Format the results into a clean list of dictionaries.
        # This is a list comprehension that iterates through each `hit` in the `results`.
        return [
            {
                "score": hit.score, # The similarity score (higher is better).
                "text": hit.payload.get("text", ""), # The text of the code chunk.
                "metadata": hit.payload # The full metadata payload.
            }
            for hit in results
        ]

    # This method implements a more advanced two-stage search.
    def hybrid_search(self, query: str, top_k: int = 20) -> List[Dict]:
        """Combine dense (vector) and sparse (keyword) search for more relevant results."""
        
        # --- Stage 1: Dense Retrieval ---
        # First, perform a normal vector search to find semantically similar items.
        # We ask for `top_k` results initially.
        dense_results = self.retrieve_similar(query, top_k=top_k)
        
        # --- Stage 2: Sparse Re-ranking ---
        # Next, we re-rank these initial results by giving a score boost to items
        # that also share specific, important keywords with the query.

        # Extract important keywords (APIs, network terms, etc.) from the query code.
        keywords = extract_code_features(query)
        # Combine all the found keywords into a single list.
        important_terms = (keywords['api_calls'] + 
                           keywords['network_operations'] + 
                           keywords['crypto_operations'])
        
        # Loop through each result we got from the dense search.
        for result in dense_results:
            # Get the text content from the result's metadata and convert to lowercase.
            metadata_text = result['metadata'].get('text', '').lower()
            # This is a generator expression inside `sum()`.
            # It generates a `1` for each important term that is found in the result's text.
            # `sum()` then adds them up to get the total number of keyword matches.
            keyword_matches = sum(1 for term in important_terms if term.lower() in metadata_text)
            # Boost the result's original similarity score by a small amount for each keyword match.
            result['score'] += keyword_matches * 0.1  # The `0.1` is a weighting factor.
        
        # --- Final Sorting and Selection ---
        # `sorted()` returns a new list that is sorted.
        # `key=lambda x: x['score']` tells sorted to use the 'score' value of each dictionary for sorting.
        # `reverse=True` sorts the list from highest score to lowest.
        # `[:top_k//2]` is list slicing that selects the top half of the re-ranked results.
        return sorted(dense_results, key=lambda x: x['score'], reverse=True)[:top_k//2]