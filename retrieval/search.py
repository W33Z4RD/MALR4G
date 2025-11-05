# retrieval/search.py
from typing import List, Dict
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

import config
from ingestion.preprocessing import extract_code_features

class MalwareSearch:
    def __init__(self, client: QdrantClient, code_embedder: SentenceTransformer):
        self.client = client
        self.code_embedder = code_embedder

    def retrieve_similar(self, query_code: str, top_k: int = 10, filters: Dict = None) -> List[Dict]:
        """Retrieve similar malware samples from the vector store using dense vector search."""
        query_embedding = self.code_embedder.encode(query_code)
        
        results = self.client.search(
            collection_name=config.CODE_COLLECTION,
            query_vector=query_embedding.tolist(),
            limit=top_k,
            query_filter=filters # An optional filter to apply to the search (e.g., only search for a specific language).
        )
        
        return [
            {
                "score": hit.score,
                "text": hit.payload.get("text", ""),
                "metadata": hit.payload
            }
            for hit in results
        ]

    def hybrid_search(self, query: str, top_k: int = 20) -> List[Dict]:
        """Combine dense (vector) and sparse (keyword) search for more relevant results."""
        
        # First, perform a normal vector search to find semantically similar items.
        dense_results = self.retrieve_similar(query, top_k=top_k)
        
        # Next, we re-rank these initial results by giving a score boost to items
        # that also share specific, important keywords with the query.
        keywords = extract_code_features(query)
        important_terms = (keywords['api_calls'] + 
                           keywords['network_operations'] + 
                           keywords['crypto_operations'])
        
        for result in dense_results:
            metadata_text = result['metadata'].get('text', '').lower()
            keyword_matches = sum(1 for term in important_terms if term.lower() in metadata_text)
            result['score'] += keyword_matches * 0.1  # The `0.1` is a weighting factor.
        
        return sorted(dense_results, key=lambda x: x['score'], reverse=True)[:top_k//2]
