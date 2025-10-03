# retrieval/search.py
from typing import List, Dict
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

from malware_rag_project import config
from malware_rag_project.ingestion.preprocessing import extract_code_features

class MalwareSearch:
    def __init__(self, client: QdrantClient, code_embedder: SentenceTransformer):
        self.client = client
        self.code_embedder = code_embedder

    def retrieve_similar(self, query_code: str, top_k: int = 10, filters: Dict = None) -> List[Dict]:
        """Retrieve similar malware samples from the vector store."""
        query_embedding = self.code_embedder.encode(query_code)
        
        results = self.client.search(
            collection_name=config.CODE_COLLECTION,
            query_vector=query_embedding.tolist(),
            limit=top_k,
            query_filter=filters
        )
        
        return [
            {"score": hit.score, "text": hit.payload.get("text", ""), "metadata": hit.payload}
            for hit in results
        ]

    def hybrid_search(self, query: str, top_k: int = 20) -> List[Dict]:
        """Combine dense (vector) and sparse (keyword) search."""
        dense_results = self.retrieve_similar(query, top_k=top_k)
        
        keywords = extract_code_features(query)
        important_terms = (keywords['api_calls'] + 
                           keywords['network_operations'] + 
                           keywords['crypto_operations'])
        
        for result in dense_results:
            metadata_text = result['metadata'].get('text', '').lower()
            keyword_matches = sum(1 for term in important_terms if term.lower() in metadata_text)
            result['score'] += keyword_matches * 0.1  # Boost score
        
        return sorted(dense_results, key=lambda x: x['score'], reverse=True)[:top_k//2]
