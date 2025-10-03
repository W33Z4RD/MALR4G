# ingestion/data_loader.py
import hashlib
from pathlib import Path
from typing import List
from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

from malware_rag_project import config
from malware_rag_project.ingestion.vector_db import VectorDB
from malware_rag_project.ingestion.preprocessing import chunk_code_file, analyze_binary

def ingest_vx_repository(repo_path: str, db: VectorDB, max_files: int = None):
    """Ingest the VX-Underground repository into the vector store."""
    
    repo = Path(repo_path)
    if not repo.exists():
        print(f"Error: Repository path not found at {repo_path}")
        return

    code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
    qdrant_client = db.get_client()
    
    file_count = 0
    code_points = []

    print("Scanning VX-Underground repository...")
    
    for file_path in repo.rglob('*'):
        if not file_path.is_file():
            continue
        
        if max_files and file_count >= max_files:
            break
        
        suffix = file_path.suffix.lower()
        
        if suffix in config.CODE_EXTENSIONS:
            chunks = chunk_code_file(file_path)
            for idx, chunk in enumerate(chunks):
                embedding = code_embedder.encode(chunk["text"])
                point = PointStruct(
                    id=hashlib.md5(f"{file_path}_{idx}".encode()).hexdigest()[:16],
                    vector=embedding.tolist(),
                    payload={**chunk["metadata"], "chunk_index": idx, "type": "code"}
                )
                code_points.append(point)
                
                if len(code_points) >= 1000:
                    qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
                    print(f"Inserted {len(code_points)} code chunks")
                    code_points = []
            
            file_count += 1
            if file_count % 100 == 0:
                print(f"Processed {file_count} files...")

        elif suffix in config.BINARY_EXTENSIONS:
            binary_features = analyze_binary(file_path)
            feature_text = f"""
            File: {file_path.name}
            Imports: {', '.join(binary_features['imports'][:50])}
            Exports: {', '.join(binary_features['exports'][:20])}
            Suspicious: {', '.join(binary_features['suspicious_characteristics'])}
            """
            embedding = code_embedder.encode(feature_text)
            point = PointStruct(
                id=hashlib.md5(str(file_path).encode()).hexdigest()[:16],
                vector=embedding.tolist(),
                payload={"file": str(file_path), "type": "binary", **binary_features}
            )
            code_points.append(point)
            file_count += 1

    if code_points:
        qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
        print(f"Inserted final {len(code_points)} points")
    
    print(f"Ingestion complete! Processed {file_count} files")
