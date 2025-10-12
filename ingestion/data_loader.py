# ingestion/data_loader.py

# This script is responsible for the main data ingestion workflow.
# It scans a directory of malware samples, processes each file according to its type,
# and uploads the resulting data and embeddings to the Qdrant vector database.

# --- Imports ---

# `hashlib` provides various hashing algorithms. Not directly used here but often useful for creating file checksums.
import hashlib
# `uuid` is used to generate unique identifiers. We use it to create a unique ID for each data point we store.
import uuid
# `pathlib.Path` provides an object-oriented interface for filesystem paths.
from pathlib import Path
# `List` for type hinting.
from typing import List
# `PointStruct` is a specific data structure from the Qdrant client library used to define a point (a vector with its payload) to be uploaded.
from qdrant_client.models import PointStruct
# The main class for loading embedding models.
from sentence_transformers import SentenceTransformer

# Import settings and classes from our other project files.
import config
from ingestion.vector_db import VectorDB
from ingestion.preprocessing import chunk_code_file, analyze_binary, chunk_text_file

# --- The Ingestion Function ---

# This function orchestrates the entire ingestion process.
def ingest_vx_repository(repo_path: str, db: VectorDB, max_files: int = None):
    """Ingest the VX-Underground repository into the vector store."""
    
    # --- Initialization ---

    # Create a Path object from the string representation of the repository path.
    repo = Path(repo_path)
    # Check if the specified path actually exists.
    if not repo.exists():
        print(f"Error: Repository path not found at {repo_path}")
        return # Exit the function if the path is invalid.

    # Load the sentence transformer models specified in the config file.
    print("[*] Loading embedding models...")
    code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
    text_embedder = SentenceTransformer(config.TEXT_EMBEDDER_MODEL)
    
    # Get the Qdrant client object from our VectorDB instance.
    qdrant_client = db.get_client()
    
    # Initialize counters and batch lists.
    file_count = 0
    code_points = []
    text_points = []

    print(f"[*] Scanning repository at {repo_path}...")
    
    # --- File Processing Loop ---
    all_files = list(repo.rglob('*'))
    print(f"[*] Found {len(all_files)} total files and directories.")

    for file_path in all_files:
        # Check if the current path is a file, not a directory.
        if not file_path.is_file():
            continue
        
        # If a `max_files` limit was set, check if we have reached it.
        if max_files and file_count >= max_files:
            print(f"[*] Reached file limit of {max_files}. Stopping ingestion.")
            break
        
        # Get the file's extension and convert it to lowercase.
        suffix = file_path.suffix.lower()
        
        # --- Logic for Code Files ---
        if suffix in config.CODE_EXTENSIONS:
            chunks = chunk_code_file(file_path)
            for idx, chunk in enumerate(chunks):
                embedding = code_embedder.encode(chunk["text"])
                point = PointStruct(
                    id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}_{idx}")),
                    vector=embedding.tolist(),
                    payload={**chunk["metadata"], "chunk_index": idx, "type": "code"}
                )
                code_points.append(point)
                
                if len(code_points) >= 500:
                    qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
                    print(f"[*] Inserted {len(code_points)} code chunks")
                    code_points = []
            
            file_count += 1

        # --- Logic for Binary Files ---
        elif suffix in config.BINARY_EXTENSIONS or not suffix:
            binary_features = analyze_binary(file_path)
            if not binary_features["imports"] and not binary_features["exports"]:
                continue # Skip binaries with no extracted features

            feature_text = f"""
            File: {file_path.name}
            Imports: {', '.join(binary_features['imports'][:50])}
            Exports: {', '.join(binary_features['exports'][:20])}
            Suspicious: {', '.join(binary_features['suspicious_characteristics'])}
            """
            embedding = code_embedder.encode(feature_text)
            point = PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, str(file_path))),
                vector=embedding.tolist(),
                payload={"file": str(file_path), "type": "binary", **binary_features}
            )
            code_points.append(point)
            file_count += 1

        # --- Logic for Document Files ---
        elif suffix in config.DOC_EXTENSIONS:
            if suffix in ['.txt', '.md']:
                chunks = chunk_text_file(file_path)
                for idx, chunk in enumerate(chunks):
                    embedding = text_embedder.encode(chunk["text"])
                    point = PointStruct(
                        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}_{idx}")),
                        vector=embedding.tolist(),
                        payload={**chunk["metadata"], "chunk_index": idx, "type": "document"}
                    )
                    text_points.append(point)

                    if len(text_points) >= 500:
                        qdrant_client.upsert(collection_name=config.TEXT_COLLECTION, points=text_points)
                        print(f"[*] Inserted {len(text_points)} document chunks")
                        text_points = []
                file_count += 1
            elif suffix == '.pdf':
                print(f"[!] PDF processing for {file_path} is not yet implemented. Skipping.")


        # --- Status Update ---
        if file_count > 0 and file_count % 100 == 0:
            print(f"[*] Processed {file_count} files...")

    # --- Final Upload ---
    if code_points:
        qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
        print(f"[*] Inserted final {len(code_points)} code points.")
    if text_points:
        qdrant_client.upsert(collection_name=config.TEXT_COLLECTION, points=text_points)
        print(f"[*] Inserted final {len(text_points)} document points.")
    
    print(f"\n[+] Ingestion complete! Processed {file_count} files.")
