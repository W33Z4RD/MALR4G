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
from ingestion.preprocessing import chunk_code_file, analyze_binary

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

    # Load the sentence transformer model specified in the config file.
    # This will download the model from Hugging Face the first time it's run.
    code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
    # Get the Qdrant client object from our VectorDB instance.
    qdrant_client = db.get_client()
    
    # Initialize a counter for the number of files processed.
    file_count = 0
    # Initialize an empty list to hold the `PointStruct` objects before uploading them in a batch.
    code_points = []

    print("Scanning VX-Underground repository...")
    
    # --- File Processing Loop ---
    # `repo.rglob('*')` is a powerful method that recursively finds all files and directories under the `repo` path.
    for file_path in repo.rglob('*'):
        # Check if the current path is a file, not a directory. If it's a directory, we skip it.
        if not file_path.is_file():
            continue # `continue` skips to the next iteration of the loop.
        
        # If a `max_files` limit was set, check if we have reached it.
        if max_files and file_count >= max_files:
            break # `break` exits the loop entirely.
        
        # Get the file's extension (e.g., '.py', '.exe') and convert it to lowercase.
        suffix = file_path.suffix.lower()
        
        # --- Logic for Code Files ---
        # Check if the file extension is in our set of known code extensions from the config.
        if suffix in config.CODE_EXTENSIONS:
            # Process the code file to split it into smaller chunks.
            chunks = chunk_code_file(file_path)
            # Loop through each chunk returned by the function.
            for idx, chunk in enumerate(chunks):
                # Convert the text of the chunk into a vector embedding.
                embedding = code_embedder.encode(chunk["text"])
                # Create a `PointStruct` for this chunk.
                point = PointStruct(
                    # Generate a deterministic, unique ID for the chunk based on its file path and index.
                    id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}_{idx}")),
                    # The vector embedding. `.tolist()` converts the numpy array to a standard Python list.
                    vector=embedding.tolist(),
                    # The payload contains all the metadata.
                    # `{**chunk["metadata"], ...}` is a neat way to merge two dictionaries.
                    payload={**chunk["metadata"], "chunk_index": idx, "type": "code"}
                )
                # Add the newly created point to our batch list.
                code_points.append(point)
                
                # To avoid using too much memory and to make uploads faster, we upload in batches.
                if len(code_points) >= 1000:
                    qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
                    print(f"Inserted {len(code_points)} code chunks")
                    code_points = [] # Reset the list after uploading.
            
            file_count += 1 # Increment the file counter.
            # The modulo operator `%` gives the remainder of a division. This prints a status update every 100 files.
            if file_count % 100 == 0:
                print(f"Processed {file_count} files...")

        # --- Logic for Binary Files ---
        # `elif` checks this condition if the first `if` was false.
        # We also check `or not suffix` to process files that have no extension, which is common for Linux executables.
        elif suffix in config.BINARY_EXTENSIONS or not suffix:
            # Analyze the binary file to extract its features (imports, exports, etc.).
            binary_features = analyze_binary(file_path)
            # Create a descriptive text string from the most important features.
            feature_text = f"""
            File: {file_path.name}
            Imports: {', '.join(binary_features['imports'][:50])}
            Exports: {', '.join(binary_features['exports'][:20])}
            Suspicious: {', '.join(binary_features['suspicious_characteristics'])}
            """
            # Create an embedding of this descriptive text, not the binary itself.
            embedding = code_embedder.encode(feature_text)
            # Create the `PointStruct` for the binary file.
            point = PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, str(file_path))),
                vector=embedding.tolist(),
                # The payload includes the file path, type, and all the extracted binary features.
                payload={"file": str(file_path), "type": "binary", **binary_features}
            )
            code_points.append(point)
            file_count += 1

    # --- Final Upload ---
    # After the loop finishes, there might be some points left in the `code_points` list.
    # This `if` statement checks if the list is not empty and uploads the final batch.
    if code_points:
        qdrant_client.upsert(collection_name=config.CODE_COLLECTION, points=code_points)
        print(f"Inserted final {len(code_points)} points")
    
    print(f"Ingestion complete! Processed {file_count} files")