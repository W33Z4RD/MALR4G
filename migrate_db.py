# migrate_db.py

import os
from qdrant_client import QdrantClient, models
from tqdm import tqdm
import config

def migrate_database():
    """
    Migrates data from a local file-based Qdrant DB to a Qdrant server instance
    by scrolling through all points and upserting them to the new instance.
    """
    COLLECTION_NAME = config.CODE_COLLECTION
    OLD_DB_PATH = "./malware_vectordb"
    BATCH_SIZE = 256

    # --- Step 1: Connect to both databases ---
    print("[*] Connecting to databases...")
    try:
        local_client = QdrantClient(path=OLD_DB_PATH)
        docker_client = QdrantClient(url=config.QDRANT_URL)
        docker_client.get_collections()
    except Exception as e:
        print(f"[-] Error connecting to Qdrant instances: {e}")
        return

    print("[+] Connections successful.")

    # --- Step 2: Recreate collection on the destination server ---
    try:
        print(f"[*] Setting up collection '{COLLECTION_NAME}' on the destination server...")
        # Define the collection configuration explicitly, mirroring vector_db.py
        docker_client.recreate_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=models.VectorParams(
                size=config.CODE_EMBEDDING_DIM,
                distance=models.Distance.COSINE
            ),
            sparse_vectors_config={
                "text": models.SparseVectorParams(
                    index=models.SparseIndexParams(
                        on_disk=False,
                    )
                )
            }
        )
    except Exception as e:
        print(f"[-] Failed to recreate collection on destination: {e}")
        return

    # --- Step 3: Scroll through the old DB and upsert to the new one ---
    print("[*] Starting data migration...")
    try:
        total_points = local_client.count(collection_name=COLLECTION_NAME, exact=True).count
        next_page_offset = None
        
        with tqdm(total=total_points, desc="Migrating Points") as pbar:
            while True:
                points, next_page_offset = local_client.scroll(
                    collection_name=COLLECTION_NAME,
                    limit=BATCH_SIZE,
                    offset=next_page_offset,
                    with_payload=True,
                    with_vectors=True,
                )
                
                if not points:
                    break

                # The points from a scroll are Record objects, we need to convert them
                # back to PointStructs for the upsert operation.
                points_to_upsert = [
                    models.PointStruct(
                        id=point.id,
                        vector=point.vector,
                        payload=point.payload
                    ) for point in points
                ]

                docker_client.upsert(
                    collection_name=COLLECTION_NAME,
                    points=points_to_upsert,
                    wait=False # Use wait=False for better performance
                )
                pbar.update(len(points))

                if next_page_offset is None:
                    break
        
        # Final wait to ensure all writes are committed
        docker_client.count(collection_name=COLLECTION_NAME, exact=False) # This forces a wait

    except Exception as e:
        print(f"[-] An error occurred during migration: {e}")
        return

    # --- Step 4: Verification ---
    print("\n[*] Verifying data in the new database...")
    try:
        count_local = local_client.count(collection_name=COLLECTION_NAME, exact=True).count
        count_docker = docker_client.count(collection_name=COLLECTION_NAME, exact=True).count
        
        print(f"[+] Point count in old (local) DB: {count_local}")
        print(f"[+] Point count in new (Docker) DB: {count_docker}")
        
        if count_local == count_docker:
            print("\n[+] Migration successful! The number of points matches.")
        else:
            print("[-] Warning: Mismatch in point counts. Please check the logs.")
            
    except Exception as e:
        print(f"[-] Failed to verify counts: {e}")

if __name__ == "__main__":
    migrate_database()