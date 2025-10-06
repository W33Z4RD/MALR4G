# explore_db.py

import config
from qdrant_client import QdrantClient

# 1. Initialize the Qdrant client
# The client connects to the Qdrant server defined in the config.
client = QdrantClient(url=config.QDRANT_URL)

# 2. Get and print collection information
# This is a good way to verify that you are connected to the correct database.
print("--- Available Collections ---")
collections = client.get_collections()
print(collections)
print("\n")

# 3. Get details about a specific collection
# Let's inspect the 'malware_code' collection.
print(f"--- Details for '{config.CODE_COLLECTION}' ---")
code_collection_info = client.get_collection(collection_name=config.CODE_COLLECTION)
print(code_collection_info)
print("\n")

# 4. Retrieve a few points (vectors) from the collection
# This shows you how to access the actual data stored in the database.
# We'll retrieve the first 5 vectors with their payloads.
print(f"--- First 5 points from '{config.CODE_COLLECTION}' ---")
records, _ = client.scroll(
    collection_name=config.CODE_COLLECTION,
    limit=5,
    with_payload=True,  # Include the metadata
    with_vectors=False  # Set to True if you want to see the dense vector
)
for i, record in enumerate(records):
    print(f"Point {i+1}:")
    print(f"  ID: {record.id}")
    print(f"  Payload: {record.payload}")
    print("-" * 10)

print("\nScript finished. You can modify this to explore other collections or query the data.")
