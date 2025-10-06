# config.py

# This file acts as a central place for all important settings and configurations for the project.
# Using a config file like this makes the code cleaner and easier to maintain,
# because you can change settings here without having to hunt for them inside other scripts.

# --- Embedding Models ---
# These are the names of the pre-trained models we'll use to convert text and code into numerical vectors (embeddings).
# These models are downloaded from Hugging Face, a popular hub for machine learning models.

# This model is specialized for understanding source code. It will be used to create embeddings for code snippets.
CODE_EMBEDDER_MODEL = 'microsoft/codebert-base'
# This is a powerful general-purpose model for understanding English text. We might use it for documentation or reports.
TEXT_EMBEDDER_MODEL = 'BAAI/bge-large-en-v1.5'

# --- Vector Database (Vector DB) ---
# This section configures the database where we will store the vector embeddings.
# We are using Qdrant, which is a database specifically designed for efficient vector similarity search.

# This is the URL for the Qdrant server.
# We comment out the old path-based configuration.
# VECTOR_DB_PATH = "./malware_vectordb"
QDRANT_URL = "http://localhost:6333"
# A "collection" is like a table in a traditional database. This one will store the embeddings for malware CODE.
CODE_COLLECTION = "malware_code"
# This collection would be for storing embeddings of text documents, like analysis reports or malware documentation.
TEXT_COLLECTION = "malware_docs"
# This number specifies the size (dimensionality) of the vectors produced by the CODE_EMBEDDER_MODEL. It must match the model's output.
CODE_EMBEDDING_DIM = 768
# This is the dimensionality for the TEXT_EMBEDDER_MODEL.
TEXT_EMBEDDING_DIM = 1024

# --- Ollama Large Language Model (LLM) ---
# This section configures the connection to the local Large Language Model (LLM) run by Ollama.
# Ollama allows you to run powerful models like Llama 3, Mistral, etc., on your own machine.

# The URL endpoint for the Ollama server's chat API. Our Python code will send requests to this address.
OLLAMA_URL = "http://localhost:11434/api/chat"
# The specific name of the model we want to use from Ollama.
LLM_MODEL = "dolphin3:latest"
# This sets the maximum "context size" for the LLM, which is the amount of text (in tokens) it can consider at once.
# A larger context allows for more detailed prompts and analysis.
LLM_CONTEXT_SIZE = 32768

# --- Analysis Keywords ---
# These lists contain keywords used to identify suspicious patterns in code.

# A list of strings representing Windows API functions that are often used by malware.
# For example, "CreateRemoteThread" can be used to inject code into another process.
SUSPICIOUS_APIS = [
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "OpenProcess", "LoadLibrary", "GetProcAddress", "WinExec",
    "ShellExecute", "URLDownloadToFile", "InternetOpen",
    "CreateService", "RegSetValue", "CryptEncrypt"
]

# A list of strings related to network communication. Malware often uses these to connect to a command-and-control (C2) server.
NETWORK_PATTERNS = ["socket", "connect", "send", "recv", "http", "ftp"]

# A list of strings related to cryptography. Malware uses these for ransomware (encrypting files) or hiding data.
CRYPTO_PATTERNS = ["aes", "rsa", "encrypt", "decrypt", "cipher", "hash", "md5", "sha"]

# --- Ingestion File Types ---
# These define which file extensions the ingestion script should process.
# In Python, a `{}` with items creates a "set". Sets are like lists but are unordered and do not allow duplicate values.
# They are very fast for checking if an item exists (e.g., `if extension in CODE_EXTENSIONS:`).

# A set of file extensions for source code files.
CODE_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.py', '.asm', '.s',
                   '.vbs', '.ps1', '.bat', '.cmd', '.js'}
# A set of file extensions for compiled binary files.
BINARY_EXTENSIONS = {'.exe', '.dll', '.sys', '.so', '.dylib'}
# A set of file extensions for documentation files.
DOC_EXTENSIONS = {'.txt', '.md', '.pdf'}

# --- Malware Families ---
# A list of known malware family names.
# This can be used by helper functions to tag samples based on their file path.
MALWARE_FAMILIES = [
    'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit', 'revil',
    'wannacry', 'notpetya', 'mirai', 'zeus', 'dridex', 'qakbot',
    'cobalt', 'metasploit', 'mimikatz', 'powersploit'
]
