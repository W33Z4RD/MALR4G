# config.py

# Embedding Models
CODE_EMBEDDER_MODEL = 'microsoft/codebert-base'
TEXT_EMBEDDER_MODEL = 'BAAI/bge-large-en-v1.5'

# Vector DB
VECTOR_DB_PATH = "./malware_vectordb"
CODE_COLLECTION = "malware_code"
TEXT_COLLECTION = "malware_docs"
CODE_EMBEDDING_DIM = 768
TEXT_EMBEDDING_DIM = 1024

# Ollama LLM
OLLAMA_URL = "http://localhost:11434/api/chat"
LLM_MODEL = "dolphin3:8b"
LLM_CONTEXT_SIZE = 32768

# Analysis
SUSPICIOUS_APIS = [
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "OpenProcess", "LoadLibrary", "GetProcAddress", "WinExec",
    "ShellExecute", "URLDownloadToFile", "InternetOpen",
    "CreateService", "RegSetValue", "CryptEncrypt"
]

NETWORK_PATTERNS = ["socket", "connect", "send", "recv", "http", "ftp"]
CRYPTO_PATTERNS = ["aes", "rsa", "encrypt", "decrypt", "cipher", "hash", "md5", "sha"]

# Ingestion
CODE_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.py', '.asm', '.s',
                   '.vbs', '.ps1', '.bat', '.cmd', '.js'}
BINARY_EXTENSIONS = {'.exe', '.dll', '.sys', '.so', '.dylib'}
DOC_EXTENSIONS = {'.txt', '.md', '.pdf'}

# Malware Families for path extraction
MALWARE_FAMILIES = [
    'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit', 'revil',
    'wannacry', 'notpetya', 'mirai', 'zeus', 'dridex', 'qakbot',
    'cobalt', 'metasploit', 'mimikatz', 'powersploit'
]
