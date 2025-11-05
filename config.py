# config.py

CODE_EMBEDDER_MODEL = 'microsoft/codebert-base'
TEXT_EMBEDDER_MODEL = 'BAAI/bge-large-en-v1.5'

QDRANT_URL = "http://localhost:6333"
CODE_COLLECTION = "malware_code"
TEXT_COLLECTION = "malware_docs"
# This number specifies the size (dimensionality) of the vectors produced by the CODE_EMBEDDER_MODEL. It must match the model's output.
CODE_EMBEDDING_DIM = 768
TEXT_EMBEDDING_DIM = 1024

OLLAMA_URL = "http://localhost:11434/api/chat"
LLM_MODEL = "dolphin3:latest"
# This sets the maximum "context size" for the LLM, which is the amount of text (in tokens) it can consider at once.
# A larger context allows for more detailed prompts and analysis.
LLM_CONTEXT_SIZE = 8192

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

CODE_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.py', '.asm', '.s',
                   '.vbs', '.ps1', '.bat', '.cmd', '.js'}
BINARY_EXTENSIONS = {'.exe', '.dll', '.sys', '.so', '.dylib'}
DOC_EXTENSIONS = {'.txt', '.md', '.pdf'}

# A list of known malware family names.
# This can be used by helper functions to tag samples based on their file path.
MALWARE_FAMILIES = [
    'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit', 'revil',
    'wannacry', 'notpetya', 'mirai', 'zeus', 'dridex', 'qakbot',
    'cobalt', 'metasploit', 'mimikatz', 'powersploit'
]