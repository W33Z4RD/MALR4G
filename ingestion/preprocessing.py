# ingestion/preprocessing.py
import hashlib
from pathlib import Path
from typing import List, Dict, Any
import pefile
from malware_rag_project import config

def extract_code_features(code: str) -> Dict[str, Any]:
    """Extract semantic features from a code snippet."""
    features = {
        "api_calls": [],
        "network_operations": [],
        "crypto_operations": []
    }
    code_lower = code.lower()

    for api in config.SUSPICIOUS_APIS:
        if api.lower() in code_lower:
            features["api_calls"].append(api)

    features["network_operations"] = [p for p in config.NETWORK_PATTERNS if p in code_lower]
    features["crypto_operations"] = [p for p in config.CRYPTO_PATTERNS if p in code_lower]
    
    return features

def chunk_code_file(file_path: Path) -> List[Dict[str, Any]]:
    """Chunk a single code file into analyzable segments."""
    chunks = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        current_chunk_lines = []
        chunk_start_line = 0
        
        for i, line in enumerate(lines):
            current_chunk_lines.append(line)
            
            is_function_def = any(keyword in line for keyword in ['def ', 'function ', 'sub ', 'PROC', 'void ', 'int main'])
            
            if (is_function_def and len(current_chunk_lines) > 10) or len(current_chunk_lines) >= 50:
                chunk_text = '\n'.join(current_chunk_lines)
                chunks.append({
                    "text": chunk_text,
                    "metadata": {
                        "file": str(file_path),
                        "start_line": chunk_start_line,
                        "end_line": i,
                        "language": file_path.suffix,
                        "size": len(chunk_text),
                        "file_hash": hashlib.sha256(content.encode()).hexdigest(),
                        **extract_code_features(chunk_text)
                    }
                })
                current_chunk_lines = []
                chunk_start_line = i + 1
        
        if current_chunk_lines:
            chunk_text = '\n'.join(current_chunk_lines)
            chunks.append({
                "text": chunk_text,
                "metadata": {
                    "file": str(file_path),
                    "start_line": chunk_start_line,
                    "end_line": len(lines),
                    "language": file_path.suffix,
                    **extract_code_features(chunk_text)
                }
            })
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return chunks

def analyze_binary(file_path: Path) -> Dict[str, Any]:
    """Extract features from binary files like PE files."""
    features = {
        "imports": [],
        "exports": [],
        "sections": [],
        "suspicious_characteristics": []
    }
    try:
        if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
            pe = pefile.PE(str(file_path))
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            features["imports"].append(f"{dll_name}::{func_name}")
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        features["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                features["sections"].append({
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "entropy": entropy
                })
                if entropy > 7.0:
                    features["suspicious_characteristics"].append(
                        f"High entropy section: {name} ({entropy:.2f})"
                    )
    except Exception as e:
        print(f"Error analyzing binary {file_path}: {e}")
    
    return features
