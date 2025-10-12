# ingestion/preprocessing.py

# This script contains functions for preprocessing files before they are embedded.
# Preprocessing involves extracting important features, cleaning data, and structuring it.

# --- Imports ---

# `hashlib` is used to create a unique and consistent hash (checksum) of file contents.
import hashlib
# `pathlib.Path` for object-oriented filesystem paths.
from pathlib import Path
# Type hints for clarity.
from typing import List, Dict, Any
# `pefile` is a powerful third-party library for parsing and analyzing Windows Portable Executable (PE) files (like .exe, .dll).
import pefile
# Import our project's configuration.
import config

# --- Feature Extraction from Code ---

def extract_code_features(code: str) -> Dict[str, Any]:
    """Extract semantic features from a code snippet by searching for keywords."""
    # Initialize a dictionary to store the features we find.
    features = {
        "api_calls": [],
        "network_operations": [],
        "crypto_operations": []
    }
    # Convert the code to lowercase for case-insensitive searching.
    code_lower = code.lower()

    # Loop through the list of suspicious API names from our config file.
    for api in config.SUSPICIOUS_APIS:
        # Check if the lowercase API name exists in the lowercase code.
        if api.lower() in code_lower:
            # If it exists, add the original (properly cased) API name to our list.
            features["api_calls"].append(api)

    # We can use a list comprehension for a more concise way to do the same thing.
    # This line builds a list of all patterns `p` from NETWORK_PATTERNS that are found in `code_lower`.
    features["network_operations"] = [p for p in config.NETWORK_PATTERNS if p in code_lower]
    features["crypto_operations"] = [p for p in config.CRYPTO_PATTERNS if p in code_lower]
    
    # Return the dictionary containing the lists of found features.
    return features

# --- Code File Chunking ---

def chunk_code_file(file_path: Path) -> List[Dict[str, Any]]:
    """Chunk a single code file into smaller, more meaningful segments."""
    # Initialize a list to hold the chunks we create.
    chunks = []
    # Use a try...except block to handle potential file reading errors.
    try:
        # Open the file safely. `errors='ignore'` tells Python to discard characters it can't decode, which is useful for weird text files.
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read the entire file content into a string.
            content = f.read()
        
        # Split the content into a list of lines.
        lines = content.split('\n')
        # A temporary list to build up the lines for the current chunk.
        current_chunk_lines = []
        # Keep track of the starting line number for the current chunk.
        chunk_start_line = 0
        
        # Loop through each line with its index.
        for i, line in enumerate(lines):
            # Add the current line to our temporary list.
            current_chunk_lines.append(line)
            
            # This is a simple heuristic to detect the start of a function in various languages.
            is_function_def = any(keyword in line for keyword in ['def ', 'function ', 'sub ', 'PROC', 'void ', 'int main'])
            
            # We decide to end the current chunk if:
            # 1. We found a function definition AND the chunk is already longer than 10 lines, OR
            # 2. The chunk has reached a hard limit of 50 lines.
            if (is_function_def and len(current_chunk_lines) > 10) or len(current_chunk_lines) >= 50:
                # Join the lines back into a single string for the chunk's text.
                chunk_text = '\n'.join(current_chunk_lines)
                # Append a new dictionary representing this chunk to our list.
                chunks.append({
                    "text": chunk_text,
                    "metadata": { # The metadata payload for this chunk.
                        "file": str(file_path), # The original file path.
                        "start_line": chunk_start_line,
                        "end_line": i,
                        "language": file_path.suffix, # The file extension.
                        "size": len(chunk_text),
                        "file_hash": hashlib.sha256(content.encode()).hexdigest(), # A hash of the whole file.
                        **extract_code_features(chunk_text) # Extract features from this specific chunk.
                    }
                })
                # Reset the temporary list and update the start line for the next chunk.
                current_chunk_lines = []
                chunk_start_line = i + 1
        
        # After the loop, there might be remaining lines that didn't form a full chunk.
        # This block ensures that the last part of the file is also saved as a chunk.
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
    # If any error occurs during the process, print it but don't crash.
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    # Return the list of chunk dictionaries.
    return chunks

# --- Text File Chunking ---

def chunk_text_file(file_path: Path) -> List[Dict[str, Any]]:
    """Chunk a single text file into paragraphs."""
    chunks = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split content by double newlines (paragraphs)
        paragraphs = content.split('\n\n')
        
        for i, para in enumerate(paragraphs):
            if not para.strip():
                continue

            chunk_text = para.strip()
            chunks.append({
                "text": chunk_text,
                "metadata": {
                    "file": str(file_path),
                    "paragraph": i,
                    "size": len(chunk_text),
                    "file_hash": hashlib.sha256(content.encode()).hexdigest(),
                }
            })
    except Exception as e:
        print(f"Error processing text file {file_path}: {e}")
    return chunks

# --- Binary File Analysis ---

def analyze_binary(file_path: Path) -> Dict[str, Any]:
    """Extract features from binary files like PE files using the pefile library."""
    # Initialize a dictionary to hold the features.
    features = {
        "imports": [],
        "exports": [],
        "sections": [],
        "suspicious_characteristics": []
    }
    try:
        # Only try to parse the file if it has a common PE file extension.
        if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
            # Create a PE object from the file path.
            pe = pefile.PE(str(file_path))
            
            # `hasattr` checks if an object has a certain attribute. Not all PEs have imports.
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                # Iterate through each imported DLL.
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    # Iterate through each function imported from that DLL.
                    for imp in entry.imports:
                        if imp.name: # The function might not have a name.
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            features["imports"].append(f"{dll_name}::{func_name}")
            
            # Do the same for exported functions.
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        features["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            
            # Iterate through the sections of the PE file (e.g., .text, .data, .rsrc).
            for section in pe.sections:
                # Decode the section name and remove null bytes.
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                # `get_entropy()` calculates the entropy of the section's data. High entropy can indicate packed or encrypted code.
                entropy = section.get_entropy()
                features["sections"].append({
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "entropy": entropy
                })
                # If entropy is very high (a common threshold is > 7.0 out of 8.0), flag it as suspicious.
                if entropy > 7.0:
                    features["suspicious_characteristics"].append(
                        f"High entropy section: {name} ({entropy:.2f})"
                    )
    # `pefile` can raise various errors if the file is corrupted or not a valid PE file.
    except Exception as e:
        print(f"Error analyzing binary {file_path}: {e}")
    
    return features