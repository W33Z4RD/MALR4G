# analysis/llm_analyzer.py
import requests
import json
from typing import List, Dict

import config

def build_analysis_context(similar_samples: List[Dict], features: Dict) -> str:
    """Build a rich context string for the LLM.

    The context is the heart of the Retrieval-Augmented Generation (RAG) process. We are giving the LLM
    "retrieved" information to augment its analysis.
    """
    context = "# Similar Malware Samples from Database:\n\n"

    for i, sample in enumerate(similar_samples, 1):
        context += f"## Sample {i} (Similarity: {sample['score']:.3f})\n"
        context += f"Source: {sample['metadata'].get('file', 'Unknown')}\n"
        context += f"```\n{sample['text'][:500]}...\n```\n\n"
        if sample['metadata'].get('api_calls'):
            context += f"Suspicious APIs: {', '.join(sample['metadata']['api_calls'])}\n"
        context += "\n"

    context += "## Extracted Features from Target Sample\n\n"
    context += f"**Suspicious API Calls:** {', '.join(features.get('api_calls', ['None detected']))}\n"
    context += f"**Network Operations:** {', '.join(features.get('network_operations', ['None detected']))}\n"
    context += f"**Cryptographic Operations:** {', '.join(features.get('crypto_operations', ['None detected']))}\n"
    
    return context

def analyze_with_llm(user_code: str, context: str) -> str:
    """Analyze code using RAG and an LLM."""
    
    system_prompt = """You are an elite malware reverse engineer. Your analysis must include:
1. **Executive Summary**: High-level threat assessment.
2. **Behavioral Analysis**: What the code does.
3. **Malicious Techniques**: Specific TTPs (map to MITRE ATT&CK).
4. **Indicators of Compromise**: File hashes, network indicators, etc.
5. **Detection Rules**: YARA rule snippets.
Be thorough and technical."""

    user_prompt = f"""# Code to Analyze:
```
{user_code}
```

{context}

Provide a comprehensive malware analysis based on the code and the similar samples from our database."""

    # The Ollama API expects the conversation as a list of message dictionaries.
    # Each dictionary has a "role" (system, user, or assistant) and "content".
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]
    
    payload = {
        "model": config.LLM_MODEL,
        "messages": messages,
        "stream": False, # We set stream to False to get the full response at once, not in chunks.
        "options": {
            "temperature": 0.3, # Lower temperature = more deterministic, less creative responses.
            "num_ctx": config.LLM_CONTEXT_SIZE
        }
    }
    
    try:
        response = requests.post(config.OLLAMA_URL, json=payload, timeout=3000)
        response.raise_for_status()
        return response.json()['message']['content']
    except requests.RequestException as e:
        return f"Error communicating with LLM: {e}"
