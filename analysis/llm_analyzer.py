# analysis/llm_analyzer.py

# This script is responsible for communicating with the Large Language Model (LLM).
# It has two main jobs:
# 1. Build a detailed prompt (the "context") containing all the information we've gathered.
# 2. Send this prompt to the LLM and return its analysis.

# --- Imports ---

# `requests` is a popular third-party library for making HTTP requests. We use it to talk to the Ollama server's API.
import requests
# `json` is a standard library for working with JSON data. While not used directly here, it's often used with `requests`.
import json
# `typing` is a standard library that helps us add type hints to our code.
# Type hints make the code more readable and help tools catch errors.
# `List` and `Dict` are type hints for lists and dictionaries, respectively.
from typing import List, Dict

# Import our project's configuration settings from the `config.py` file.
import config

# --- Function to Build the LLM Context ---

# This function defines `build_analysis_context` which takes two arguments:
# - `similar_samples`: A list of dictionaries, where each dictionary contains a retrieved malware sample.
# - `features`: A dictionary containing features extracted from the user's suspicious code.
# The `-> str` is a type hint indicating that this function is expected to return a string.
def build_analysis_context(similar_samples: List[Dict], features: Dict) -> str:
    """Build a rich context string for the LLM.

    This is a docstring, which explains what the function does. It's good practice to include them.
    The context is the heart of the Retrieval-Augmented Generation (RAG) process. We are giving the LLM
    "retrieved" information to augment its analysis.
    """
    # Start building the context string. We use Markdown formatting (`#`, `##`, ````) to structure the text.
    context = "# Similar Malware Samples from Database:\n\n"

    # `enumerate` is a handy Python function that gives us both the index (`i`) and the item (`sample`) as we loop through a list.
    # We start the count from 1 instead of the default 0 for more human-readable numbering.
    for i, sample in enumerate(similar_samples, 1):
        # Use an f-string to append information about each similar sample to our context string.
        # `sample['score']:.3f` formats the similarity score to 3 decimal places.
        context += f"## Sample {i} (Similarity: {sample['score']:.3f})\n"
        # `.get('file', 'Unknown')` is a safe way to access a dictionary key. If 'file' doesn't exist, it returns 'Unknown' instead of crashing.
        context += f"Source: {sample['metadata'].get('file', 'Unknown')}\n"
        # We include the first 500 characters of the sample's code as an example.
        context += f"```\n{sample['text'][:500]}...\n```\n\n"
        # Check if the sample's metadata contains a list of API calls.
        if sample['metadata'].get('api_calls'):
            # `', '.join(...)` is a string method that concatenates elements of a list into a single string, separated by a comma and space.
            context += f"Suspicious APIs: {', '.join(sample['metadata']['api_calls'])}\n"
        # Add a newline for spacing.
        context += "\n"

    # Now, add the features extracted from the user's target code to the context.
    context += "## Extracted Features from Target Sample\n\n"
    context += f"**Suspicious API Calls:** {', '.join(features.get('api_calls', ['None detected']))}\n"
    context += f"**Network Operations:** {', '.join(features.get('network_operations', ['None detected']))}\n"
    context += f"**Cryptographic Operations:** {', '.join(features.get('crypto_operations', ['None detected']))}\n"
    
    # Return the final, complete context string.
    return context

# --- Function to Analyze with LLM ---

# This function takes the user's code and the context string, sends them to the LLM, and returns the response.
def analyze_with_llm(user_code: str, context: str) -> str:
    """Analyze code using RAG and an LLM."""
    
    # --- System Prompt ---
    # The system prompt tells the LLM how to behave. It sets the persona and the rules for the conversation.
    # Using a triple-quote `"""` string allows us to write multi-line text easily.
    system_prompt = """You are an elite malware reverse engineer. Your analysis must include:
1. **Executive Summary**: High-level threat assessment.
2. **Behavioral Analysis**: What the code does.
3. **Malicious Techniques**: Specific TTPs (map to MITRE ATT&CK).
4. **Indicators of Compromise**: File hashes, network indicators, etc.
5. **Detection Rules**: YARA rule snippets.
Be thorough and technical."""

    # --- User Prompt ---
    # The user prompt contains the specific query. Here, we combine the user's code with the rich context we built.
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
    
    # --- API Payload ---
    # This dictionary represents the JSON payload we will send to the Ollama API.
    payload = {
        "model": config.LLM_MODEL, # The model to use, from our config file.
        "messages": messages, # The conversation history.
        "stream": False, # We set stream to False to get the full response at once, not in chunks.
        "options": { # Model-specific options.
            "temperature": 0.3, # Lower temperature = more deterministic, less creative responses.
            "num_ctx": config.LLM_CONTEXT_SIZE # Set the context window size.
        }
    }
    
    # --- API Request and Error Handling ---
    # A `try...except` block is used to gracefully handle potential network errors.
    try:
        # `requests.post` sends an HTTP POST request to the specified URL.
        # `json=payload` automatically converts our Python dictionary to a JSON string.
        # `timeout=300` will cause the request to fail if it takes longer than 300 seconds.
        response = requests.post(config.OLLAMA_URL, json=payload, timeout=300)
        # `raise_for_status()` will raise an error if the HTTP response code indicates a failure (e.g., 404 Not Found, 500 Server Error).
        response.raise_for_status()
        # If the request was successful, we parse the JSON response and return the content of the message.
        return response.json()['message']['content']
    # This `except` block will catch any error raised by the `requests` library (e.g., network down, timeout).
    except requests.RequestException as e:
        # If an error occurs, we return a formatted error message string.
        return f"Error communicating with LLM: {e}"