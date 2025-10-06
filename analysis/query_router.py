# analysis/query_router.py

# This script provides a simple but effective way to categorize a piece of code
# based on keywords. This initial classification can help focus the subsequent analysis.

# --- The Router Function ---

# Defines a function named `route_query` that takes one string argument `code`
# and is type-hinted to return a string.
def route_query(code: str) -> str:
    """Intelligently route queries to specialized indexes based on keywords.

    This is a simple heuristic-based router. It checks for the presence of certain
    keywords to make an educated guess about the malware's category.
    """
    # Convert the input code to lowercase to make the keyword search case-insensitive.
    # For example, it will find "Encrypt" as well as "encrypt".
    code_lower = code.lower()
    
    # --- Keyword Checking Logic ---
    # The following `if` statements check for keywords associated with different malware types.

    # `any(...)` is a built-in Python function that returns True if any item in an iterable is true.
    # `(term in code_lower for term in [...])` is a generator expression. It's a memory-efficient
    # way to check each term in the list against the lowercase code.
    # If any of the ransomware-related terms are found, the function immediately returns "ransomware".
    if any(term in code_lower for term in ['encrypt', 'ransom', 'bitcoin', '.locked']):
        return "ransomware"
    
    # If the first `if` was false, Python moves to the next one.
    # This checks for terms related to Remote Access Trojans (RATs) and spyware.
    if any(term in code_lower for term in ['keylog', 'screenshot', 'clipboard', 'rat']):
        return "rats"

    # Checks for terms related to rootkits, which operate at a low level of the operating system.
    if any(term in code_lower for term in ['kernel', 'driver', 'rootkit', 'ssdt']):
        return "rootkits"

    # Checks for terms related to cryptocurrency miners, which steal CPU resources.
    if any(term in code_lower for term in ['mining', 'xmrig', 'monero', 'stratum']):
        return "cryptominers"

    # Checks for terms related to botnets, which are networks of infected machines.
    if any(term in code_lower for term in ['bot', 'ddos', 'irc', 'command']):
        return "botnets"

    # Checks for terms related to infostealers, which steal passwords, cookies, and other credentials.
    if any(term in code_lower for term in ['password', 'cookie', 'credential', 'wallet']):
        return "infostealers"
    
    # If none of the specific categories matched, the function returns a default "general" category.
    return "general"