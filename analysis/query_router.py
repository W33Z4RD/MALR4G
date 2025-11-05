# analysis/query_router.py

def route_query(code: str) -> str:
    """Intelligently route queries to specialized indexes based on keywords.

    This is a simple heuristic-based router. It checks for the presence of certain
    keywords to make an educated guess about the malware's category.
    """
    code_lower = code.lower()
    
    if any(term in code_lower for term in ['encrypt', 'ransom', 'bitcoin', '.locked']):
        return "ransomware"
    
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
    
    return "general"