# analysis/query_router.py

def route_query(code: str) -> str:
    """Intelligently route queries to specialized indexes based on keywords."""
    code_lower = code.lower()
    
    if any(term in code_lower for term in ['encrypt', 'ransom', 'bitcoin', '.locked']):
        return "ransomware"
    if any(term in code_lower for term in ['keylog', 'screenshot', 'clipboard', 'rat']):
        return "rats"
    if any(term in code_lower for term in ['kernel', 'driver', 'rootkit', 'ssdt']):
        return "rootkits"
    if any(term in code_lower for term in ['mining', 'xmrig', 'monero', 'stratum']):
        return "cryptominers"
    if any(term in code_lower for term in ['bot', 'ddos', 'irc', 'command']):
        return "botnets"
    if any(term in code_lower for term in ['password', 'cookie', 'credential', 'wallet']):
        return "infostealers"
    
    return "general"
