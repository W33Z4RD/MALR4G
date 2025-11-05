# utils/helpers.py
import re
from pathlib import Path
from malware_rag_project import config

def extract_year_from_path(path: Path) -> int:
    """Extract a four-digit year from a file path using a regular expression."""
    year_match = re.search(r'(19\d{2}|20\d{2})', str(path))
    return int(year_match.group(1)) if year_match else 2024

def extract_malware_family(file_path: str) -> str:
    """Extract a malware family name from a file path by checking for known family names."""
    file_lower = file_path.lower()
    for family in config.MALWARE_FAMILIES:
        if family in file_lower:
            return family.title()
    return "Unknown"
