# utils/helpers.py

# This script contains small, reusable helper functions that can be used anywhere in the project.
# Keeping them here prevents code duplication and makes the main scripts cleaner.

# --- Imports ---

# `re` is Python's standard library for working with regular expressions.
# Regular expressions are powerful mini-languages for pattern matching in strings.
import re
# `pathlib.Path` for working with filesystem paths.
from pathlib import Path
# We need to import the `config` module from the parent directory.
# This import statement is slightly different because of the project structure.
from malware_rag_project import config

# --- Helper Functions ---

def extract_year_from_path(path: Path) -> int:
    """Extract a four-digit year from a file path using a regular expression."""
    # `re.search(pattern, string)` searches the string for the first location where the pattern produces a match.
    # The pattern `r'(19\d{2}|20\d{2})'` means:
    # `r'...'` - Defines a raw string, which is good practice for regex patterns.
    # `(` and `)` - Creates a capturing group. This is the part of the match we want to extract.
    # `19\d{2}` - Matches the number 19 followed by exactly two digits (\d{2}). This finds years in the 1900s.
    # `|` - Acts as an "OR".
    # `20\d{2}` - Matches the number 20 followed by exactly two digits. This finds years in the 2000s.
    year_match = re.search(r'(19\d{2}|20\d{2})', str(path))
    
    # This is a Python conditional expression (also known as a ternary operator).
    # It's a concise one-line if-else statement.
    # `if year_match:` checks if the `re.search` found a match.
    # If it did, `year_match.group(1)` gets the content of the first capturing group (the year), and `int()` converts it to an integer.
    # If no match was found, it returns a default value of 2024.
    return int(year_match.group(1)) if year_match else 2024

def extract_malware_family(file_path: str) -> str:
    """Extract a malware family name from a file path by checking for known family names."""
    # Convert the file path to lowercase for case-insensitive matching.
    file_lower = file_path.lower()
    # Loop through the list of malware family names we defined in our config file.
    for family in config.MALWARE_FAMILIES:
        # Check if the family name string exists anywhere in the lowercase file path string.
        if family in file_lower:
            # If found, return the family name with the first letter capitalized.
            return family.title()
    # If the loop finishes without finding any known family names, return "Unknown".
    return "Unknown"