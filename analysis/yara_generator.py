# analysis/yara_generator.py

# This script is responsible for automatically generating YARA rules.
# YARA is a tool used to identify and classify malware samples. A YARA rule is a set of
# strings and conditions that define a pattern to look for in files.
# This script creates a rule by finding common patterns in a group of similar malware samples.

# --- Imports ---

# Import `List` and `Dict` for type hinting.
from typing import List, Dict
# `collections.Counter` is a specialized dictionary subclass for counting hashable objects.
# It's perfect for counting how many times each API call or string appears.
from collections import Counter
# `datetime` is a standard library for working with dates and times.
import datetime

# --- The YARA Generation Function ---

def generate_yara_rule(malware_family: str, samples: List[Dict]) -> str:
    """Auto-generate a YARA rule from a cluster of malware samples."""
    
    # --- Aggregate Indicators ---
    # First, we collect all the indicators (API calls and suspicious strings)
    # from the metadata of all the provided samples.

    # Initialize empty lists to hold all the indicators.
    all_apis = []
    all_strings = []
    
    # Loop through each sample dictionary in the `samples` list.
    for sample in samples:
        # Get the metadata dictionary from the current sample.
        metadata = sample['metadata']
        # `extend` adds all items from one list to another. Here, we add the API calls
        # from the current sample to our `all_apis` list.
        # `.get('api_calls', [])` safely gets the list, returning an empty list `[]` if it doesn't exist.
        all_apis.extend(metadata.get('api_calls', []))
        all_strings.extend(metadata.get('suspicious_strings', []))

    # --- Find Common Indicators ---
    # Now we count the occurrences of each indicator to find the most common ones.

    # Create Counter objects to count the frequency of each API and string.
    api_counter = Counter(all_apis)
    string_counter = Counter(all_strings)
    
    # Determine a threshold for how common an indicator must be to be included in the rule.
    # We set it to 50% of the number of samples, with a minimum of 1.
    # `len(samples)` gets the number of items in the list.
    # `max(a, b)` returns the larger of the two numbers.
    threshold = max(1, len(samples) * 0.5)

    # These are list comprehensions, a concise way to create lists.
    # The first one creates a list of APIs that appeared at or above the threshold.
    # `.items()` gives us key-value pairs (the api and its count).
    common_apis = [api for api, count in api_counter.items() if count >= threshold]
    # This one does the same for suspicious strings.
    common_strings = [s for s, count in string_counter.items() if count >= threshold]

    # --- Build the YARA Rule String ---
    # Now we assemble the final YARA rule as a multi-line string.

    # Create a unique name for the rule, including the malware family and a short hash.
    # `.replace(' ', '_')` makes the family name safe for a rule name.
    rule_name = f"{malware_family.replace(' ', '_')}_{hash(malware_family) & 0xFFFF:04x}"
    
    # Start building the rule string using an f-string and triple quotes.
    rule = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated rule for {malware_family}"
        author = "RAG Malware Analysis System"
        date = "{datetime.datetime.now().strftime('%Y-%m-%d')}" # Format the current date as YYYY-MM-DD.
        sample_count = "{len(samples)}"
    strings:
"""
    # Loop through the first 10 common strings to add them to the rule.
    # `[:10]` is list slicing, it gets the first 10 items.
    for i, string in enumerate(common_strings[:10], 1):
        # `$str{i}` is the YARA syntax for a string variable.
        # `ascii wide nocase` are YARA keywords telling it how to search for the string.
        rule += f'        $str{i} = "{string}" ascii wide nocase\n'
    
    # Do the same for the first 10 common API calls.
    for i, api in enumerate(common_apis[:10], 1):
        rule += f'        $api{i} = "{api}" ascii wide\n'
    
    # --- Define the Rule Condition ---
    # The condition is the logic that determines if the rule matches.
    rule += """
    condition:
        // This first part checks if the file is a Windows PE file (like .exe or .dll)
        // by looking for the "MZ" magic bytes at the beginning of the file.
        uint16(0) == 0x5A4D and 
        // This part is the main logic. The rule matches if the file is a PE file AND
        // (it contains at least 3 of the suspicious strings OR at least 5 of the API calls).
        (3 of ($str*) or 5 of ($api*))
}}"""
    
    # Return the complete YARA rule as a single string.
    return rule