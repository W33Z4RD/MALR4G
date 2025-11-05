# analysis/yara_generator.py
from typing import List, Dict
from collections import Counter
import datetime

def generate_yara_rule(malware_family: str, samples: List[Dict]) -> str:
    """Auto-generate a YARA rule from a cluster of malware samples."""
    
    all_apis = []
    all_strings = []
    
    for sample in samples:
        metadata = sample['metadata']
        all_apis.extend(metadata.get('api_calls', []))
        all_strings.extend(metadata.get('suspicious_strings', []))

    api_counter = Counter(all_apis)
    string_counter = Counter(all_strings)
    
    # Determine a threshold for how common an indicator must be to be included in the rule.
    # We set it to 50% of the number of samples, with a minimum of 1.
    threshold = max(1, len(samples) * 0.5)

    common_apis = [api for api, count in api_counter.items() if count >= threshold]
    common_strings = [s for s, count in string_counter.items() if count >= threshold]

    rule_name = f"{malware_family.replace(' ', '_')}_{hash(malware_family) & 0xFFFF:04x}"
    
    rule = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated rule for {malware_family}"
        author = "RAG Malware Analysis System"
        date = "{datetime.datetime.now().strftime('%Y-%m-%d')}"
        sample_count = "{len(samples)}"
    strings:
"""
    for i, string in enumerate(common_strings[:10], 1):
        # `$str{i}` is the YARA syntax for a string variable.
        # `ascii wide nocase` are YARA keywords telling it how to search for the string.
        rule += f'        $str{i} = "{string}" ascii wide nocase\n'
    
    for i, api in enumerate(common_apis[:10], 1):
        rule += f'        $api{i} = "{api}" ascii wide\n'
    
    rule += """
    condition:
        // This first part checks if the file is a Windows PE file (like .exe or .dll)
        // by looking for the "MZ" magic bytes at the beginning of the file.
        uint16(0) == 0x5A4D and 
        // This part is the main logic. The rule matches if the file is a PE file AND
        // (it contains at least 3 of the suspicious strings OR at least 5 of the API calls).
        (3 of ($str*) or 5 of ($api*))
}}"""
    
    return rule
