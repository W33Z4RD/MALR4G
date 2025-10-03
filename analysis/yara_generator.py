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
        rule += f'        $str{i} = "{string}" ascii wide nocase\n'
    for i, api in enumerate(common_apis[:10], 1):
        rule += f'        $api{i} = "{api}" ascii wide\n'
    
    rule += """
    condition:
        uint16(0) == 0x5A4D and (3 of ($str*) or 5 of ($api*))
}}"""
    return rule
