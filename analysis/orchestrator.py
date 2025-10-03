# analysis/orchestrator.py
import numpy as np
from pathlib import Path
from typing import List, Dict

from .. import config
from ..retrieval.search import MalwareSearch
from ..ingestion.preprocessing import extract_code_features
from . import query_router, yara_generator, llm_analyzer

class ComprehensiveMalwareAnalyzer:
    """Orchestrates the full malware analysis workflow."""

    def __init__(self, search_engine: MalwareSearch):
        self.search_engine = search_engine

    def full_analysis_report(self, suspicious_code: str, include_yara: bool = True) -> str:
        """Generate a comprehensive analysis report."""
        print("[*] Starting comprehensive malware analysis...")

        malware_type = query_router.route_query(suspicious_code)
        print(f"[+] Detected malware type: {malware_type}")

        print("[*] Searching for similar malware samples...")
        similar_samples = self.search_engine.hybrid_search(suspicious_code, top_k=10)

        print("[*] Extracting indicators of compromise...")
        features = extract_code_features(suspicious_code)

        yara_rule = ""
        if include_yara and len(similar_samples) >= 2:
            print("[*] Generating YARA detection rule...")
            yara_rule = yara_generator.generate_yara_rule(malware_type, similar_samples)

        print("[*] Building context for LLM...")
        context = llm_analyzer.build_analysis_context(similar_samples, features)
        
        # Add YARA rule to context if generated
        if yara_rule:
            context += f"\n## Auto-Generated YARA Rule\n```yara\n{yara_rule}\n```"

        print("[*] Generating detailed analysis with LLM...")
        analysis = llm_analyzer.analyze_with_llm(suspicious_code, context)

        return analysis

    def batch_analysis(self, code_samples: List[str], output_dir: str = "./analysis_reports"):
        """Analyze multiple samples and save reports."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        for i, code in enumerate(code_samples, 1):
            print(f"\n{'='*60}\nAnalyzing sample {i}/{len(code_samples)}\n{'='*60}")
            try:
                report = self.full_analysis_report(code)
                report_file = output_path / f"report_{i}_{hash(code) & 0xFFFF:04x}.md"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Malware Analysis Report - Sample {i}\n\n")
                    f.write(report)
                print(f"[+] Report saved to: {report_file}")
            except Exception as e:
                print(f"[!] Error analyzing sample {i}: {e}")

