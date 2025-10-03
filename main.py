# main.py
import argparse
from sentence_transformers import SentenceTransformer

from malware_rag_project import config
from malware_rag_project.ingestion.vector_db import VectorDB
from malware_rag_project.ingestion.data_loader import ingest_vx_repository
from malware_rag_project.retrieval.search import MalwareSearch
from malware_rag_project.analysis.orchestrator import ComprehensiveMalwareAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Malware RAG Analysis System")
    parser.add_argument('--ingest', action='store_true', help="Run the ingestion pipeline.")
    parser.add_argument('--repo-path', type=str, default="/mnt/data/vx-underground", help="Path to the VX-Underground repository.")
    parser.add_argument('--max-files', type=int, default=None, help="Maximum number of files to ingest.")
    parser.add_argument('--analyze', type=str, help="Path to a file containing suspicious code to analyze.")
    
    args = parser.parse_args()

    # Initialize core components
    print("[*] Initializing components...")
    db = VectorDB(path=config.VECTOR_DB_PATH)
    
    if args.ingest:
        print("[*] Starting ingestion process...")
        ingest_vx_repository(
            repo_path=args.repo_path,
            db=db,
            max_files=args.max_files
        )
        print("[+] Ingestion complete.")

    elif args.analyze:
        print(f"[*] Analyzing file: {args.analyze}")
        try:
            with open(args.analyze, 'r', encoding='utf-8') as f:
                suspicious_code = f.read()
        except FileNotFoundError:
            print(f"Error: Analysis file not found at {args.analyze}")
            return
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        # Initialize analysis components
        code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
        search_engine = MalwareSearch(client=db.get_client(), code_embedder=code_embedder)
        analyzer = ComprehensiveMalwareAnalyzer(search_engine=search_engine)

        # Run analysis
        report = analyzer.full_analysis_report(suspicious_code)

        print("\n" + "="*60)
        print("MALWARE ANALYSIS REPORT")
        print("="*60 + "\n")
        print(report)

    else:
        print("No action specified. Use --ingest to build the database or --analyze <file_path> to analyze code.")

if __name__ == "__main__":
    main()
