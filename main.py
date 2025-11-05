# main.py
import argparse
from sentence_transformers import SentenceTransformer
import config
from ingestion.vector_db import VectorDB
from ingestion.data_loader import ingest_vx_repository
from retrieval.search import MalwareSearch
from analysis.orchestrator import ComprehensiveMalwareAnalyzer
from analysis.redteam_chat import redteam_chat_session

def main():
    parser = argparse.ArgumentParser(description="Malware RAG Analysis and Red Team System")

    parser.add_argument('--mode', type=str, default='analyze', choices=['ingest', 'analyze', 'redteam'], 
                        help="The mode to run the application in. 'ingest', 'analyze', or 'redteam'.")

    parser.add_argument('--repo-path', type=str, default="/mnt/data/vx-underground", 
                        help="Path to the VX-Underground repository for ingestion.")
    parser.add_argument('--max-files', type=int, default=None, 
                        help="Maximum number of files to ingest.")

    parser.add_argument('--file', type=str, help="Path to a file containing suspicious code to analyze.")
    
    args = parser.parse_args()

    if args.mode == 'ingest':
        print("[*] Starting ingestion process...")
        db = VectorDB()
        ingest_vx_repository(
            repo_path=args.repo_path,
            db=db,
            max_files=args.max_files
        )
        print("[+] Ingestion complete.")

    elif args.mode == 'analyze':
        if not args.file:
            print("Error: The '--file' argument is required for 'analyze' mode.")
            return

        print(f"[*] Analyzing file: {args.file}")
        
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                suspicious_code = f.read()
        except FileNotFoundError:
            print(f"Error: Analysis file not found at {args.file}")
            return
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        print("[*] Initializing analysis components...")
        db = VectorDB()
        code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
        search_engine = MalwareSearch(client=db.get_client(), code_embedder=code_embedder)
        analyzer = ComprehensiveMalwareAnalyzer(search_engine=search_engine)

        report = analyzer.full_analysis_report(suspicious_code)

        print("\n" + "="*60)
        print("MALWARE ANALYSIS REPORT")
        print("="*60 + "\n")
        print(report)

    elif args.mode == 'redteam':
        redteam_chat_session()

    else:
        print("Invalid mode specified. Use --help for options.")

if __name__ == "__main__":
    main()
