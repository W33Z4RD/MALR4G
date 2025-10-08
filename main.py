# main.py

# This is the main entry point for the application.
# It's the script you run from the command line to either ingest data or perform an analysis.

# --- Imports ---
# We start by importing the necessary libraries and modules.

# `argparse` is a standard Python library for parsing command-line arguments.
# This lets us create a command-line interface (CLI) for our script (e.g., --ingest, --analyze).
import argparse

# `SentenceTransformer` is the main class from the sentence-transformers library.
# We use it to load the pre-trained models that turn code/text into vector embeddings.
from sentence_transformers import SentenceTransformer

# `import config` brings in all the variables we defined in our config.py file.
# This is how we access settings like model names and database paths.
import config

# Here we import our own custom classes and functions from other files in the project.
# This is good practice for organizing a larger project into logical parts.
from ingestion.vector_db import VectorDB # Manages the vector database connection.
from ingestion.data_loader import ingest_vx_repository # Handles the data ingestion process.
from retrieval.search import MalwareSearch # Performs the search for similar malware.
from analysis.orchestrator import ComprehensiveMalwareAnalyzer # Orchestrates the analysis workflow.
from analysis.redteam_chat import redteam_chat_session # The new red team chat mode.

# --- Main Function ---
# The `main` function contains the primary logic of the script.
def main():
    # --- Command-Line Argument Parsing ---
    # Here, we set up the command-line arguments that the user can provide.

    # Create a parser object. The description is shown when the user runs the script with `--help`.
    parser = argparse.ArgumentParser(description="Malware RAG Analysis and Red Team System")

    # Add the `--mode` argument to switch between application functionalities.
    parser.add_argument('--mode', type=str, default='analyze', choices=['ingest', 'analyze', 'redteam'], 
                        help="The mode to run the application in. 'ingest', 'analyze', or 'redteam'.")

    # Arguments for 'ingest' mode
    parser.add_argument('--repo-path', type=str, default="/mnt/data/vx-underground", 
                        help="Path to the VX-Underground repository for ingestion.")
    parser.add_argument('--max-files', type=int, default=None, 
                        help="Maximum number of files to ingest.")

    # Argument for 'analyze' mode
    parser.add_argument('--file', type=str, help="Path to a file containing suspicious code to analyze.")
    
    # This line actually parses the arguments provided by the user when they ran the script.
    # The results are stored in the `args` object.
    args = parser.parse_args()

    # --- Main Logic Branching ---
    # The script now decides what to do based on the user's selected mode.

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

# --- Script Execution Guard ---
if __name__ == "__main__":
    main()
