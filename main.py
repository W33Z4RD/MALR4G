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

# --- Main Function ---
# The `main` function contains the primary logic of the script.
def main():
    # --- Command-Line Argument Parsing ---
    # Here, we set up the command-line arguments that the user can provide.

    # Create a parser object. The description is shown when the user runs the script with `--help`.
    parser = argparse.ArgumentParser(description="Malware RAG Analysis System")

    # Add the `--ingest` argument. `action='store_true'` makes it a flag; if it's present, `args.ingest` will be True.
    parser.add_argument('--ingest', action='store_true', help="Run the ingestion pipeline.")

    # Add the `--repo-path` argument. `type=str` means it expects a string value.
    # `default` provides a value if the user doesn't specify one.
    parser.add_argument('--repo-path', type=str, default="/mnt/data/vx-underground", help="Path to the VX-Underground repository.")

    # Add the `--max-files` argument. `type=int` expects an integer.
    parser.add_argument('--max-files', type=int, default=None, help="Maximum number of files to ingest.")

    # Add the `--analyze` argument. It expects a string (the file path to analyze).
    parser.add_argument('--analyze', type=str, help="Path to a file containing suspicious code to analyze.")
    
    # This line actually parses the arguments provided by the user when they ran the script.
    # The results are stored in the `args` object.
    args = parser.parse_args()

    # --- Component Initialization ---
    # These components are needed for both ingestion and analysis.

    # The `print()` function displays text in the console. It's useful for showing progress and status.
    print("[*] Initializing components...")
    db = VectorDB()
    
    # --- Main Logic Branching ---
    # The script now decides what to do based on the user's command-line arguments.

    # `if/elif/else` is a standard way to control the flow of a program in Python.
    # This block checks if the `--ingest` flag was used.
    if args.ingest:
        print("[*] Starting ingestion process...")
        # Call the ingestion function with the necessary arguments from the command line and the db object.
        ingest_vx_repository(
            repo_path=args.repo_path,
            db=db,
            max_files=args.max_files
        )
        print("[+] Ingestion complete.")

    # `elif` means "else if". This block runs if `--ingest` was NOT used, but `--analyze` WAS.
    elif args.analyze:
        # An f-string (formatted string) is a modern way to embed variables directly inside a string.
        print(f"[*] Analyzing file: {args.analyze}")
        
        # `try...except` is Python's way of handling errors gracefully.
        # The code inside the `try` block is executed, but if an error occurs, the program jumps to the `except` block instead of crashing.
        try:
            # `with open(...)` is the recommended way to work with files in Python.
            # It automatically handles closing the file, even if errors occur.
            # 'r' means read mode, and `encoding='utf-8'` is important for handling a wide range of text characters.
            with open(args.analyze, 'r', encoding='utf-8') as f:
                # `.read()` reads the entire content of the file into the `suspicious_code` variable.
                suspicious_code = f.read()
        # This block catches the specific error that occurs if the file doesn't exist.
        except FileNotFoundError:
            print(f"Error: Analysis file not found at {args.analyze}")
            return # `return` exits the function immediately.
        # This block catches any other exceptions that might occur during file reading.
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        # --- Analysis Component Initialization ---
        # These components are only needed for the analysis workflow, so we initialize them here.
        
        # Load the code embedding model from the name specified in our config file.
        code_embedder = SentenceTransformer(config.CODE_EMBEDDER_MODEL)
        # Create an instance of our MalwareSearch class.
        # It needs the database client and the embedding model to work.
        search_engine = MalwareSearch(client=db.get_client(), code_embedder=code_embedder)
        # Create an instance of our main analyzer class, giving it the search engine.
        analyzer = ComprehensiveMalwareAnalyzer(search_engine=search_engine)

        # --- Run Analysis ---
        # Call the main analysis method on the analyzer object, passing in the suspicious code.
        report = analyzer.full_analysis_report(suspicious_code)

        # --- Print Report ---
        # The following lines print a formatted header for the report.
        # `"\n"` is a newline character. `"="*60` creates a string of 60 equal signs.
        print("\n" + "="*60)
        print("MALWARE ANALYSIS REPORT")
        print("="*60 + "\n")
        # Finally, print the report generated by the LLM.
        print(report)

    # The `else` block runs if neither `--ingest` nor `--analyze` were provided.
    else:
        print("No action specified. Use --ingest to build the database or --analyze <file_path> to analyze code.")

# --- Script Execution Guard ---
# This is a very common and important pattern in Python.
# `__name__` is a special variable that Python sets.
# When you run a file directly (e.g., `python main.py`), Python sets `__name__` to `"__main__"`.
# If the file is imported by another script, `__name__` is set to the module's name (e.g., `"main"`).
# This `if` statement ensures that the `main()` function is called only when the script is executed directly.
if __name__ == "__main__":
    main()