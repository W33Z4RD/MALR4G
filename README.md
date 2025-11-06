# Malware RAG Analysis and Red Team System

This project is a sophisticated malware analysis system that leverages Retrieval-Augmented Generation (RAG) to provide deep, context-aware analysis of suspicious code. It also includes a "Red Team" mode for interactive, adversarial brainstorming with an LLM.

## Key Features

*   **RAG-Powered Malware Analysis:** Enriches LLM analysis by providing context from a database of known malware samples.
*   **Comprehensive Reporting:** Generates in-depth reports including behavioral analysis, MITRE ATT&CK mapping, and IOCs.
*   **Interactive Red Team Mode:** An interactive chat mode that allows for adversarial brainstorming of novel offensive security techniques with an LLM.
*   **Dockerized Vector DB:** Uses Qdrant running in a Docker container for robust and persistent vector storage.
*   **Modular Architecture:** The system is divided into distinct modules for ingestion, retrieval, and analysis.

## Project Structure

The project is organized into the following directories:

*   `analysis`: Contains the logic for analyzing suspicious code and the new Red Team chat mode.
*   `ingestion`: Handles the ingestion of malware samples into the vector database.
*   `retrieval`: Implements the search functionality for finding similar malware samples.
*   `utils`: Provides helper functions and utility scripts.
*   `qdrant_storage`: This directory is mounted into the Qdrant Docker container to persist the vector database on your local disk.

## Setup Instructions

### 1. Prerequisites

*   Python 3.8+
*   Docker and Docker Compose
*   Access to a running [Ollama](https://ollama.ai/) instance with a suitable model (e.g., `dolphin3:latest`).

### 2. Clone the Repository

```bash
git clone https://github.com/W33Z4RD/MALR4G.git
cd MALR4G
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Vector Database (Qdrant)

This command starts a Qdrant container, maps the necessary ports, and mounts the `qdrant_storage` directory to persist data.

```bash
docker run -p 6333:6333 -p 6334:6334 \
    -v $(pwd)/qdrant_storage:/qdrant/storage:z \
    qdrant/qdrant
```

You can verify that Qdrant is running by opening the web UI at [http://localhost:6333/dashboard](http://localhost:6333/dashboard).

### 5. Configure the Project

Review the `config.py` file. The default settings should work if you are running Qdrant and Ollama locally on their default ports.

## Usage

The `main.py` script provides three modes of operation.

### Ingest Mode

Ingest malware samples into the vector database. This must be done before you can run an analysis.

```bash
# Ingest from the default path with a limit of 5000 files
python main.py --mode ingest --max-files 5000

# Ingest from a custom repository path
python main.py --mode ingest --repo-path /path/to/your/malware/dataset
```

### Analyze Mode

Analyze a suspicious file and generate a full report.

```bash
python main.py --mode analyze --file /path/to/your/suspicious_file.c
```

### Red Team Mode

Start an interactive chat session with the LLM in a "Red Team" persona for adversarial brainstorming.

```bash
python main.py --mode redteam
```
Inside the chat, type `exit` or `quit` to end the session.

---

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or find any bugs.
