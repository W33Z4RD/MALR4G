# Malware RAG Analysis System

This project is a sophisticated malware analysis system that leverages Retrieval-Augmented Generation (RAG) to provide deep, context-aware analysis of suspicious code. By combining a vast database of known malware samples with the analytical power of large language models (LLMs), this system can identify threats, explain their functionality, and generate detection rules.

## Key Features

*   **Hybrid Search:** Utilizes a combination of dense vector search and sparse keyword search to find the most relevant malware samples from the database.
*   **RAG-Powered Analysis:** Enriches the analysis by providing the LLM with context from similar malware samples, enabling more accurate and detailed reports.
*   **Comprehensive Reporting:** Generates in-depth analysis reports that include an executive summary, behavioral analysis, MITRE ATT&CK mapping, indicators of compromise (IOCs), and YARA detection rules.
*   **Automatic YARA Rule Generation:** Creates YARA rules based on common patterns identified in clusters of similar malware samples.
*   **Modular Architecture:** The system is divided into distinct modules for ingestion, retrieval, and analysis, making it easy to extend and maintain.
*   **Efficient Ingestion:** A flexible data ingestion pipeline that can process a variety of file types, including source code, binary files, and documents.

## Project Structure

The project is organized into the following directories:

*   `analysis`: Contains the logic for analyzing suspicious code, including the query router, YARA generator, and LLM analyzer.
*   `ingestion`: Handles the ingestion of malware samples into the vector database, including data loading and preprocessing.
*   `retrieval`: Implements the search functionality for finding similar malware samples in the vector database.
*   `utils`: Provides helper functions and utility scripts used throughout the project.

## Getting Started

### Prerequisites

*   Python 3.8+
*   [Poetry](https://python-poetry.org/) for dependency management
*   Access to a running [Ollama](https://ollama.ai/) instance with a suitable model (e.g., `dolphin3:8b`)

### Setup Instructions

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/malware-rag-project.git
    cd malware-rag-project
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Download the malware dataset:**

    This project is designed to work with the [VX-Underground](https://vx-underground.org/datasets.html) malware dataset. Download the dataset and place it in a directory accessible to the project.

4.  **Configure the project:**

    Update the `config.py` file with the appropriate paths and settings for your environment.

5.  **Ingest the malware data:**

    Run the following command to ingest the malware samples into the vector database. This may take a significant amount of time depending on the size of the dataset.

    ```bash
    python main.py --ingest --repo-path /path/to/vx-underground
    ```

6.  **Analyze a suspicious file:**

    Once the ingestion is complete, you can analyze a suspicious file using the following command:

    ```bash
    python main.py --analyze /path/to/suspicious_file.py
    ```

## Usage

The `main.py` script provides two main functions:

*   `--ingest`: Ingests the malware dataset into the vector database.
*   `--analyze`: Analyzes a suspicious file and generates a report.

For more information on the available options, run:

```bash
python main.py --help
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or find any bugs.
