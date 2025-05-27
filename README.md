# WAF-RGT: WAF Rule Generator & Tuner

## Project Overview

The **AWAF-RGT (AI-Assisted Web Application Firewall Rule Generator & Tuner)** is a Python-based tool designed to automate and assist in the process of generating and refining Web Application Firewall (WAF) rules. It analyzes web server access logs, identifies suspicious patterns indicative of common web vulnerabilities (like SQL Injection, Cross-Site Scripting, and Path Traversal), and suggests WAF rules in a ModSecurity CRS-like syntax.

A key feature is its ability to handle simulated false positives, helping to tune the generated rules to minimize legitimate traffic blocking.

## Features

* **Log Ingestion:** Reads and parses standard web server access logs (e.g., Nginx/Apache combined log format).
* **Request Parsing:** Extracts essential HTTP request components (method, path, query parameters, headers, body placeholder).
* **Attack Pattern Detection:** Identifies a range of common web vulnerabilities using predefined regex patterns, including:
    * SQL Injection (SQLi)
    * Cross-Site Scripting (XSS)
    * Path Traversal (LFI/RFI)
    * OS Command Injection
    * Basic Web Scanner/Reconnaissance detection
* **WAF Rule Generation:** Automatically generates WAF rules in a syntax similar to ModSecurity's Core Rule Set (CRS) based on detected threats.
* **False Positive Handling:** Incorporates a basic whitelist mechanism to simulate false positive identification and prevent rule generation for benign patterns.
* **Command-Line Interface (CLI):** User-friendly interface with options for input/output files, verbosity, and controlling rule generation.

## How It Works (High-Level)

1.  **Read Logs:** The tool ingests web server access logs.
2.  **Parse Requests:** Each log entry is parsed into structured HTTP request data.
3.  **Detect Attacks:** The parsed request data is scanned against a library of attack signatures.
4.  **Filter False Positives:** Detected threats are checked against a false positive whitelist.
5.  **Generate Rules:** For confirmed threats, corresponding WAF rules are generated.
6.  **Output Rules:** The unique, generated rules are written to a specified `.conf` file.

## Getting Started

### Prerequisites

* Python 3.8+ installed.

### Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/vukhanh732/waf_rgt.git
    cd waf_rgt
    ```
    

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    # On macOS/Linux:
    source venv/bin/activate
    # On Windows (Command Prompt):
    .\venv\Scripts\activate.bat
    # On Windows (PowerShell):
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The tool is run via the command line.

```bash
python3 main.py -i <input_log_file> [OPTIONS]

Options:
-i, --input <path>: (Required) Path to the input web server access log file.

-o, --output <path>: Path to the output file for generated WAF rules.

Default: generated_waf_rules.conf

-v, --verbose: Enable verbose output (DEBUG level logging).

--no-rules: Do not generate WAF rules; only perform analysis.

--log-level <level>: Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).

Default: INFO

Examples:
Analyze logs and generate rules (default output file):

python3 main.py -i sample_access.log

Analyze logs and generate rules to a custom file:

python3 main.py -i sample_access.log -o my_custom_rules.conf

Perform verbose analysis without generating rules:

python3 main.py -i sample_access.log -v --no-rules

Run with only warning/error messages:

python3 main.py -i sample_access.log --log-level WARNING

```

Contributing
Contributions are welcome! If you have suggestions for new attack signatures, false positive handling improvements, or other features, please open an issue or submit a pull request.

License
This project is open-sourced
