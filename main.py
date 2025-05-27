import argparse
import logging
from parser import parse_log_entry # Import our parser module

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, # Set to DEBUG for more verbose output during development
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("waf_rgt.log"), # Logs to a file named waf_rgt.log
        logging.StreamHandler()              # Logs to the console
    ]
)

def read_logs(file_path):
    """
    Reads log entries from a specified file and parses them.

    Args:
        file_path (str): The path to the log file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a parsed request.
    """
    parsed_requests = []
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                parsed_data = parse_log_entry(line.strip())
                if parsed_data:
                    parsed_requests.append(parsed_data)
                    logging.debug(f"Successfully parsed line {line_num}: {line.strip()}")
                else:
                    logging.warning(f"Failed to parse line {line_num}: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"Error: Log file not found at {file_path}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading logs: {e}")
    
    return parsed_requests

def main():
    """Main function to run the WAF Rule Generator & Tuner."""
    logging.info("Starting AWAF-RGT: AI-Assisted WAF Rule Generator & Tuner")

    # --- Command Line Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Analyze web server logs to suggest WAF rules."
    )
    parser.add_argument(
        '-i', '--input', 
        type=str, 
        required=True, 
        help="Path to the input web server access log file."
    )
    # We'll add -o (output file) and other arguments in later phases

    args = parser.parse_args()

    # --- Read and Parse Logs ---
    logging.info(f"Reading logs from: {args.input}")
    requests = read_logs(args.input)
    logging.info(f"Finished parsing. Total requests parsed: {len(requests)}")

    # --- Initial Output (for verification) ---
    if requests:
        logging.info("\n--- Displaying first 5 parsed requests ---")
        for i, req in enumerate(requests[:5]):
            print(f"\nRequest {i+1}:")
            print(f"  IP: {req['ip_address']}")
            print(f"  Timestamp: {req['timestamp']}")
            print(f"  Method: {req['method']}")
            print(f"  Path: {req['path']}")
            print(f"  Query Params: {req['query_params']}")
            print(f"  User-Agent: {req['headers'].get('User-Agent')}")
            print(f"  Full Path (decoded): {req['full_path']}") # Show decoded full path
            print("-" * 40)
        if len(requests) > 5:
            logging.info(f"... and {len(requests) - 5} more requests.")
    else:
        logging.info("No requests were parsed. Check log file path and format.")

    logging.info("AWAF-RGT finished Phase 1.")

if __name__ == "__main__":
    main()

