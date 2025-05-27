import argparse
import logging
from parser import parse_log_entry # Import our parser module
from detector import detect_attacks # Import our new detector module

# --- Logging Setup ---
logging.basicConfig(
    level=logging.DEBUG, # Changed to DEBUG for more verbose output during development
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

    # --- Detect Attacks ---
    logging.info("\n--- Analyzing requests for attack patterns ---")
    all_detected_threats = []
    for i, req in enumerate(requests):
        threats_in_request = detect_attacks(req)
        if threats_in_request:
            all_detected_threats.extend(threats_in_request)
            logging.info(f"Threat(s) detected in request from {req['ip_address']} ({req['method']} {req['full_path']}):")
            for threat in threats_in_request:
                logging.info(f"  - {threat['name']} (Severity: {threat['severity']}) in {threat['matched_field']}: '{threat['matched_value']}'")
        else:
            logging.debug(f"No threats detected in request from {req['ip_address']} ({req['method']} {req['full_path']})")

    logging.info(f"\n--- Analysis Complete. Total threats detected: {len(all_detected_threats)} ---")

    logging.info("AWAF-RGT finished Phase 2.")

if __name__ == "__main__":
    main()

