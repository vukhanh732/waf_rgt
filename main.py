import argparse
import logging
import datetime
import re # Import datetime for generation date
from parser import parse_log_entry
from detector import detect_attacks
from rule_generator import generate_rule

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, # Keep at INFO for cleaner output during normal runs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("waf_rgt.log"),
        logging.StreamHandler()
    ]
)

# --- False Positive Whitelist (Simplified for this phase) ---
# These are regex patterns that, if matched, will be considered benign
# and will prevent a rule from being generated for that specific detection.
# In a real system, this would be dynamic, user-managed, or learned.
# Example: The "Command Injection - Common Commands" detection on "/products?category=electronics&id=123"
# is a false positive. We can add a pattern that specifically whitelists 'id=\d+'.
FALSE_POSITIVE_WHITELIST = [
    re.compile(r"id=\d+", re.IGNORECASE), # Whitelist common ID parameters
    re.compile(r"category=[a-zA-Z0-9]+", re.IGNORECASE), # Whitelist common category parameters
    # Add more specific patterns as needed based on observed false positives
    # For example, if "test.php" is a legitimate file, you might add:
    # re.compile(r"/test.php", re.IGNORECASE)
]

def is_false_positive(threat_detection):
    """
    Checks if a detected threat matches any pattern in the false positive whitelist.

    Args:
        threat_detection (dict): A dictionary describing a detected threat.

    Returns:
        bool: True if it's a false positive, False otherwise.
    """
    matched_value = threat_detection.get('matched_value', '')
    matched_field = threat_detection.get('matched_field', '')
    
    # Apply specific false positive logic based on the threat name or matched field
    if threat_detection['name'] == 'Command Injection - Common Commands' and 'id=' in matched_value:
        # This is a heuristic for the false positive on '/products?category=electronics&id=123'
        # The 'id=123' part is what triggered the 'commands' regex.
        # We can specifically check if the matched value is just a number in an ID parameter.
        if re.search(r"id=\d+", matched_value, re.IGNORECASE):
            logging.info(f"  -> Identified as potential false positive (Command Injection on ID): {matched_value}")
            return True

    # General whitelist check for matched_value
    for pattern in FALSE_POSITIVE_WHITELIST:
        if pattern.search(matched_value):
            logging.info(f"  -> Identified as false positive by whitelist pattern: '{pattern.pattern}' in '{matched_value}'")
            return True
            
    return False


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
    parser.add_argument(
        '-o', '--output',
        type=str,
        default="generated_waf_rules.conf", # Default output file name
        help="Path to the output file for generated WAF rules."
    )

    args = parser.parse_args()

    # --- Read and Parse Logs ---
    logging.info(f"Reading logs from: {args.input}")
    requests = read_logs(args.input)
    logging.info(f"Finished parsing. Total requests parsed: {len(requests)}")

    # --- Detect Attacks & Handle False Positives ---
    logging.info("\n--- Analyzing requests for attack patterns ---")
    all_detected_threats = []
    false_positives_count = 0
    for i, req in enumerate(requests):
        threats_in_request = detect_attacks(req)
        
        # Filter out false positives
        filtered_threats = []
        for threat in threats_in_request:
            if is_false_positive(threat):
                false_positives_count += 1
                logging.info(f"  -> Skipping rule generation for potential false positive: {threat['name']} in '{threat['matched_value']}'")
            else:
                filtered_threats.append(threat)

        if filtered_threats:
            all_detected_threats.extend(filtered_threats)
            logging.info(f"Threat(s) detected in request from {req['ip_address']} ({req['method']} {req['full_path']}):")
            for threat in filtered_threats:
                logging.info(f"  - {threat['name']} (Severity: {threat['severity']}) in {threat['matched_field']}: '{threat['matched_value']}'")
        else:
            logging.debug(f"No threats detected in request from {req['ip_address']} ({req['method']} {req['full_path']})")

    logging.info(f"\n--- Analysis Complete. Total threats detected (after FP filtering): {len(all_detected_threats)} ---")
    logging.info(f"Total potential false positives identified: {false_positives_count}")

    # --- Generate WAF Rules ---
    logging.info("\n--- Generating WAF rules ---")
    generated_rules = set() # Use a set to store unique rules
    for threat in all_detected_threats:
        rule = generate_rule(threat)
        if rule:
            generated_rules.add(rule) # Add to set to ensure uniqueness

    logging.info(f"Total unique WAF rules generated: {len(generated_rules)}")

    # --- Write Rules to Output File ---
    try:
        with open(args.output, 'w') as f:
            f.write("# Generated by AWAF-RGT (AI-Assisted WAF Rule Generator & Tuner)\n")
            f.write(f"# Generation Date: {datetime.datetime.now().isoformat()}\n\n")
            for rule in sorted(list(generated_rules)): # Sort for consistent output
                f.write(rule)
                f.write("\n\n") # Add extra newline for readability
        logging.info(f"Generated WAF rules written to: {args.output}")
    except Exception as e:
        logging.error(f"Error writing rules to file {args.output}: {e}")

    logging.info("AWAF-RGT finished Phase 4.")

if __name__ == "__main__":
    main()

