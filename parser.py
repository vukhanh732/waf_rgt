import re
from urllib.parse import urlparse, parse_qs, unquote_plus
import json

# Regex for a common Nginx/Apache combined log format
# This regex is designed to capture:
# 1: IP Address
# 2: Timestamp
# 3: HTTP Method
# 4: URL Path (including query string)
# 5: HTTP Protocol Version
# 6: Status Code
# 7: Response Size
# 8: Referer
# 9: User-Agent
LOG_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] '
    r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(.*?)\s+(HTTP/\d\.\d)" '
    r'(\d{3}) (\d+) "(.*?)" "(.*?)"'
)

def parse_log_entry(log_line):
    """
    Parses a single web server log line into a structured dictionary.

    Args:
        log_line (str): A single line from a web server access log.

    Returns:
        dict or None: A dictionary containing parsed request components,
                      or None if the line cannot be parsed.
    """
    match = LOG_PATTERN.match(log_line)
    if not match:
        return None

    (ip_address, timestamp, method, full_path, http_version,
     status_code, response_size, referer, user_agent) = match.groups()

    # Parse the URL to separate path and query string
    parsed_url = urlparse(full_path)
    path = parsed_url.path
    query_string = parsed_url.query
    
    # Parse query parameters into a dictionary
    query_params = parse_qs(query_string)
    # unquote_plus each value in the query parameters
    decoded_query_params = {k: [unquote_plus(v_item) for v_item in v] for k, v in query_params.items()}

    # Placeholder for request_body (not present in standard access logs, handled later)
    request_body = None 

    # Placeholder for headers (only User-Agent and Referer are directly parsed from this log format)
    headers = {
        "User-Agent": unquote_plus(user_agent),
        "Referer": unquote_plus(referer) if referer != '-' else None # Handle '-' for no referer
    }

    return {
        "raw_log": log_line,
        "ip_address": ip_address,
        "timestamp": timestamp,
        "method": method,
        "full_path": unquote_plus(full_path), # Decode the full path including query
        "path": unquote_plus(path),
        "query_string": unquote_plus(query_string), # Decode the raw query string
        "query_params": decoded_query_params,
        "http_version": http_version,
        "status_code": int(status_code),
        "response_size": int(response_size),
        "headers": headers,
        "request_body": request_body # Will be populated if we read from a source that includes it
    }

# Example usage (for testing this module directly)
if __name__ == "__main__":
    sample_log_lines = [
        '192.168.1.10 - - [27/May/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"',
        '172.16.0.2 - - [27/May/2025:10:00:15 +0000] "GET /search?query=test%27%20OR%201%3D1-- HTTP/1.1" 403 200 "http://example.com/search" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"',
        '203.0.113.1 - - [27/May/2025:10:00:20 +0000] "GET /vuln.php?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 300 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
        '198.51.100.1 - - [27/May/2025:10:00:25 +0000] "GET /etc/passwd HTTP/1.1" 404 150 "http://attacker.com/" "curl/7.68.0"',
        '192.168.1.12 - - [27/May/2025:10:00:30 +0000] "POST /api/data HTTP/1.1" 200 100 "http://example.com/app" "PostmanRuntime/7.29.0"' # Body not in log, but we'll handle later
    ]

    for line in sample_log_lines:
        parsed = parse_log_entry(line)
        if parsed:
            print(f"--- Parsed Request from {parsed['ip_address']} ---")
            print(f"Method: {parsed['method']}")
            print(f"Path: {parsed['path']}")
            print(f"Query Params: {parsed['query_params']}")
            print(f"User-Agent: {parsed['headers'].get('User-Agent')}")
            print("-" * 30)
        else:
            print(f"Could not parse line: {line}")

