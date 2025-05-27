import re
import logging

# Configure logging for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Can be set to DEBUG for more detailed output

# --- Attack Signatures Definition ---
# Each signature is a dictionary with:
# - 'name': A unique name for the attack type.
# - 'pattern': A compiled regular expression for detection.
# - 'target_fields': A list of request components to check (e.g., 'path', 'query_params', 'body', 'headers').
# - 'severity': 'Low', 'Medium', 'High', 'Critical'.
# - 'description': A brief explanation of the attack.
# - 'waf_rule_tag': A tag used for generating WAF rules (e.g., 'sqli', 'xss', 'pt').

ATTACK_SIGNATURES = [
    # --- SQL Injection (SQLi) ---
    {
        'name': 'SQLi - Common Keywords',
        'pattern': re.compile(
            r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|xp_cmdshell|exec\s+\(|"
            r"benchmark\(|sleep\(|pg_sleep\(|waitfor\s+delay|information_schema|sys.objects|user_tab_columns|"
            r"@@version|load_file|outfile|dumpfile|into\s+outfile|into\s+dumpfile)",
            re.IGNORECASE
        ),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects common keywords used in SQL Injection attacks.',
        'waf_rule_tag': 'sqli_keywords'
    },
    {
        'name': 'SQLi - Boolean Based',
        'pattern': re.compile(r"(\s+or\s+\d+=\d+|\s+and\s+\d+=\d+|\s+or\s+['\"]\w+['\"]=['\"]\w+['\"]|\s+and\s+['\"]\w+['\"]=['\"]\w+['\"])", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects boolean-based SQL Injection patterns.',
        'waf_rule_tag': 'sqli_boolean'
    },
    {
        'name': 'SQLi - Error Based',
        'pattern': re.compile(r"(extractvalue|updatexml|floor\(rand\(0\)\)|concat\(.*\))", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects functions commonly used in error-based SQL Injection.',
        'waf_rule_tag': 'sqli_error'
    },

    # --- Cross-Site Scripting (XSS) ---
    {
        'name': 'XSS - Basic Script Tags',
        'pattern': re.compile(r"(<script>|%3cscript%3e|javascript:|on(load|error|click|mouseover|mouseout|keydown|keyup|keypress)=)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects basic script tags and common event handlers for XSS.',
        'waf_rule_tag': 'xss_basic'
    },
    {
        'name': 'XSS - HTML Entities/Obfuscation',
        'pattern': re.compile(r"(&#x[0-9a-fA-F]+;|&#\d+;|<img\s+src\s*=\s*x\s+onerror=)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'Medium',
        'description': 'Detects HTML entities and common obfuscation techniques for XSS.',
        'waf_rule_tag': 'xss_obfuscation'
    },

    # --- Path Traversal (LFI/RFI) ---
    {
        'name': 'Path Traversal - Directory Up',
        'pattern': re.compile(r"(\.\./|\.\.\\|\%2e%2e%2f|\%2e%2e\\)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects attempts to traverse directories using ".." sequences.',
        'waf_rule_tag': 'pt_dir_up'
    },
    {
        'name': 'Path Traversal - Common Files',
        'pattern': re.compile(r"(/etc/passwd|/windows/win.ini|/proc/self/environ)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects attempts to access common sensitive system files.',
        'waf_rule_tag': 'pt_common_files'
    },

    # --- Command Injection (OS Command Injection) ---
    {
        'name': 'Command Injection - Basic Separators',
        'pattern': re.compile(r"(&&|\|\||;|`|\$\(|%0a|%0d)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects common command separators used in OS command injection.',
        'waf_rule_tag': 'cmd_inject_separators'
    },
    {
        'name': 'Command Injection - Common Commands',
        'pattern': re.compile(r"(cat\s+|ls\s+|whoami|id|uname|ping\s+|nc\s+-e|/bin/sh|/bin/bash)", re.IGNORECASE),
        'target_fields': ['full_path', 'query_params', 'request_body'],
        'severity': 'High',
        'description': 'Detects common system commands often used in command injection.',
        'waf_rule_tag': 'cmd_inject_commands'
    },
    
    # --- Web Scanners/Reconnaissance ---
    {
        'name': 'Web Scan - User-Agent',
        'pattern': re.compile(r"(nmap|nikto|sqlmap|acunetix|netsparker|wpscan|gobuster|dirb|feroxbuster|masscan|zgrab|testphp.vulnweb.com)", re.IGNORECASE),
        'target_fields': ['headers'], # Specifically check User-Agent header
        'severity': 'Low',
        'description': 'Detects common web vulnerability scanners by their User-Agent string.',
        'waf_rule_tag': 'scanner_ua'
    },
    {
        'name': 'Web Scan - Common Paths',
        'pattern': re.compile(r"(/phpmyadmin/|/admin/|/wp-admin/|/login.php|/test.php|/.git/config)", re.IGNORECASE),
        'target_fields': ['full_path'],
        'severity': 'Low',
        'description': 'Detects requests for common administrative or vulnerable paths.',
        'waf_rule_tag': 'scanner_paths'
    }
]

def detect_attacks(parsed_request):
    """
    Analyzes a parsed HTTP request for known attack patterns.

    Args:
        parsed_request (dict): A dictionary representing a parsed HTTP request.

    Returns:
        list: A list of dictionaries, where each dictionary describes a detected threat.
              Each threat dict includes: 'name', 'severity', 'description', 'matched_field', 'matched_value', 'matched_pattern'.
    """
    detected_threats = []

    for signature in ATTACK_SIGNATURES:
        for field in signature['target_fields']:
            # Get the value to check based on the field name
            value_to_check = None
            if field == 'full_path':
                value_to_check = parsed_request.get('full_path', '')
            elif field == 'query_params':
                # Check each value in query_params dictionary
                for param_name, param_values in parsed_request.get('query_params', {}).items():
                    for param_value in param_values:
                        if signature['pattern'].search(param_value):
                            detected_threats.append({
                                'name': signature['name'],
                                'severity': signature['severity'],
                                'description': signature['description'],
                                'matched_field': f"query_param_{param_name}",
                                'matched_value': param_value,
                                'matched_pattern': signature['pattern'].pattern,
                                'waf_rule_tag': signature['waf_rule_tag']
                            })
                            logger.debug(f"Detected {signature['name']} in query param '{param_name}' with value '{param_value}'")
                            # Found a match, move to next signature to avoid duplicate detections for the same signature
                            # but allow other signatures to match on this request
                            break 
                    else: # This else belongs to the inner for loop (param_values)
                        continue
                    break # This break belongs to the outer for loop (param_name)
                if detected_threats and detected_threats[-1].get('waf_rule_tag') == signature['waf_rule_tag']:
                    continue # Already added for this signature
                
            elif field == 'request_body':
                value_to_check = parsed_request.get('request_body', '')
                # If request_body is JSON, check values within it
                if parsed_request.get('headers', {}).get('Content-Type', '').startswith('application/json'):
                    try:
                        json_body = json.loads(value_to_check)
                        # Simple recursive search for string values in JSON
                        for key, val in json_body.items():
                            if isinstance(val, str) and signature['pattern'].search(val):
                                detected_threats.append({
                                    'name': signature['name'],
                                    'severity': signature['severity'],
                                    'description': signature['description'],
                                    'matched_field': f"json_body_{key}",
                                    'matched_value': val,
                                    'matched_pattern': signature['pattern'].pattern,
                                    'waf_rule_tag': signature['waf_rule_tag']
                                })
                                logger.debug(f"Detected {signature['name']} in JSON body key '{key}' with value '{val}'")
                                break # Found a match, move to next signature
                        if detected_threats and detected_threats[-1].get('waf_rule_tag') == signature['waf_rule_tag']:
                            continue # Already added for this signature
                    except json.JSONDecodeError:
                        logger.warning(f"Request body is not valid JSON for {parsed_request.get('ip_address')}")
                        # Fallback to checking raw body if JSON parsing fails
                        if signature['pattern'].search(value_to_check):
                            detected_threats.append({
                                'name': signature['name'],
                                'severity': signature['severity'],
                                'description': signature['description'],
                                'matched_field': 'request_body_raw',
                                'matched_value': value_to_check,
                                'matched_pattern': signature['pattern'].pattern,
                                'waf_rule_tag': signature['waf_rule_tag']
                            })
                            logger.debug(f"Detected {signature['name']} in raw request body")
                            continue # Already added for this signature
                else: # Not JSON, just check the raw body
                    if signature['pattern'].search(value_to_check):
                        detected_threats.append({
                            'name': signature['name'],
                            'severity': signature['severity'],
                            'description': signature['description'],
                            'matched_field': 'request_body',
                            'matched_value': value_to_check,
                            'matched_pattern': signature['pattern'].pattern,
                            'waf_rule_tag': signature['waf_rule_tag']
                        })
                        logger.debug(f"Detected {signature['name']} in request body")
                        continue # Already added for this signature
            elif field == 'headers':
                # Specifically for User-Agent or other headers
                user_agent = parsed_request.get('headers', {}).get('User-Agent', '')
                if signature['pattern'].search(user_agent):
                    detected_threats.append({
                        'name': signature['name'],
                        'severity': signature['severity'],
                        'description': signature['description'],
                        'matched_field': 'header_User-Agent',
                        'matched_value': user_agent,
                        'matched_pattern': signature['pattern'].pattern,
                        'waf_rule_tag': signature['waf_rule_tag']
                    })
                    logger.debug(f"Detected {signature['name']} in User-Agent header: {user_agent}")
                    continue # Already added for this signature
            
            # For other simple string fields (like 'full_path' if not already handled by query_params)
            if value_to_check and signature['pattern'].search(value_to_check):
                detected_threats.append({
                    'name': signature['name'],
                    'severity': signature['severity'],
                    'description': signature['description'],
                    'matched_field': field,
                    'matched_value': value_to_check,
                    'matched_pattern': signature['pattern'].pattern,
                    'waf_rule_tag': signature['waf_rule_tag']
                })
                logger.debug(f"Detected {signature['name']} in {field}: {value_to_check}")

    return detected_threats

# Example usage (for testing this module directly)
if __name__ == "__main__":
    # Example parsed request (simulating output from parser.py)
    sample_parsed_request_sqli = {
        "raw_log": "...",
        "ip_address": "172.16.0.2",
        "timestamp": "27/May/2025:10:00:15 +0000",
        "method": "GET",
        "full_path": "/search?query=test' OR 1=1--",
        "path": "/search",
        "query_string": "query=test%27%20OR%201%3D1--",
        "query_params": {'query': ["test' OR 1=1--"]},
        "http_version": "HTTP/1.1",
        "status_code": 403,
        "response_size": 200,
        "headers": {"User-Agent": "Mozilla/5.0 ..."},
        "request_body": None
    }

    sample_parsed_request_xss = {
        "raw_log": "...",
        "ip_address": "203.0.113.1",
        "timestamp": "27/May/2025:10:00:20 +0000",
        "method": "GET",
        "full_path": "/vuln.php?name=<script>alert(1)</script>",
        "path": "/vuln.php",
        "query_string": "name=%3Cscript%3Ealert(1)%3C/script%3E",
        "query_params": {'name': ['<script>alert(1)</script>']},
        "http_version": "HTTP/1.1",
        "status_code": 200,
        "response_size": 300,
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        "request_body": None
    }
    
    sample_parsed_request_pt = {
        "raw_log": "...",
        "ip_address": "198.51.100.1",
        "timestamp": "27/May/2025:10:00:25 +0000",
        "method": "GET",
        "full_path": "/etc/passwd",
        "path": "/etc/passwd",
        "query_string": "",
        "query_params": {},
        "http_version": "HTTP/1.1",
        "status_code": 404,
        "response_size": 150,
        "headers": {"User-Agent": "curl/7.68.0"},
        "request_body": None
    }

    sample_parsed_request_scanner_ua = {
        "raw_log": "...",
        "ip_address": "1.2.3.4",
        "timestamp": "27/May/2025:10:00:25 +0000",
        "method": "GET",
        "full_path": "/index.php",
        "path": "/index.php",
        "query_string": "",
        "query_params": {},
        "http_version": "HTTP/1.1",
        "status_code": 200,
        "response_size": 150,
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; Nikto/2.1.5; +http://cirt.net/nikto/)"},
        "request_body": None
    }

    print("--- Testing SQLi Detection ---")
    detections = detect_attacks(sample_parsed_request_sqli)
    for d in detections:
        print(f"  Detected: {d['name']} (Severity: {d['severity']}) in {d['matched_field']}: {d['matched_value']}")

    print("\n--- Testing XSS Detection ---")
    detections = detect_attacks(sample_parsed_request_xss)
    for d in detections:
        print(f"  Detected: {d['name']} (Severity: {d['severity']}) in {d['matched_field']}: {d['matched_value']}")

    print("\n--- Testing Path Traversal Detection ---")
    detections = detect_attacks(sample_parsed_request_pt)
    for d in detections:
        print(f"  Detected: {d['name']} (Severity: {d['severity']}) in {d['matched_field']}: {d['matched_value']}")

    print("\n--- Testing Scanner User-Agent Detection ---")
    detections = detect_attacks(sample_parsed_request_scanner_ua)
    for d in detections:
        print(f"  Detected: {d['name']} (Severity: {d['severity']}) in {d['matched_field']}: {d['matched_value']}")

