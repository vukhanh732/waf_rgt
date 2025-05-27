import logging
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Can be set to DEBUG for more detailed output

# Global counter for rule IDs (ModSecurity rules need unique IDs)
# In a real system, this would be managed more robustly (e.g., from a database)
# For this project, we'll increment it. Start from a high number to avoid conflicts with CRS.
_RULE_ID_COUNTER = 100000

def get_next_rule_id():
    """Increments and returns the next unique rule ID."""
    global _RULE_ID_COUNTER
    _RULE_ID_COUNTER += 1
    return _RULE_ID_COUNTER

def escape_regex_for_modsecurity(pattern_string):
    """
    Escapes a raw regex pattern string for use within ModSecurity's PCRE engine.
    ModSecurity often requires escaping of characters like '|' or '"' if they are
    part of the literal pattern and not regex operators.
    
    For simplicity, this function will primarily escape quotes and backslashes
    that might interfere with ModSecurity's rule parsing.
    
    Note: This is a simplified escaping. Complex regexes might need more specific handling.
    """
    # Escape backslashes first, then single quotes, then double quotes
    # ModSecurity rules use double quotes for the regex, so double quotes need escaping.
    # We're assuming the regex pattern itself is already valid Python regex.
    escaped_pattern = pattern_string.replace('\\', '\\\\') # Escape existing backslashes
    escaped_pattern = escaped_pattern.replace('"', '\\"') # Escape double quotes
    escaped_pattern = escaped_pattern.replace("'", "\\'") # Escape single quotes
    
    # ModSecurity's PCRE engine might interpret some characters differently or
    # require additional escaping for certain contexts.
    # For example, if the regex contains a literal '|' that is not meant as an OR,
    # it might need to be escaped. However, for most common attack patterns,
    # the regex operators like | (OR), ? (optional), * (zero or more) are expected.
    # We'll rely on the original regex being correctly formed.
    
    return escaped_pattern


def generate_rule(detected_threat):
    """
    Generates a ModSecurity-like WAF rule string for a given detected threat.

    Args:
        detected_threat (dict): A dictionary describing a detected threat,
                                 as returned by detector.py's detect_attacks.

    Returns:
        str: A string representing the generated WAF rule, or None if a rule cannot be generated.
    """
    rule_id = get_next_rule_id()
    
    # Determine the ModSecurity variable to target based on the matched_field
    target_variable = ""
    if detected_threat['matched_field'].startswith('query_param_'):
        # Target specific query parameter
        param_name = detected_threat['matched_field'].replace('query_param_', '')
        target_variable = f"ARGS:{param_name}"
    elif detected_threat['matched_field'] == 'full_path':
        target_variable = "REQUEST_URI"
    elif detected_threat['matched_field'] == 'path': # Less specific than full_path, prefer full_path
        target_variable = "REQUEST_URI"
    elif detected_threat['matched_field'] == 'request_body' or detected_threat['matched_field'].startswith('json_body_'):
        target_variable = "REQUEST_BODY"
    elif detected_threat['matched_field'] == 'header_User-Agent':
        target_variable = "REQUEST_HEADERS:User-Agent"
    else:
        logger.warning(f"Unknown matched_field '{detected_threat['matched_field']}'. Cannot generate specific rule variable.")
        # Fallback to checking all args and body if specific target not found
        target_variable = "ARGS|REQUEST_BODY|REQUEST_URI|REQUEST_HEADERS" 

    # Escape the regex pattern for ModSecurity
    # The pattern is already a Python regex string, but might contain chars that
    # ModSecurity's parsing of the rule file itself would misinterpret (e.g., quotes).
    # We also need to ensure the regex is suitable for ModSecurity's PCRE engine.
    # For now, we'll use the raw pattern from the signature, assuming it's PCRE compatible.
    # A more advanced tool might convert Python regex to PCRE if differences exist.
    # The `re.escape` in Python is for escaping *literal* strings to be used in regex,
    # not for escaping regex *patterns* for another regex engine.
    # So, we'll just use the pattern as is, but ensure it's quoted correctly.
    
    # We need to ensure the regex pattern itself is safe within the double quotes of SecRule.
    # This means escaping any double quotes within the pattern.
    pattern_for_rule = detected_threat['matched_pattern'].replace('"', '\\"')
    
    # Construct the ModSecurity rule string
    # Using 'phase:2' for request body/URI/headers checks, 'block' action.
    # 'deny' is often used with 'block' to reject the request.
    # 'log' ensures the event is logged.
    # 'msg' provides a human-readable message.
    # 'tag' allows categorization.
    
    rule_string = (
        f'SecRule {target_variable} "@rx {pattern_for_rule}" \\\n'
        f'        "id:{rule_id},phase:2,block,deny,log,auditlog, \\\n'
        f'        msg:\'{detected_threat["name"]} detected in {detected_threat["matched_field"]}\', \\\n'
        f'        tag:\'attack-{detected_threat["waf_rule_tag"]}\', \\\n'
        f'        tag:\'severity-{detected_threat["severity"]}\', \\\n'
        f'        severity:\'{detected_threat["severity"]}\'' # Numeric severity could also be used here
        f'"'
    )
    
    logger.debug(f"Generated rule (ID: {rule_id}):\n{rule_string}")
    return rule_string

# Example usage (for testing this module directly)
if __name__ == "__main__":
    # Simulate a detected threat
    sample_detected_sqli = {
        'name': 'SQLi - Boolean Based',
        'severity': 'High',
        'description': 'Detects boolean-based SQL Injection patterns.',
        'matched_field': 'query_param_query',
        'matched_value': "test' OR 1=1--",
        'matched_pattern': r"(\s+or\s+\d+=\d+|\s+and\s+\d+=\d+)", # Simplified pattern for example
        'waf_rule_tag': 'sqli_boolean'
    }

    sample_detected_xss = {
        'name': 'XSS - Basic Script Tags',
        'severity': 'High',
        'description': 'Detects basic script tags for XSS.',
        'matched_field': 'query_param_name',
        'matched_value': "<script>alert(1)</script>",
        'matched_pattern': r"(<script>|javascript:)", # Simplified pattern for example
        'waf_rule_tag': 'xss_basic'
    }
    
    sample_detected_pt = {
        'name': 'Path Traversal - Common Files',
        'severity': 'High',
        'description': 'Detects attempts to access common sensitive system files.',
        'matched_field': 'full_path',
        'matched_value': "/etc/passwd",
        'matched_pattern': r"(/etc/passwd)",
        'waf_rule_tag': 'pt_common_files'
    }

    print("--- Generating SQLi Rule ---")
    sqli_rule = generate_rule(sample_detected_sqli)
    print(sqli_rule)

    print("\n--- Generating XSS Rule ---")
    xss_rule = generate_rule(sample_detected_xss)
    print(xss_rule)

    print("\n--- Generating Path Traversal Rule ---")
    pt_rule = generate_rule(sample_detected_pt)
    print(pt_rule)

