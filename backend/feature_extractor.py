import re
import math
from urllib.parse import urlparse

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'account', 'banking', 'secure', 'webscr', 
    'paypal', 'ebay', 'signin', 'admin', 'credential', 'free', 'token', 
    'bonus', 'service', 'wallet', 'security', 'support', 'verify', 'confirm',
    'password', 'billing', 'online', 'auth', 'access'
]

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def calculate_char_continuation_rate(s: str) -> float:
    """Calculate ratio of max consecutive repeating character sequence."""
    if not s:
        return 0.0
    max_run = 1
    current_run = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    return max_run / len(s)

def parse_domain_info(domain_clean: str):
    """Extract TLD and subdomains safely with or without tldextract."""
    if HAS_TLDEXTRACT:
        try:
            ext = tldextract.extract(domain_clean)
            tld = ext.suffix or ''
            # In dataset, standard domains (www.example.com) have NoOfSubDomain = 1.0 (counting www as 1)
            # If user enters example.com without www, count main domain level appropriately.
            subdomain_str = ext.subdomain
            if not subdomain_str:
                subdomains = ['www'] # Match dataset convention for standard root domains
            else:
                subdomains = subdomain_str.split('.')
            return tld, len(tld), len(subdomains)
        except Exception:
            pass
            
    # Fallback splitting by dot
    parts = domain_clean.split('.')
    if len(parts) <= 1:
        return '', 0, 1
    tld = parts[-1]
    subdomains = parts[:-2] if len(parts) > 2 else ['www']
    return tld, len(tld), len(subdomains)

def extract_url_features(url: str) -> dict:
    """
    Extract lexical, structural, and statistical features from a raw URL string.
    Works robustly with or without http/https protocol prefix.
    """
    url_str = str(url).strip()
    if not url_str:
        url_str = "https://unknown.com"
        
    # Ensure scheme for urlparse if missing
    if not re.match(r'^[a-zA-Z]+://', url_str):
        parse_target = 'https://' + url_str
        is_https = 1
    else:
        parse_target = url_str
        is_https = 1 if url_str.lower().startswith('https://') else 0

    parsed = urlparse(parse_target)
    domain_full = parsed.netloc or parsed.path.split('/')[0]
    
    # Remove port if present for domain analysis
    domain_clean = domain_full.split(':')[0]
    
    # Check IP address usage
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    is_domain_ip = 1 if re.match(ip_pattern, domain_clean) else 0

    tld, tld_length, no_of_subdomain = parse_domain_info(domain_clean)

    # Basic counts
    url_length = len(url_str)
    domain_length = len(domain_clean)
    
    # Letters & Digits
    letters = sum(1 for c in url_str if c.isalpha())
    digits = sum(1 for c in url_str if c.isdigit())
    letter_ratio = letters / url_length if url_length > 0 else 0.0
    digit_ratio = digits / url_length if url_length > 0 else 0.0
    
    # Specific characters
    no_of_equals = url_str.count('=')
    no_of_qmark = url_str.count('?')
    no_of_ampersand = url_str.count('&')
    
    # Obfuscation
    obfuscated_chars = len(re.findall(r'%[0-9a-fA-F]{2}|@', url_str))
    has_obfuscation = 1 if obfuscated_chars > 0 else 0
    obfuscation_ratio = obfuscated_chars / url_length if url_length > 0 else 0.0
    
    # Special characters
    special_chars = sum(1 for c in url_str if not c.isalnum())
    other_special = sum(1 for c in url_str if not c.isalnum() and c not in ['/', ':', '.', '?', '=', '&'])
    special_char_ratio = special_chars / url_length if url_length > 0 else 0.0
    
    # Advanced lexical features
    entropy = calculate_entropy(url_str)
    char_continuation_rate = calculate_char_continuation_rate(url_str)
    
    # Additional flags
    has_at_symbol = 1 if '@' in url_str else 0
    has_double_slash_path = 1 if '//' in parsed.path else 0
    hyphens_in_domain = domain_clean.count('-')
    
    # Keyword detection
    url_lower = url_str.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    features = {
        'URLLength': float(url_length),
        'DomainLength': float(domain_length),
        'IsDomainIP': int(is_domain_ip),
        'TLDLength': float(tld_length),
        'NoOfSubDomain': float(no_of_subdomain),
        'HasObfuscation': int(has_obfuscation),
        'NoOfObfuscatedChar': float(obfuscated_chars),
        'ObfuscationRatio': float(obfuscation_ratio),
        'NoOfLettersInURL': float(letters),
        'LetterRatioInURL': float(letter_ratio),
        'NoOfDegitsInURL': float(digits),
        'DegitRatioInURL': float(digit_ratio),
        'NoOfEqualsInURL': float(no_of_equals),
        'NoOfQMarkInURL': float(no_of_qmark),
        'NoOfAmpersandInURL': float(no_of_ampersand),
        'NoOfOtherSpecialCharsInURL': float(other_special),
        'SpacialCharRatioInURL': float(special_char_ratio),
        'IsHTTPS': int(is_https),
        'CharContinuationRate': float(char_continuation_rate),
        'Entropy': float(entropy),
        'HasAtSymbol': int(has_at_symbol),
        'HasDoubleSlashInPath': int(has_double_slash_path),
        'HyphensInDomain': float(hyphens_in_domain),
        'SuspiciousKeywordCount': float(suspicious_keyword_count)
    }
    
    return features
