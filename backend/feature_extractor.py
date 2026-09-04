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
    'bonus', 'service', 'wallet', 'security', 'support', 'confirm',
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
            subdomain_str = ext.subdomain
            if not subdomain_str or subdomain_str == 'www':
                no_of_subdomain = 1.0
            else:
                subdomains = subdomain_str.split('.')
                no_of_subdomain = float(len(subdomains))
            return tld, len(tld), no_of_subdomain
        except Exception:
            pass
            
    # Fallback splitting by dot
    parts = domain_clean.split('.')
    if len(parts) <= 1:
        return '', 0, 1.0
    tld = parts[-1]
    subdomains = parts[:-2] if len(parts) > 2 else ['www']
    return tld, len(tld), float(len(subdomains))

def extract_url_features(url: str) -> dict:
    """
    Extract canonical 24 lexical, structural, and statistical features from a raw URL string.
    Guarantees 100% consistency between model training and live inference.
    """
    url_str = str(url).strip()
    if not url_str:
        url_str = "https://unknown.com"
        
    # Ensure scheme for urlparse if missing
    if not re.match(r'^[a-zA-Z]+://', url_str, re.IGNORECASE):
        parse_target = 'https://' + url_str
        is_https = 1
    else:
        parse_target = url_str
        is_https = 1 if url_str.lower().startswith('https://') else 0

    parsed = urlparse(parse_target)
    domain_full = (parsed.netloc or parsed.path.split('/')[0]).lower()
    domain_clean = domain_full.split(':')[0]
    
    # Normalize 2-part root domain to standard www form (e.g. netflix.com -> www.netflix.com)
    if not domain_clean.startswith('www.') and domain_clean.count('.') == 1 and not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain_clean):
        domain_clean = 'www.' + domain_clean
        parse_target = parse_target.replace(domain_full.split(':')[0], domain_clean, 1)

    # Normalize target URL for consistent feature counts (strip trailing slash if root path)
    url_norm = parse_target
    if url_norm.endswith('/') and parsed.path in ['', '/'] and not parsed.query:
        url_norm = url_norm[:-1]

    url_length = len(url_norm)
    domain_length = len(domain_clean)
    
    # Check IP address usage
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    is_domain_ip = 1 if re.match(ip_pattern, domain_clean) else 0

    tld, tld_length, no_of_subdomain = parse_domain_info(domain_clean)

    # Letters & Digits
    letters = sum(1 for c in url_norm if c.isalpha())
    digits = sum(1 for c in url_norm if c.isdigit())
    letter_ratio = letters / url_length if url_length > 0 else 0.0
    digit_ratio = digits / url_length if url_length > 0 else 0.0
    
    # Specific characters
    no_of_equals = url_norm.count('=')
    no_of_qmark = url_norm.count('?')
    no_of_ampersand = url_norm.count('&')
    
    # Obfuscation
    obfuscated_chars = len(re.findall(r'%[0-9a-fA-F]{2}|@', url_norm))
    has_obfuscation = 1 if obfuscated_chars > 0 else 0
    obfuscation_ratio = obfuscated_chars / url_length if url_length > 0 else 0.0
    
    # Special characters (excluding scheme and standard path delimiters)
    special_symbols = sum(1 for c in url_norm if not c.isalnum() and c not in ['/', ':', '.'])
    special_symbol_ratio = special_symbols / url_length if url_length > 0 else 0.0
    
    # Advanced lexical features
    entropy = calculate_entropy(url_norm)
    char_continuation_rate = calculate_char_continuation_rate(url_norm)
    
    # Additional flags
    has_at_symbol = 1 if '@' in url_norm else 0
    has_double_slash_path = 1 if '//' in parsed.path else 0
    hyphens_in_domain = domain_clean.count('-')
    
    # Keyword detection
    url_lower = url_norm.lower()
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
        'NoOfOtherSpecialCharsInURL': float(special_symbols),
        'SpacialCharRatioInURL': float(special_symbol_ratio),
        'IsHTTPS': int(is_https),
        'CharContinuationRate': float(char_continuation_rate),
        'Entropy': float(entropy),
        'HasAtSymbol': int(has_at_symbol),
        'HasDoubleSlashInPath': int(has_double_slash_path),
        'HyphensInDomain': float(hyphens_in_domain),
        'SuspiciousKeywordCount': float(suspicious_keyword_count)
    }
    
    return features

