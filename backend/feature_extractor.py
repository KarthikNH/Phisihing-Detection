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
    'password', 'billing', 'online', 'auth', 'access', 'recover',
    'verification', 'client', 'payment', 'authenticate', 'submit'
]

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'work', 'gq', 'cf', 'ml', 'tk', 'ga', 
    'ru', 'cn', 'live', 'stream', 'bid', 'click', 'fit', 'monster', 
    'invalid', 'today', 'pw', 'cc', 'bar', 'rest', 'surf', 'loan',
    'link', 'zone', 'win', 'space'
}

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def calculate_char_continuation_rate(s: str) -> float:
    """
    Calculate maximum consecutive repeating character run in domain, 
    ignoring standard 'www.' prefix so legitimate non-www domains 
    (like en.wikipedia.org) are not artificially penalized.
    Normal text has max_run of 1 or 2. Excessive runs (4+) indicate typosquatting.
    """
    clean = re.sub(r'^www\.', '', str(s).lower())
    if not clean:
        return 1.0
    max_run = 1
    current_run = 1
    for i in range(1, len(clean)):
        if clean[i] == clean[i-1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    return float(max_run)

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
    Extract canonical lexical, structural, and statistical features from a raw URL string.
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

    # Letters & Digits in URL
    letters = sum(1 for c in url_norm if c.isalpha())
    digits = sum(1 for c in url_norm if c.isdigit())
    letter_ratio = letters / url_length if url_length > 0 else 0.0
    digit_ratio = digits / url_length if url_length > 0 else 0.0
    
    # Domain specific digits and hyphens
    digits_in_domain = sum(1 for c in domain_clean if c.isdigit())
    hyphens_in_domain = domain_clean.count('-')
    
    # Specific characters
    no_of_equals = url_norm.count('=')
    no_of_qmark = url_norm.count('?')
    no_of_ampersand = url_norm.count('&')
    
    # Obfuscation: hex percent-encoding or authority credentials masking
    has_at_symbol = 1 if '@' in parsed.netloc else 0
    obfuscated_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url_norm)) + (1 if has_at_symbol else 0)
    has_obfuscation = 1 if obfuscated_chars > 0 else 0
    obfuscation_ratio = obfuscated_chars / url_length if url_length > 0 else 0.0
    
    # Special characters (excluding scheme and standard path delimiters)
    special_symbols = sum(1 for c in url_norm if not c.isalnum() and c not in ['/', ':', '.'])
    special_symbol_ratio = special_symbols / url_length if url_length > 0 else 0.0
    
    # Advanced lexical features
    entropy = calculate_entropy(url_norm)
    domain_entropy = calculate_entropy(domain_clean)
    
    # Domain-anchored char continuation rate:
    # Evaluates character runs on the domain to avoid penalizing long legitimate paths
    char_continuation_rate = calculate_char_continuation_rate(domain_clean)
    
    # Additional flags
    has_double_slash_path = 1 if '//' in parsed.path else 0
    
    # Suspicious TLD detection
    tld_lower = str(tld).lower().lstrip('.')
    is_suspicious_tld = 1 if tld_lower in SUSPICIOUS_TLDS else 0
    
    # Keyword detection: match delimited tokens rather than accidental substrings
    # (e.g. 'security' inside 'cybersecurity' shouldn't falsely trigger)
    url_lower = url_norm.lower()
    domain_lower = domain_clean.lower()
    suspicious_keyword_in_domain = sum(
        1 for kw in SUSPICIOUS_KEYWORDS 
        if re.search(r'(?:^|[-._0-9])' + re.escape(kw) + r'(?:[-._0-9]|$)', domain_lower)
    )
    suspicious_keyword_count = sum(
        1 for kw in SUSPICIOUS_KEYWORDS 
        if re.search(r'(?:^|[/._?=&%#+ -])' + re.escape(kw) + r'(?:[/._?=&%#+ -]|$)', url_lower)
    )
    
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
        'SuspiciousKeywordCount': float(suspicious_keyword_count),
        'DigitsInDomain': float(digits_in_domain),
        'SuspiciousKeywordInDomain': float(suspicious_keyword_in_domain),
        'IsSuspiciousTLD': int(is_suspicious_tld),
        'DomainEntropy': float(domain_entropy)
    }
    
    return features
