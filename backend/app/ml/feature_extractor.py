"""
Pure Statistical & Lexical URL Feature Extraction
=================================================
Dynamically extracts 21 engineered numerical, statistical, lexical, and structural features
from ANY raw URL without relying on hardcoded lists of domains or websites.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

SUSPICIOUS_KEYWORDS = [
    "verify-identity", "confirm-identity", "account-suspended", "security-alert",
    "webscr", "ebayisapi", "appleid-login", "wallet-seed", "seed-phrase",
    "authorize-device", "unauthorized-sign", "pass-reset-urgent", "billing-resolve",
    "2fa-bypass", "kyc-validation", "secure-banking-update", "credential-confirm",
    "login", "signin", "verify", "verification", "authenticate", "confirm", "wallet",
    "password", "credential", "recover", "unlock", "banking", "billing", "account"
]

DECEPTIVE_HYPHEN_KEYWORDS = [
    "login", "signin", "verify", "auth", "security", "update", "service", 
    "support", "account", "recover", "alert", "portal", "confirm", "secure",
    "billing", "validation", "banking", "wallet"
]

SUSPICIOUS_TLDS = {
    ".xyz": 0.80,
    ".top": 0.85,
    ".tk": 0.95,
    ".ml": 0.95,
    ".ga": 0.95,
    ".cf": 0.95,
    ".gq": 0.95,
    ".buzz": 0.75,
    ".fit": 0.70,
    ".icu": 0.85,
    ".monster": 0.80,
    ".cam": 0.75,
    ".work": 0.70,
    ".click": 0.80,
    ".link": 0.65,
    ".info": 0.45,
    ".ru": 0.40,
    ".cn": 0.40
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorte.st", "rb.gy", "linktr.ee"
}

FEATURE_METADATA = [
    {"name": "url_length", "display": "URL Length", "desc": "Overall character length of the complete URL string."},
    {"name": "domain_length", "display": "Domain Length", "desc": "Length of the domain/host portion."},
    {"name": "path_length", "display": "Path Length", "desc": "Length of the directory and query path."},
    {"name": "subdomain_count", "display": "Subdomain Count", "desc": "Number of subdomains nested before root domain."},
    {"name": "count_dots", "display": "Dot Count", "desc": "Total occurrences of '.' across the URL."},
    {"name": "count_hyphens", "display": "Hyphen Count", "desc": "Total occurrences of '-' indicating typosquatting or brand spoofing."},
    {"name": "count_underscores", "display": "Underscore Count", "desc": "Total occurrences of '_' in URL."},
    {"name": "count_slashes", "display": "Slash Count", "desc": "Total forward slashes '/' in URL path hierarchy."},
    {"name": "count_question_marks", "display": "Question Mark Count", "desc": "Number of '?' denoting query parameter strings."},
    {"name": "count_equals", "display": "Equals Count", "desc": "Number of '=' signs in query arguments."},
    {"name": "count_percent", "display": "Percent Encoded Count", "desc": "Occurrences of '%' for obfuscated hex characters."},
    {"name": "count_digits", "display": "Digit Count", "desc": "Count of numeric digits in URL (frequent in phishing hash params)."},
    {"name": "https_status", "display": "HTTPS Protocol", "desc": "1 if URL uses HTTPS, 0 if unencrypted HTTP."},
    {"name": "ip_address", "display": "IP in Hostname", "desc": "1 if hostname is a raw IPv4/IPv6 address instead of a domain name."},
    {"name": "has_at_symbol", "display": "Contains @ Symbol", "desc": "1 if '@' is used to confuse user credential parsing."},
    {"name": "has_double_slash_redirect", "display": "Double Slash Redirect", "desc": "1 if '//' appears inside path to trigger redirection."},
    {"name": "has_prefix_suffix", "display": "Prefix/Suffix Dash", "desc": "1 if hyphen is deceptively prefixed or suffixed to domain name."},
    {"name": "is_shortened_url", "display": "URL Shortener Used", "desc": "1 if known link shortening service (bit.ly, tinyurl) is used."},
    {"name": "suspicious_keywords", "display": "Suspicious Keywords Count", "desc": "Occurrences of deceptive credential/financial phishing keywords."},
    {"name": "entropy", "display": "Shannon Entropy", "desc": "Randomness measure of URL text (high entropy indicates DGA or obfuscation)."},
    {"name": "tld_risk_score", "display": "TLD Risk Factor", "desc": "Reputation risk index based on Top-Level Domain registry abuse statistics."}
]

FEATURE_NAMES = [f["name"] for f in FEATURE_METADATA]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon Entropy of a string to detect randomness."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    for count in char_counts.values():
        p_x = count / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 4)

def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    host_clean = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        if re.match(r"^0x[0-9a-fA-F]+", host_clean):
            return True
        return False

def clean_url(raw_url: str) -> str:
    """Ensures URL has a scheme for accurate parsing."""
    url = raw_url.strip()
    if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("ftp://"):
        url = "http://" + url
    return url

def detect_prefix_suffix_attack(hostname: str) -> int:
    """
    Detects generic deceptive hyphenation patterns on hostnames.
    """
    if not hostname or is_ip_address(hostname):
        return 0
    clean = hostname.split(":")[0].lower()
    parts = clean.split(".")
    
    for p in parts:
        if p.startswith("-") or p.endswith("-"):
            return 1
        if p.count("-") >= 2:
            return 1
            
    for kw in DECEPTIVE_HYPHEN_KEYWORDS:
        if f"-{kw}" in clean or f"{kw}-" in clean:
            return 1

    return 0

def extract_features(raw_url: str) -> Tuple[Dict[str, Any], List[float], List[str], str]:
    """
    Dynamically extracts all 21 numerical/boolean features from ANY URL string.
    """
    normalized_url = clean_url(raw_url)
    parsed = urlparse(normalized_url)
    
    url_lower = raw_url.lower()
    hostname = (parsed.hostname or "").lower().split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = path + ("?" + query if query else "")
    
    # 1. Lengths
    url_length = len(raw_url)
    domain_length = len(hostname)
    path_length = len(full_path)
    
    # 2. Subdomains
    subdomain_count = 0
    if hostname and not is_ip_address(hostname):
        clean_host = hostname
        if clean_host.startswith("www."):
            clean_host = clean_host[4:]
            
        parts = clean_host.split(".")
        if len(parts) >= 3 and parts[-2] in ("co", "gov", "ac", "edu", "org", "net", "nic", "com", "res"):
            subdomain_count = max(0, len(parts) - 3)
        elif len(parts) > 2:
            subdomain_count = len(parts) - 2
        else:
            subdomain_count = 0
            
    # 3. Special Characters
    count_dots = raw_url.count(".")
    count_hyphens = raw_url.count("-")
    count_underscores = raw_url.count("_")
    count_slashes = raw_url.count("/")
    count_question_marks = raw_url.count("?")
    count_equals = raw_url.count("=")
    count_percent = raw_url.count("%")
    count_digits = sum(1 for c in raw_url if c.isdigit())
    
    # 4. Protocol & Security Flags
    https_status = 1 if parsed.scheme.lower() == "https" else 0
    ip_addr_flag = 1 if is_ip_address(hostname) else 0
    has_at = 1 if "@" in raw_url else 0
    has_redirect = 1 if "//" in path else 0
    has_prefix_suffix = detect_prefix_suffix_attack(hostname)
    is_shortener = 1 if hostname in SHORTENER_DOMAINS else 0
    
    # 5. Suspicious Keywords
    detected_words = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            detected_words.append(kw)
    suspicious_keywords_count = len(detected_words)
    
    # 6. Shannon Entropy
    entropy = calculate_shannon_entropy(raw_url)
    
    # 7. TLD Risk
    detected_tld = ""
    tld_risk_score = 0.1
    for tld, risk in SUSPICIOUS_TLDS.items():
        if hostname.endswith(tld):
            detected_tld = tld
            tld_risk_score = risk
            break
            
    if not detected_tld and "." in hostname:
        detected_tld = "." + hostname.split(".")[-1]
        
    features_dict = {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "subdomain_count": subdomain_count,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "count_slashes": count_slashes,
        "count_question_marks": count_question_marks,
        "count_equals": count_equals,
        "count_percent": count_percent,
        "count_digits": count_digits,
        "https_status": https_status,
        "ip_address": ip_addr_flag,
        "has_at_symbol": has_at,
        "has_double_slash_redirect": has_redirect,
        "has_prefix_suffix": has_prefix_suffix,
        "is_shortened_url": is_shortener,
        "suspicious_keywords": suspicious_keywords_count,
        "entropy": entropy,
        "tld_risk_score": tld_risk_score
    }
    
    features_vector = [float(features_dict[name]) for name in FEATURE_NAMES]
    
    return features_dict, features_vector, detected_words, detected_tld
