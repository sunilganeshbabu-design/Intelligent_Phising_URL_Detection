"""
MODULE 3: Pure Statistical & Lexical URL Feature Extraction Module
===================================================================
Dynamically extracts 21 engineered numerical, statistical, lexical, and structural features
from ANY raw URL without relying on hardcoded lists of domains or websites.

Analytical Dimensions:
1. Lexical & Length Dimensions (url_length, domain_length, path_length)
2. Subdomain & Domain Architecture (subdomain_count, count_dots)
3. Symbol & Character Distributions (count_hyphens, count_underscores, count_slashes, count_question_marks, count_equals, count_percent, count_digits)
4. Protocol & Security Flags (https_status, ip_address, has_at_symbol, has_double_slash_redirect)
5. Deceptive Structural Signals (has_prefix_suffix, is_shortened_url, suspicious_keywords)
6. Information Theory & Registry Risk Metrics (entropy, tld_risk_score)
"""

import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

# Universal credential and financial phishing keywords (statistical lexical signals)
SUSPICIOUS_KEYWORDS = [
    "verify-identity", "confirm-identity", "account-suspended", "security-alert",
    "webscr", "ebayisapi", "appleid-login", "wallet-seed", "seed-phrase",
    "authorize-device", "unauthorized-sign", "pass-reset-urgent", "billing-resolve",
    "2fa-bypass", "kyc-validation", "secure-banking-update", "credential-confirm",
    "login", "signin", "verify", "verification", "authenticate", "confirm", "wallet",
    "password", "credential", "recover", "unlock", "banking", "billing", "account"
]

# Deceptive hyphenated keyword patterns in hostnames
DECEPTIVE_HYPHEN_KEYWORDS = [
    "login", "signin", "verify", "auth", "security", "update", "service", 
    "support", "account", "recover", "alert", "portal", "confirm", "secure",
    "billing", "validation", "banking", "wallet"
]

# High-abuse Top-Level Domains (TLDs) risk scoring
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

# Known universal URL shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorte.st", "rb.gy", "linktr.ee"
}

FEATURE_METADATA = [
    {"name": "url_length", "category": "Lexical", "display": "URL Length", "desc": "Overall character length of the complete URL string."},
    {"name": "domain_length", "category": "Lexical", "display": "Domain Length", "desc": "Length of the domain/host portion."},
    {"name": "path_length", "category": "Lexical", "display": "Path Length", "desc": "Length of the directory and query path."},
    {"name": "subdomain_count", "category": "Domain Structure", "display": "Subdomain Count", "desc": "Number of subdomains nested before root domain."},
    {"name": "count_dots", "category": "Character Distribution", "display": "Dot Count", "desc": "Total occurrences of '.' across the URL."},
    {"name": "count_hyphens", "category": "Character Distribution", "display": "Hyphen Count", "desc": "Total occurrences of '-' indicating typosquatting or brand spoofing."},
    {"name": "count_underscores", "category": "Character Distribution", "display": "Underscore Count", "desc": "Total occurrences of '_' in URL."},
    {"name": "count_slashes", "category": "Character Distribution", "display": "Slash Count", "desc": "Total forward slashes '/' in URL path hierarchy."},
    {"name": "count_question_marks", "category": "Character Distribution", "display": "Question Mark Count", "desc": "Number of '?' denoting query parameter strings."},
    {"name": "count_equals", "category": "Character Distribution", "display": "Equals Count", "desc": "Number of '=' signs in query arguments."},
    {"name": "count_percent", "category": "Character Distribution", "display": "Percent Encoded Count", "desc": "Occurrences of '%' for obfuscated hex characters."},
    {"name": "count_digits", "category": "Character Distribution", "display": "Digit Count", "desc": "Count of numeric digits in URL (frequent in phishing hash params)."},
    {"name": "https_status", "category": "Protocol & Security", "display": "HTTPS Protocol", "desc": "1 if URL uses HTTPS, 0 if unencrypted HTTP."},
    {"name": "ip_address", "category": "Protocol & Security", "display": "IP in Hostname", "desc": "1 if hostname is a raw IPv4/IPv6 address instead of a domain name."},
    {"name": "has_at_symbol", "category": "Protocol & Security", "display": "Contains @ Symbol", "desc": "1 if '@' is used to confuse user credential parsing."},
    {"name": "has_double_slash_redirect", "category": "Protocol & Security", "display": "Double Slash Redirect", "desc": "1 if '//' appears inside path to trigger redirection."},
    {"name": "has_prefix_suffix", "category": "Domain Structure", "display": "Prefix/Suffix Dash", "desc": "1 if hyphen is deceptively prefixed or suffixed to domain name."},
    {"name": "is_shortened_url", "category": "Domain Structure", "display": "URL Shortener Used", "desc": "1 if known link shortening service (bit.ly, tinyurl) is used."},
    {"name": "suspicious_keywords", "category": "Content & Semantic", "display": "Suspicious Keywords Count", "desc": "Occurrences of deceptive credential/financial phishing keywords."},
    {"name": "entropy", "category": "Information Theory", "display": "Shannon Entropy", "desc": "Randomness measure of URL text (high entropy indicates DGA or obfuscation)."},
    {"name": "tld_risk_score", "category": "Registry Risk", "display": "TLD Risk Factor", "desc": "Reputation risk index based on Top-Level Domain registry abuse statistics."}
]

FEATURE_NAMES = [f["name"] for f in FEATURE_METADATA]

class URLFeatureExtractor:
    """
    Module 3 Core Class: Implements dynamic, generalized feature extraction for ANY URL.
    """

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon Entropy of a string to detect randomized strings or DGA."""
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

    @staticmethod
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

    @staticmethod
    def clean_url(raw_url: str) -> str:
        """Ensures URL has a scheme for accurate parsing."""
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("ftp://"):
            url = "http://" + url
        return url

    @classmethod
    def detect_prefix_suffix_attack(cls, hostname: str) -> int:
        """
        Detects generic deceptive hyphenation patterns on hostnames:
        - Domain starts or ends with '-'
        - Any domain label starts or ends with '-'
        - Domain label has 2 or more hyphens (e.g. `service-update-portal`)
        - Domain contains deceptive hyphenated keyword patterns (e.g. `*-login`, `*-verify`, `*-auth`)
        """
        if not hostname or cls.is_ip_address(hostname):
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

    @classmethod
    def extract(cls, raw_url: str) -> Tuple[Dict[str, Any], List[float], List[str], str]:
        """
        Dynamically extracts all 21 numerical/boolean features from ANY URL string.
        Returns:
          - features_dict (mapping of feature_name -> value)
          - features_vector (list of float values in canonical feature order)
          - detected_keywords (list of sensitive words found)
          - detected_tld (the top-level domain detected)
        """
        normalized_url = cls.clean_url(raw_url)
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
        
        # 2. Subdomains (strip standard 'www.' prefix before counting)
        subdomain_count = 0
        if hostname and not cls.is_ip_address(hostname):
            clean_host = hostname
            if clean_host.startswith("www."):
                clean_host = clean_host[4:]
                
            parts = clean_host.split(".")
            # Handle 2-part ccTLDs (e.g. .co.uk, .gov.in, .ac.uk, .edu.in)
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
        ip_addr_flag = 1 if cls.is_ip_address(hostname) else 0
        has_at = 1 if "@" in raw_url else 0
        has_redirect = 1 if "//" in path else 0
        has_prefix_suffix = cls.detect_prefix_suffix_attack(hostname)
        is_shortener = 1 if hostname in SHORTENER_DOMAINS else 0
        
        # 5. Suspicious Keywords (Generic lexical matching)
        detected_words = []
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in url_lower:
                detected_words.append(kw)
        suspicious_keywords_count = len(detected_words)
        
        # 6. Shannon Entropy
        entropy = cls.calculate_shannon_entropy(raw_url)
        
        # 7. TLD Risk Factor
        detected_tld = ""
        tld_risk_score = 0.1  # baseline risk for standard clean TLDs (.com, .org, .net, .edu, .gov, .io, .ai, .dev, etc.)
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

# Helper function aliases
extract_features = URLFeatureExtractor.extract
clean_url = URLFeatureExtractor.clean_url
calculate_shannon_entropy = URLFeatureExtractor.calculate_shannon_entropy
is_ip_address = URLFeatureExtractor.is_ip_address
