"""
MODULE 2: URL Input & Validation Module
=======================================
Responsible for:
- Strict URL syntactical validation (RFC 3986 / WHATWG standards)
- Scheme normalization (handles missing schemes, enforces http/https/ftp)
- Domain and host extraction, port range validation
- Internationalized Domain Name (IDN) / Punycode decoding (detects homograph attacks)
- Decomposition of URL into canonical components (scheme, hostname, port, path, query, fragment)
- Pre-classification security flags (embedded @ symbols, double slash redirects, excessive encoding)
- Batch input validation with granular diagnostic reports per URL
"""

import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Optional, Tuple

URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http://, https://, ftp://, ftps://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)

# Common protocols accepted by the scanner
ALLOWED_SCHEMES = {"http", "https", "ftp", "ftps"}

class URLValidator:
    """
    Module 2 Core Class: Implements URL Input validation, canonicalization,
    and structural integrity checks.
    """

    @staticmethod
    def normalize_scheme(raw_url: str) -> str:
        """
        Normalizes URL scheme, defaulting to 'http://' if no scheme is present.
        """
        cleaned = raw_url.strip()
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
            cleaned = "http://" + cleaned
        return cleaned

    @staticmethod
    def is_valid_ip(host: str) -> Tuple[bool, Optional[str]]:
        """
        Determines whether the hostname is an IPv4 or IPv6 address.
        """
        clean_host = host.split(":")[0].strip("[]")
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            ip_type = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
            return True, ip_type
        except ValueError:
            # Check for hex IP representation (e.g. 0x7f000001)
            if re.match(r"^0x[0-9a-fA-F]+", clean_host):
                return True, "Hex-IPv4"
            return False, None

    @classmethod
    def validate_url(cls, raw_url: str) -> Dict[str, Any]:
        """
        Validates a single URL string and returns comprehensive structural diagnostics.
        """
        if not raw_url or not isinstance(raw_url, str):
            return {
                "is_valid": False,
                "raw_url": raw_url or "",
                "normalized_url": "",
                "error": "URL cannot be empty or non-string",
                "issues": ["Empty URL input"],
                "security_flags": {}
            }

        url_str = raw_url.strip()
        if len(url_str) > 4096:
            return {
                "is_valid": False,
                "raw_url": url_str,
                "normalized_url": "",
                "error": "URL exceeds maximum permitted length of 4096 characters",
                "issues": ["URL length too long"],
                "security_flags": {"oversized": True}
            }

        normalized = cls.normalize_scheme(url_str)
        issues = []
        security_flags = {}

        try:
            parsed = urlparse(normalized)
        except Exception as e:
            return {
                "is_valid": False,
                "raw_url": url_str,
                "normalized_url": normalized,
                "error": f"URL parsing error: {str(e)}",
                "issues": [str(e)],
                "security_flags": {}
            }

        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            issues.append(f"Unsupported protocol scheme: '{scheme}' (supported: http, https, ftp)")

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            issues.append("Missing hostname / domain name in URL")

        # Port validation
        port = parsed.port
        if port is not None:
            if not (1 <= port <= 65535):
                issues.append(f"Invalid port number: {port} (must be 1-65535)")
            if port not in (80, 443, 8080, 8443):
                security_flags["non_standard_port"] = port

        # Check IP hostname
        is_ip, ip_type = cls.is_valid_ip(hostname)
        if is_ip:
            security_flags["is_ip_address"] = True
            security_flags["ip_type"] = ip_type

        # Check Punycode / IDN Homograph
        if "xn--" in hostname:
            security_flags["is_punycode"] = True
            try:
                decoded_idn = hostname.encode("utf-8").decode("idna")
                security_flags["decoded_idn"] = decoded_idn
            except Exception:
                security_flags["decoded_idn"] = "Invalid IDN encoding"

        # Check pre-@ credentials
        if "@" in normalized:
            security_flags["contains_at_symbol"] = True

        # Check double slash in path (redirect evasion)
        path = parsed.path or ""
        if "//" in path:
            security_flags["double_slash_in_path"] = True

        # Check percent encoding obfuscation
        percent_count = normalized.count("%")
        if percent_count >= 3:
            security_flags["heavy_percent_encoding"] = percent_count

        # Regex format test
        is_regex_match = bool(URL_REGEX.match(normalized))
        if not is_regex_match and not is_ip:
            if "." not in hostname and hostname != "localhost":
                issues.append("Hostname must contain a valid top-level domain (e.g. .com, .org)")

        is_valid = len(issues) == 0

        return {
            "is_valid": is_valid,
            "raw_url": url_str,
            "normalized_url": normalized,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "fragment": parsed.fragment or "",
            "is_ip": is_ip,
            "issues": issues,
            "security_flags": security_flags
        }

    @classmethod
    def validate_batch(cls, raw_urls: List[str]) -> Dict[str, Any]:
        """
        Validates a batch of URLs and aggregates batch statistics.
        """
        results = []
        valid_count = 0
        invalid_count = 0

        for url in raw_urls:
            val_res = cls.validate_url(url)
            if val_res["is_valid"]:
                valid_count += 1
            else:
                invalid_count += 1
            results.append(val_res)

        return {
            "total": len(raw_urls),
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "results": results
        }
