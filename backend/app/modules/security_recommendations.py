"""
MODULE 10: Security Recommendation Module
==========================================
Responsible for:
- Generating dynamic, context-aware cybersecurity recommendations and remediation steps.
- Analyzing threat indicators:
    - Insecure HTTP protocol
    - IP address hostname host evasion
    - Credential harvest keywords
    - Brand typosquatting and impersonation
    - Deceptive subdomain structures & high-risk TLDs
    - Compromised or self-signed SSL/TLS certificates
- Structuring guidance into 4 prioritized remediation tiers:
    1. Immediate User Action (immediate safety steps for end-users)
    2. Endpoint & Browser Defense (session isolation, MFA, cache purge)
    3. SOC & Enterprise Containment (firewall block rules, DNS sinkholing, SIEM alerts)
    4. Educational Awareness (tactical explanation of the attack vector)
"""

from typing import Dict, Any, List, Optional

class SecurityRecommendationEngine:
    """
    Module 10 Core Class: Generates tailored security advice based on prediction telemetry.
    """

    @classmethod
    def generate_recommendations(
        cls,
        risk_level: str,
        features_dict: Dict[str, Any],
        domain: str = "",
        threat_intel: Optional[Any] = None,
        detected_words: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Synthesizes detection results into actionable security advice.
        """
        recs = []
        detected_words = detected_words or []

        # 1. Critical & High Risk Playbooks
        if risk_level in ["Critical", "High"]:
            recs.append({
                "category": "Immediate User Action",
                "priority": "CRITICAL",
                "icon": "ShieldAlert",
                "title": "Do NOT Enter Credentials or Sensitive Information",
                "action": "Immediately close the browser tab. Under no circumstances should you input passwords, 2FA tokens, or financial details on this destination.",
                "details": f"The URL displays active indicators of deceptive phishing targeting {domain or 'untrusted infrastructure'}."
            })

            recs.append({
                "category": "Endpoint & Browser Defense",
                "priority": "HIGH",
                "icon": "Lock",
                "title": "Isolate Active Sessions & Reset Potentially Compromised Accounts",
                "action": "If you previously entered credentials on this site, immediately navigate to the legitimate official website directly (by manually typing the verified domain) and update your password. Enable multi-factor authentication (MFA/FIDO2).",
                "details": "Credential harvesters typically attempt automated login within seconds of submission."
            })

            recs.append({
                "category": "SOC & Enterprise Containment",
                "priority": "HIGH",
                "icon": "Server",
                "title": "Enforce DNS Sinkholing & Perimeter Firewall Block",
                "action": f"Block outbound traffic to domain '{domain}' across corporate firewalls, secure web gateways (SWG), and DNS resolvers.",
                "details": f"Domain IOC: {domain}. Recommend logging all recent egress DNS lookups to audit impacted endpoints."
            })

        # 2. Specific Indicator Guidance
        if features_dict.get("ip_address", 0) == 1:
            recs.append({
                "category": "Indicator Specific",
                "priority": "HIGH",
                "icon": "Network",
                "title": "Raw IP Address Host Evasion Detected",
                "action": "Legitimate enterprise services almost never route users directly to raw IP addresses for authentication. Treat this host as highly untrusted.",
                "details": "Attackers deploy bare IP addresses to circumvent standard domain reputation blacklists."
            })

        if features_dict.get("https_status", 1) == 0:
            recs.append({
                "category": "Indicator Specific",
                "priority": "MEDIUM",
                "icon": "AlertTriangle",
                "title": "Unencrypted HTTP Protocol",
                "action": "Never transmit credentials, cookies, or session tokens over unencrypted HTTP. Data is exposed in cleartext to network eavesdroppers.",
                "details": "Ensure all sensitive web endpoints enforce HTTPS with valid TLS 1.3 encryption."
            })

        if features_dict.get("has_prefix_suffix", 0) == 1 or features_dict.get("subdomain_count", 0) >= 3:
            recs.append({
                "category": "Indicator Specific",
                "priority": "MEDIUM",
                "icon": "FileQuestion",
                "title": "Deceptive Subdomain / Brand Typosquatting Alert",
                "action": "Inspect the root domain carefully before trusting any branded logo on the web page. Attackers often prefix legitimate brand names to foreign root domains.",
                "details": f"Check that the domain truly terminates at the verified brand suffix, not a deceptive multi-tier subdomain."
            })

        if features_dict.get("is_shortened_url", 0) == 1:
            recs.append({
                "category": "Indicator Specific",
                "priority": "MEDIUM",
                "icon": "ExternalLink",
                "title": "Opaque Link Shortener Used",
                "action": "Use an unshortening inspection proxy or preview tool before following shortened links received in unsolicited messages.",
                "details": "Shorteners mask the true destination URL, bypassing lexical email filters."
            })

        # 3. Medium & Low Risk Guidance
        if risk_level == "Medium" and not recs:
            recs.append({
                "category": "Advisory",
                "priority": "MEDIUM",
                "icon": "AlertCircle",
                "title": "Exercise Caution with Unusual URL Structures",
                "action": "Verify the authenticity of the sender who provided this link before proceeding.",
                "details": "The link contains some abnormal structural parameters that warrant user vigilance."
            })

        # 4. Safe Guidance
        if risk_level in ["Safe", "Low"] and len(recs) == 0:
            recs.append({
                "category": "General Hygiene",
                "priority": "INFO",
                "icon": "CheckCircle2",
                "title": "Domain Appears Legitimate & Verified",
                "action": "Standard browsing precautions apply. Always verify that the browser address bar displays a valid TLS padlock.",
                "details": f"No anomalous evasion features or blacklisted patterns detected for {domain}."
            })

        return recs
