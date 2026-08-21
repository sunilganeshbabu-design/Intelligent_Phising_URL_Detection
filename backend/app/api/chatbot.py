import os
import re
import math
import logging
import json
import requests
from typing import Dict, Any, List, Optional, Tuple
from fastapi import APIRouter
from urllib.parse import urlparse
from ..models.schemas import ChatbotQuery, ChatbotResponse
from ..ml.feature_extractor import extract_features, clean_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/chatbot", tags=["AI Security Chatbot"])

# =====================================================================
# 📚 COMPREHENSIVE CYBERSECURITY & EXPLAINABLE AI KNOWLEDGE REPOSITORY
# =====================================================================

KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    # ------------------ FUNDAMENTAL CYBERSECURITY & THREAT CONCEPTS ------------------
    "cybersecurity_fundamentals": {
        "title": "Cybersecurity Fundamentals & The CIA Triad",
        "category": "fundamentals",
        "keywords": ["cybersecurity", "cyber security", "fundamentals", "basics of security", "cia triad", "confidentiality", "integrity", "availability", "defense in depth", "security posture", "cyber safety"],
        "summary": "Cybersecurity is the practice of protecting systems, networks, and data from digital attacks, centered around Confidentiality, Integrity, and Availability (the CIA Triad).",
        "content": (
            "### 🛡️ Cybersecurity Fundamentals & Core Principles\n\n"
            "**Cybersecurity** encompasses the technologies, processes, and controls designed to protect systems, networks, programs, devices, and data from cyber attacks, unauthorized access, and disruption.\n\n"
            "#### 1. The Core Pillar: The CIA Triad\n"
            "• **Confidentiality**: Ensuring sensitive information is accessible only to authorized individuals (implemented via AES-256 encryption, access control lists, and MFA).\n"
            "• **Integrity**: Safeguarding the accuracy and completeness of data against unauthorized modification or tampering (enforced via cryptographic hashes like SHA-256 and digital signatures).\n"
            "• **Availability**: Ensuring authorized users have timely and reliable access to critical assets and services (maintained via DDoS mitigation, redundant cloud architecture, and automated backups).\n\n"
            "#### 2. Defense-in-Depth Strategy\n"
            "A layered security architecture that prevents a single point of failure by deploying perimeter firewalls, network segmentation, endpoint detection and response (EDR), identity governance, and continuous telemetry monitoring.\n\n"
            "#### 3. How PhishGuard Enforces Cyber Hygiene:\n"
            "PhishGuard addresses the initial access vector (deceptive links and social engineering) by inspecting URLs using a 21-feature machine learning classifier coupled with SHAP and LIME Explainable AI."
        ),
        "actions": ["What is Phishing?", "Explain the CIA Triad", "What is Zero Trust Architecture?", "What is Social Engineering?"]
    },

    "phishing_overview": {
        "title": "Phishing Attacks & Deception Mechanics",
        "category": "attack_vectors",
        "keywords": ["phishing", "phish", "what is phishing", "phishing attack", "how does phishing work", "phishing links", "credential harvesting", "phishing scam", "fake website", "phisher", "phishing email", "why are phishing links dangerous", "explain phishing"],
        "summary": "Phishing is a social engineering attack where cyber adversaries impersonate trusted entities to deceive victims into handing over credentials, financial data, or downloading malware.",
        "content": (
            "### 🎣 Phishing Attacks: Anatomy & Deception Mechanics\n\n"
            "**Phishing** is the most prevalent form of social engineering where cyber adversaries impersonate trusted organizations (banks, cloud providers, streaming services, employers) to trick victims into divulging sensitive credentials, session tokens, or payment card details.\n\n"
            "#### How Phishing Operates in 4 Core Stages:\n"
            "1. **Reconnaissance & Lure Creation**: Attackers clone authentic login portals (e.g. Microsoft 365, Google, PayPal) and craft high-urgency lures (*'Account Suspended'*, *'Unauthorized $1,500 Payment'*, *'Password Reset Required'*).\n"
            "2. **Delivery Vector**: Delivered via deceptive emails, SMS (*Smishing*), QR codes (*Quishing*), voice calls (*Vishing*), or malicious search ads (*SEO Poisoning*).\n"
            "3. **Deceptive Evasion**: Malicious URLs employ typosquatting (`paypa1.com`), subdomain stacking (`paypal.com.security-verify.xyz`), raw IP hosts, or AitM reverse proxies.\n"
            "4. **Credential Exfiltration & Session Theft**: When the victim submits credentials or 2FA codes, they are captured in real-time and exfiltrated to the attacker's command-and-control (C2) server.\n\n"
            "#### How PhishGuard AI Detects Phishing:\n"
            "PhishGuard extracts **21 structural, lexical, and statistical features** (including Shannon entropy, subdomain nesting, and protocol heuristics) and passes them through a high-precision **XGBoost model** with **SHAP / LIME Explainable AI** proof."
        ),
        "actions": ["What is Spear Phishing?", "Explain 21 Extracted Features", "What is Quishing (QR Phishing)?", "What to do if I clicked a phishing link?"]
    },

    "spear_phishing": {
        "title": "Spear Phishing & Targeted Reconnaissance",
        "category": "attack_vectors",
        "keywords": ["spear phishing", "spearphishing", "targeted phishing", "targeted attack", "reconnaissance", "osint", "customized email", "tailored lure"],
        "summary": "Spear phishing is a highly personalized phishing attack targeting specific individuals or organizations using open-source intelligence (OSINT).",
        "content": (
            "### 🎯 Spear Phishing: Targeted Social Engineering\n\n"
            "Unlike broad phishing campaigns that send generic emails to millions of recipients, **Spear Phishing** is a highly customized attack targeting specific individuals, executives, or departments within an organization.\n\n"
            "#### Key Characteristics of Spear Phishing:\n"
            "• **OSINT Reconnaissance**: Attackers research victims on LinkedIn, Twitter, company websites, and public data breaches to uncover job titles, colleagues, software vendors, and project names.\n"
            "• **Tailored Context**: Emails cite actual project codenames, vendor invoices, or internal jargon to establish instant credibility.\n"
            "• **High Success Rate**: Because the email appears contextually authentic, victims are much more likely to open attachments or click links.\n\n"
            "#### Defensive Measures:\n"
            "1. Implement DMARC/DKIM/SPF email authentication.\n"
            "2. Conduct periodic simulated spear-phishing drills.\n"
            "3. Enforce out-of-band verification for fund transfers and credential changes."
        ),
        "actions": ["What is Whaling?", "What is Business Email Compromise (BEC)?", "What is Smishing & Vishing?", "Cybersecurity protection tips"]
    },

    "whaling": {
        "title": "Whaling (CEO Fraud & Executive Targeting)",
        "category": "attack_vectors",
        "keywords": ["whaling", "whale phishing", "ceo fraud", "executive phishing", "c-suite", "board of directors", "high value target", "wire transfer scam"],
        "summary": "Whaling is a specialized spear phishing attack targeting high-profile executives (C-suite, board members) to authorize high-value wire transfers or leak trade secrets.",
        "content": (
            "### 🐋 Whaling (Executive Targeting & CEO Fraud)\n\n"
            "**Whaling** is a specialized category of spear phishing aimed specifically at senior executives, board members, CFOs, and government officials (*the 'big fish'*).\n\n"
            "#### Typical Whaling Scenarios:\n"
            "• **Urgent Wire Transfer Requests**: The attacker impersonates the CEO and instructs the finance department to urgently wire funds for a confidential acquisition.\n"
            "• **Legal & Regulatory Inquiries**: Fake subpoenas or tax notices purportedly from government agencies demanding corporate filings.\n"
            "• **HR & Payroll Exfiltration**: Requests for employee W-2 forms or payroll databases.\n\n"
            "#### Prevention & Defense:\n"
            "• Mandatory multi-person authorization for financial transfers exceeding specified thresholds.\n"
            "• Strict verification through independent verbal communication channels."
        ),
        "actions": ["What is Spear Phishing?", "What is Social Engineering?", "What is Zero Trust?", "Email Security Best Practices"]
    },

    "smishing_vishing": {
        "title": "Smishing (SMS Phishing) & Vishing (Voice Phishing)",
        "category": "attack_vectors",
        "keywords": ["smishing", "vishing", "sms phishing", "voice phishing", "phone phishing", "caller id spoofing", "text message scam", "ai voice clone", "deepfake voice"],
        "summary": "Smishing uses SMS text messages and Vishing uses fraudulent phone calls/voice cloning to trick victims into revealing sensitive information or clicking malicious links.",
        "content": (
            "### 📱 Smishing & Vishing: Mobile Attack Vectors\n\n"
            "#### 1. Smishing (SMS Phishing)\n"
            "Attackers send deceptive text messages masquerading as banks, package delivery couriers (FedEx, USPS), or toll authorities (*'Unpaid toll balance'*, *'Package delivery failed'*).\n"
            "• Messages contain shortened links (`bit.ly`, `.xyz`) leading to credential harvesting pages.\n"
            "• Victims on mobile devices often cannot easily inspect the underlying URL destination.\n\n"
            "#### 2. Vishing (Voice Phishing)\n"
            "Adversaries call victims directly, often using **Caller ID Spoofing** or modern **AI Voice Cloning** to impersonate IT support, banking fraud departments, or family members.\n"
            "• Attackers create high-stress situations (*'Your account is compromised, read me the 6-digit code on your screen'*).\n\n"
            "#### Defense Strategy:\n"
            "• Never click links sent via unsolicited SMS.\n"
            "• Hang up and call your bank or IT department using official phone numbers from their website."
        ),
        "actions": ["What is Quishing (QR Phishing)?", "What is Social Engineering?", "How to identify a phishing URL?", "What is 2FA Bypass?"]
    },

    "pharming": {
        "title": "Pharming & DNS Poisoning",
        "category": "attack_vectors",
        "keywords": ["pharming", "dns poisoning", "dns spoofing", "hosts file", "dns cache poisoning", "domain hijacking", "resolver attack"],
        "summary": "Pharming redirects users from legitimate websites to fraudulent clones by corrupting DNS resolution tables or local hosts files, even when the user types the exact correct URL.",
        "content": (
            "### 🌐 Pharming: DNS Poisoning & Traffic Redirection\n\n"
            "**Pharming** is a sophisticated cyber attack where victims are redirected to a fraudulent website without their knowledge, even when they type the authentic web address correctly in their browser.\n\n"
            "#### How Pharming Works:\n"
            "1. **DNS Cache Poisoning**: Attackers exploit vulnerabilities in DNS recursive servers to inject false IP mappings (e.g. mapping `bank.com` to the attacker's IP `198.51.100.23`).\n"
            "2. **Host File Manipulation**: Malware modifies the local `C:\\Windows\\System32\\drivers\\etc\\hosts` file on the victim's device.\n"
            "3. **Router DNS Hijacking**: Attackers compromise default Wi-Fi router passwords and change upstream DNS servers to malicious resolvers.\n\n"
            "#### Defense:\n"
            "• Enable **DNSSEC (Domain Name System Security Extensions)** to validate cryptographic DNS signatures.\n"
            "• Use secure encrypted DNS protocols like **DoH (DNS over HTTPS)** or **DoT (DNS over TLS)**.\n"
            "• Always verify valid SSL/TLS certificates and issuer identity."
        ),
        "actions": ["What is DNS Spoofing?", "What is HTTPS vs HTTP?", "What is Man-in-the-Middle (MitM)?", "Explain 21 Features"]
    },

    "social_engineering": {
        "title": "Social Engineering & Psychological Manipulation",
        "category": "attack_vectors",
        "keywords": ["social engineering", "pretexting", "baiting", "scareware", "psychological manipulation", "urgency", "human factor", "manipulation", "social engineer", "tailgating", "human vector"],
        "summary": "Attacks that exploit human psychology—fear, urgency, curiosity, authority, or greed—rather than purely technical software vulnerabilities.",
        "content": (
            "### 🧠 Social Engineering: The Human Vector in Cybersecurity\n\n"
            "**Social Engineering** is the art of manipulating individuals into performing actions or divulging confidential information by exploiting human cognitive biases.\n\n"
            "#### The 6 Primary Psychological Triggers Exploited by Attackers:\n"
            "1. ⚡ **Urgency & Panic**: *'Your account will be permanently deleted in 24 hours unless you verify now.'*\n"
            "2. 👑 **Authority**: Impersonating executive management (CEO Fraud), legal authorities (IRS), or IT administrators.\n"
            "3. 🎁 **Greed / Baiting**: Offering free gift cards, cryptocurrency airdrops, or infected USB drives left in parking lots.\n"
            "4. 😨 **Fear & Intimidation**: Falsely claiming that illegal activity or malware was detected on your computer.\n"
            "5. 🤝 **Familiarity / Trust**: Compromising a colleague's email account to send seemingly authentic file attachments.\n"
            "6. ⏳ **Scarcity**: Claiming limited-time access to exclusive discounts or investment returns.\n\n"
            "**Key Defense**: Always verify unexpected requests *out-of-band* using official, verified phone numbers or direct internal communication channels."
        ),
        "actions": ["What is Spear Phishing?", "What is Email Phishing & BEC?", "What is Smishing & Vishing?", "Cybersecurity protection tips"]
    },

    # ------------------ MALWARE & THREAT TYPES ------------------
    "malware_overview": {
        "title": "Malware Types: Ransomware, Spyware, Trojans, Viruses & Worms",
        "category": "malware",
        "keywords": ["malware", "malicious software", "ransomware", "spyware", "trojan", "trojans", "virus", "viruses", "worm", "worms", "botnet", "botnets", "rootkit", "keylogger", "difference between phishing and malware"],
        "summary": "Malware (malicious software) includes ransomware, spyware, Trojans, viruses, worms, and botnets designed to compromise, damage, or gain unauthorized access to systems.",
        "content": (
            "### 🦠 Malware Classification: Taxonomy & Threat Mechanics\n\n"
            "**Malware** (Malicious Software) is any software intentionally designed to cause disruption, damage, unauthorized access, or data theft.\n\n"
            "| Malware Type | Primary Mechanism | Delivery Vector | Impact |\n"
            "| :--- | :--- | :--- | :--- |\n"
            "| **Ransomware** | Encrypts files using AES/RSA; demands crypto ransom | Phishing attachments, RDP exploits | Complete business downtime & data loss |\n"
            "| **Spyware / Keylogger** | Silently logs keystrokes, clipboard, screenshots | Bundled software, drive-by downloads | Credential & identity theft |\n"
            "| **Trojan Horse** | Disguised as legitimate utility (e.g. cracked software) | Phishing links, torrent downloads | Backdoor access & remote command |\n"
            "| **Virus** | Injects code into host executable files; requires execution | Infected USBs, email attachments | File corruption, system instability |\n"
            "| **Worm** | Self-replicating standalone program over network ports | Network vulnerabilities (SMB, EternalBlue) | Rapid lateral infection across networks |\n"
            "| **Botnet** | Network of compromised zombie machines under C2 control | Malware infection, default IoT passwords | Massive DDoS attacks, spam propagation |\n\n"
            "#### Phishing vs Malware:\n"
            "• **Phishing** is a *delivery/deception technique* (tricking the human).\n"
            "• **Malware** is the *malicious payload* (executable code attacking the machine)."
        ),
        "actions": ["What is Ransomware?", "What is a Botnet?", "What is the difference between phishing and malware?", "Cybersecurity protection tips"]
    },

    "ransomware": {
        "title": "Ransomware & Double Extortion Attacks",
        "category": "malware",
        "keywords": ["ransomware", "extortion", "double extortion", "triple extortion", "encrypt", "crypto locker", "decryptor", "ransom", "lockbit", "blackcat"],
        "summary": "Ransomware encrypts victim files and exfiltrates sensitive data, demanding cryptocurrency payments for decryption keys and non-disclosure.",
        "content": (
            "### 🔒 Ransomware: Mechanics & Modern Double Extortion\n\n"
            "**Ransomware** is malicious software that encrypts a victim's files and systems, rendering them inaccessible until a ransom (usually in Bitcoin or Monero) is paid.\n\n"
            "#### Evolution to Multi-Extortion:\n"
            "1. **Single Extortion (Encryption)**: Files locked with AES-256 and asymmetric RSA-4096 key pairs.\n"
            "2. **Double Extortion (Data Exfiltration)**: Attackers steal gigabytes of proprietary data *before* encrypting, threatening public leak on dark web forums if ransom is refused.\n"
            "3. **Triple Extortion (DDoS & Stakeholder Harassment)**: Attackers contact customers, suppliers, and regulators directly to force the victim company into compliance.\n\n"
            "#### Critical Defense: The 3-2-1-1-0 Backup Rule\n"
            "• **3** copies of data, on **2** different media types, with **1** copy kept offsite, **1** copy immutable / offline (air-gapped), and **0** errors on backup recovery tests."
        ),
        "actions": ["What is Malware?", "What is Incident Response?", "How does phishing deliver ransomware?", "Explain Zero Trust Architecture"]
    },

    "password_attacks": {
        "title": "Password Attacks: Brute-Force, Credential Stuffing & Passkeys",
        "category": "authentication",
        "keywords": ["password attacks", "brute force", "bruteforce", "credential stuffing", "dictionary attack", "password spraying", "credential theft", "identity theft", "passkeys", "rainbow tables", "hash cracking"],
        "summary": "Methods adversaries use to compromise passwords and credentials, including brute-force, dictionary attacks, credential stuffing, and password spraying.",
        "content": (
            "### 🔑 Password Attacks: Attack Mechanics & Modern Defense\n\n"
            "#### Common Password Attack Types:\n"
            "1. **Brute-Force Attack**: Systematically attempting every possible combination of letters, numbers, and symbols until the correct password is found.\n"
            "2. **Dictionary Attack**: Testing thousands of common words and known passwords from wordlists (like *RockYou*).\n"
            "3. **Credential Stuffing**: Using automated bots to test millions of username/password pairs leaked in past data breaches across different websites.\n"
            "4. **Password Spraying**: Attempting a few common passwords (e.g. `Winter2026!`) against thousands of enterprise usernames to evade account lockout policies.\n"
            "5. **Rainbow Table Attack**: Using precomputed tables of cryptographic hashes to reverse unsalted passwords.\n\n"
            "#### Modern Defense Paradigm:\n"
            "• **FIDO2 Passkeys & WebAuthn**: Cryptographic public-key pairs that are physically immune to phishing and credential stuffing.\n"
            "• **Password Managers**: Generate and store unique 20+ character random passphrases.\n"
            "• **Bcrypt / Argon2 Password Hashing**: Slow, salted key derivation functions that render offline hash cracking computationally infeasible."
        ),
        "actions": ["What is MFA/2FA?", "Passwords vs 2FA vs Passkeys", "What is Credential Stuffing?", "Cybersecurity best practices"]
    },

    "mfa_2fa_passkeys": {
        "title": "Authentication, MFA, 2FA & FIDO2 Passkeys",
        "category": "authentication",
        "keywords": ["mfa", "2fa", "multi-factor authentication", "two-factor authentication", "passkeys", "fido2", "webauthn", "totp", "sms 2fa", "authenticator app", "yubikey", "hardware token", "evilproxy", "session hijacking", "authentication and authorization"],
        "summary": "Multi-Factor Authentication (MFA) requires two or more independent factors: something you know, something you have, or something you are.",
        "content": (
            "### 🛡️ Authentication: MFA, 2FA & Next-Gen Passkeys\n\n"
            "#### The 3 Authentication Factors:\n"
            "1. **Something You Know**: Password, PIN, security question.\n"
            "2. **Something You Have**: Authenticator app (TOTP), SMS OTP, hardware security key (YubiKey).\n"
            "3. **Something You Are**: Biometrics (fingerprint, Face ID, retina scan).\n\n"
            "#### Security Hierarchy of MFA Methods:\n"
            "| MFA Method | Security Level | Vulnerable to Phishing / AitM? |\n"
            "| :--- | :--- | :--- |\n"
            "| **SMS OTP / Voice Call** | ⚠️ Low | Yes (SIM Swapping & Phishing Reverse Proxies) |\n"
            "| **Authenticator App (TOTP)** | ⚡ Moderate | Yes (Adversary-in-the-Middle credential interception) |\n"
            "| **Push Notifications** | ⚡ Moderate | Vulnerable to MFA Fatigue / Prompt Bombing |\n"
            "| **FIDO2 / WebAuthn Passkeys** | 🏆 Gold Standard | **Cryptographically Immune to Phishing** |\n\n"
            "**Why Passkeys are Immune to Phishing**: WebAuthn binds the cryptographic key exchange directly to the browser's verified origin domain (`https://paypal.com`), preventing a fake site (`paypal-login.xyz`) from receiving authentication signatures."
        ),
        "actions": ["How do hackers bypass 2FA?", "What is EvilProxy?", "What is Social Engineering?", "Cybersecurity protection tips"]
    },

    "network_web_security": {
        "title": "Network, Web & Application Security: Firewalls, VPN, IDS/IPS & HTTPS",
        "category": "network_security",
        "keywords": ["network security", "web security", "application security", "cloud security", "mobile security", "data security", "firewall", "firewalls", "vpn", "ids", "ips", "ids/ips", "https", "ssl", "tls", "ssl/tls", "secure browsing", "encryption", "symmetric encryption", "asymmetric encryption", "aes", "rsa"],
        "summary": "Defensive infrastructure securing transport and application layers through Firewalls, VPNs, Intrusion Detection/Prevention, and SSL/TLS encryption.",
        "content": (
            "### 🔒 Network, Web & Transport Layer Security\n\n"
            "#### 1. Firewalls vs IDS/IPS\n"
            "• **Firewall**: Filters incoming and outgoing traffic based on predefined stateful rules, ports, and IP addresses.\n"
            "• **IDS (Intrusion Detection System)**: Passively monitors network traffic for known attack signatures or anomalies and raises alerts.\n"
            "• **IPS (Intrusion Prevention System)**: Actively sits inline with traffic to detect and block malicious packets in real-time.\n\n"
            "#### 2. Virtual Private Network (VPN)\n"
            "Creates an encrypted tunnel (using protocols like WireGuard or OpenVPN) between the client device and a remote server, masking IP addresses and protecting data on untrusted public Wi-Fi.\n\n"
            "#### 3. HTTPS & SSL/TLS Encryption\n"
            "• **TLS (Transport Layer Security)**: Encrypts communication between web browsers and servers using asymmetric cryptography (ECDHE for key exchange) and symmetric cryptography (AES-GCM for bulk data).\n"
            "• **Critical Warning**: **HTTPS alone does NOT mean a website is safe.** Over 80% of modern phishing websites utilize free valid SSL certificates (e.g. Let's Encrypt) to display the padlock icon."
        ),
        "actions": ["Why is HTTPS not enough?", "What is Symmetric vs Asymmetric Encryption?", "What is SQL Injection?", "What is OWASP Top 10?"]
    },

    "web_vulnerabilities": {
        "title": "Web Vulnerabilities: OWASP Top 10, SQLi, XSS, CSRF & SSRF",
        "category": "web_security",
        "keywords": ["vulnerabilities", "vulnerability", "owasp", "owasp top 10", "sqli", "sql injection", "xss", "cross-site scripting", "csrf", "ssrf", "injection", "broken access control", "remote code execution", "rce"],
        "summary": "Exploits targeting application code flaws, including SQL Injection, Cross-Site Scripting (XSS), CSRF, SSRF, and Broken Access Control.",
        "content": (
            "### 💉 Web Application Vulnerabilities & OWASP Top 10\n\n"
            "#### 1. SQL Injection (SQLi)\n"
            "Occurs when untrusted user input is directly concatenated into database queries. Attackers can bypass authentication (`' OR '1'='1`), dump database records, or drop tables.\n"
            "• **Defense**: Use Parameterized Queries / Prepared Statements and ORMs.\n\n"
            "#### 2. Cross-Site Scripting (XSS)\n"
            "Adversaries inject malicious JavaScript into web pages viewed by other users. The script can steal `document.cookie` session tokens or redirect victims to phishing portals.\n"
            "• **Defense**: Contextual output encoding, Content Security Policy (CSP), and `HttpOnly` cookie flags.\n\n"
            "#### 3. Server-Side Request Forgery (SSRF)\n"
            "Tricks the backend server into making unauthorized HTTP requests to internal resources (such as AWS metadata endpoints `http://169.254.169.254`).\n\n"
            "#### 4. Broken Access Control\n"
            "Failing to enforce authorization checks, allowing regular users to access admin endpoints (e.g. changing URL ID parameters to view other users' private scan records)."
        ),
        "actions": ["What is SQL Injection?", "What is XSS?", "What is Zero Trust Architecture?", "Cybersecurity best practices"]
    },

    "incident_response_best_practices": {
        "title": "Incident Response Playbook & Cyber Hygiene Best Practices",
        "category": "defense",
        "keywords": ["incident response", "clicked phishing link", "what should i do if i clicked a phishing link", "what to do if hacked", "compromised account", "cyber hygiene", "security best practices", "how to protect myself from phishing", "protection tips", "how to secure accounts"],
        "summary": "Step-by-step incident containment procedures for compromised credentials and devices, along with everyday cyber hygiene rules.",
        "content": (
            "### 🚨 Incident Response: What to Do If You Clicked a Phishing Link\n\n"
            "If you suspect you entered credentials or downloaded a file from a phishing website, execute this immediate containment playbook:\n\n"
            "#### Immediate Containment Steps:\n"
            "1. 🔒 **Reset Passwords Immediately**: From a *separate, secure device*, change the password for the affected account and any other accounts sharing that password.\n"
            "2. 🚪 **Terminate Active Sessions**: In the account security settings, select *'Log out of all devices and active sessions'* to revoke stolen session cookies.\n"
            "3. 🛡️ **Enable Phishing-Resistant MFA**: Upgrade to an Authenticator app (TOTP) or FIDO2 Passkey.\n"
            "4. 💻 **Isolate & Scan Endpoint**: Disconnect the device from Wi-Fi/Ethernet and run a full antivirus/EDR scan.\n"
            "5. 💳 **Financial Alert**: If credit card or banking details were entered, immediately call your bank's fraud prevention hotline to freeze the card.\n"
            "6. 📢 **Report**: Submit the malicious link to IT security, PhishGuard, and Google Safe Browsing.\n\n"
            "#### Everyday Cyber Hygiene Best Practices:\n"
            "• Inspect the apex domain before typing credentials.\n"
            "• Never trust display names or high-urgency threats.\n"
            "• Use a dedicated password manager to generate unique 20+ character passwords."
        ),
        "actions": ["How to identify a phishing URL?", "Passwords vs 2FA vs Passkeys", "Explain 21 Features", "Is my current URL safe?"]
    },

    # ------------------ INTELLIGENT PHISHING URL DETECTION & FEATURES ------------------
    "url_anatomy_forensics": {
        "title": "URL Structure, Lexical Analysis & Deception Indicators",
        "category": "phishing_detection",
        "keywords": ["url structure", "domain analysis", "subdomain analysis", "url length", "domain length", "path analysis", "query parameters", "special characters", "suspicious keywords", "ip-based urls", "http vs https", "url shortening", "redirects", "typosquatting", "homograph attacks", "brand impersonation", "suspicious domains", "url lexical features", "how can i identify a phishing url"],
        "summary": "Deep lexical, structural, and semantic inspection of URL components used to uncover phishing indicators.",
        "content": (
            "### 🔬 URL Structure & Forensic Phishing Indicators\n\n"
            "A URL consists of: `[scheme]://[subdomains].[domain].[tld]:[port]/[path]?[query]#[fragment]`\n\n"
            "#### Key Deception Vectors Analyzed by PhishGuard:\n"
            "1. **Domain & Subdomain Stacking**: Attackers chain subdomains to mimic legitimate portals (`paypal.com.account-verify.security-update.xyz`). The true destination is the apex domain right before the TLD (`security-update.xyz`).\n"
            "2. **URL & Path Lengths**: Phishing links are frequently over 75 characters long with deep nested directory structures to obscure the destination.\n"
            "3. **Raw IP Hosts**: Direct numerical IPs (`http://192.168.1.100/login`) bypass domain-level reputation blocklists.\n"
            "4. **Special Character Density**: Excessive hyphens (`-`), underscores (`_`), percent encodings (`%20`), and `@` symbols (RFC 1738 userinfo obfuscation).\n"
            "5. **Suspicious Keyword Density**: Words like `login`, `verify`, `update`, `banking`, `secure`, `wallet`, `kyc`, `account` embedded in third-party hostnames.\n"
            "6. **URL Shorteners & Open Redirects**: Services like `bit.ly`, `tinyurl.com`, or `t.co` hide the ultimate destination.\n"
            "7. **Typosquatting & Punycode (IDN Homograph)**: Lookalike domains (`g00gle.com` or Cyrillic `а` in `pаypal.com` encoded as `xn--...`)."
        ),
        "actions": ["Explain 21 Extracted Features", "What is Shannon Character Entropy?", "What is Typosquatting?", "Why is an IP host dangerous?"]
    },

    "features_21_engine": {
        "title": "The 21 Feature Extraction Engine",
        "category": "phishing_detection",
        "keywords": ["21 features", "extracted features", "feature extraction", "lexical features", "feature table", "feature list", "features in phishguard", "what features are extracted"],
        "summary": "PhishGuard extracts 21 quantitative lexical, structural, statistical, and security features from every input URL.",
        "content": (
            "### ⚙️ The 21 Feature Extraction Engine in PhishGuard\n\n"
            "PhishGuard extracts **21 numerical and statistical features** categorized into 4 core analytical dimensions:\n\n"
            "#### 1. Structural & Length Metrics (6 Features)\n"
            "• `url_length`: Total character length of URL ($> 75$ is high risk).\n"
            "• `domain_length`: Total character length of hostname.\n"
            "• `path_length`: Length of URI path component.\n"
            "• `subdomain_count`: Number of dot-separated subdomains ($> 2$ indicates stacking).\n"
            "• `count_slashes`: Number of `/` path delimiters.\n"
            "• `count_dots`: Number of `.` characters across the URL.\n\n"
            "#### 2. Special Characters & Symbol Density (6 Features)\n"
            "• `count_hyphens`: Hyphens (`-`) used in typosquatting.\n"
            "• `count_underscores`: Underscores (`_`) in paths/subdomains.\n"
            "• `count_question_marks`: Query string indicators (`?`).\n"
            "• `count_equals`: Parameter assignments (`=`).\n"
            "• `count_percent`: Percent-encoded hex tokens (`%20`).\n"
            "• `count_digits`: Total numerical digits in the URL.\n\n"
            "#### 3. Protocol, Evasion & Redirection Flags (6 Features)\n"
            "• `https_status`: True (1) if SSL/TLS enabled, False (0) for insecure HTTP.\n"
            "• `ip_address`: True (1) if host is raw numerical IPv4/IPv6.\n"
            "• `has_at_symbol`: True (1) if RFC 1738 `@` userinfo spoofing is detected.\n"
            "• `has_double_slash_redirect`: True (1) if `//` occurs after protocol position.\n"
            "• `has_prefix_suffix`: True (1) if domain contains hyphenated brand prefixes.\n"
            "• `is_shortened_url`: True (1) if domain matches known shorteners (`bit.ly`, `t.co`).\n\n"
            "#### 4. Advanced Semantic & Statistical Metrics (3 Features)\n"
            "• `suspicious_keywords`: Frequency count of security keywords (`login`, `verify`, `banking`, etc.).\n"
            "• `entropy`: Shannon character entropy quantifying character randomness ($> 4.2$ flags DGA botnets).\n"
            "• `tld_risk_score`: Empirical abuse rate of the TLD (`.xyz`, `.top`, `.buzz` vs `.com`, `.gov`)."
        ),
        "actions": ["Explain Shannon Character Entropy", "What is SHAP?", "What is LIME?", "How does Machine Learning detect phishing?"]
    },

    # ------------------ MACHINE LEARNING & EVALUATION ------------------
    "ml_classification_pipeline": {
        "title": "Machine Learning Classification: XGBoost Model & Evaluation",
        "category": "machine_learning",
        "keywords": ["machine learning", "ml", "how does machine learning detect phishing urls", "xgboost", "xgbooster", "xgboost model", "gradient boosting", "training testing datasets", "accuracy", "precision", "recall", "f1-score", "f1 score", "confusion matrix", "false positives", "false negatives", "confidence score", "risk score"],
        "summary": "How the high-performance XGBoost model classifies phishing URLs, balances precision/recall, and computes confidence and risk scores.",
        "content": (
            "### 🤖 Machine Learning Classification in PhishGuard\n\n"
            "PhishGuard utilizes an optimized **XGBoost model (Extreme Gradient Boosting)** machine learning model trained on balanced cybersecurity datasets (from **PhishTank, OpenPhish, APWG, and Alexa Top 1M**).\n\n"
            "#### 1. Primary Classifier Architecture:\n"
            "• **XGBoost model (Primary ~99.4% Acc)**: High-performance gradient boosted decision trees (100 estimators, max depth 6, logloss objective) with second-order gradient optimization.\n\n"
            "#### 2. Performance Metrics & Confusion Matrix:\n"
            "• **Accuracy**: $\\frac{TP + TN}{TP + TN + FP + FN} \\approx 99.4\\%$\n"
            "• **Precision**: $\\frac{TP}{TP + FP} \\approx 99.4\\%$ (minimizes **False Positives** — blocking safe sites).\n"
            "• **Recall**: $\\frac{TP}{TP + FN} \\approx 99.5\\%$ (minimizes **False Negatives** — missing live attacks).\n"
            "• **F1-Score**: Harmonic mean of Precision and Recall ($99.5\\%$).\n"
            "• **Confidence Score**: Absolute certainty of the prediction ($|P - 0.5| \\times 200\\%$).\n"
            "• **Risk Score (0-100)**: Synthesized from ML probability and live network threat intelligence across 5 tiers (**Safe, Low, Medium, High, Critical**)."
        ),
        "actions": ["What is SHAP?", "What is LIME?", "What does the confidence score mean?", "Explain the 10 detection modules."]
    },

    # ------------------ EXPLAINABLE AI (SHAP & LIME) ------------------
    "shap_xai": {
        "title": "SHAP (SHapley Additive exPlanations)",
        "category": "xai",
        "keywords": ["shap", "shapley", "additive", "game theory", "treeexplainer", "waterfall", "base value", "prior probability", "feature contribution", "attribution", "marginal contribution", "what is shap"],
        "summary": "SHAP computes mathematically exact directional feature contributions for every URL feature using cooperative game theory.",
        "content": (
            "### 🧠 SHAP (SHapley Additive exPlanations) in PhishGuard\n\n"
            "**SHAP** is an advanced Explainable AI framework rooted in **cooperative game theory** (Lloyd Shapley, Nobel Memorial Prize 2012).\n\n"
            "#### How SHAP Works in This Project:\n"
            "1. **Baseline Prior ($\\mathbb{E}[f(x)]$ )**: The average background prediction probability of the model (~50% base prior).\n"
            "2. **Marginal Feature Attribution (Shapley Value $\\phi_i$)**: For each of the 21 extracted features, SHAP computes its marginal contribution across all possible feature permutations:\n"
            "   $$\\phi_i = \\sum_{S \\subseteq F \\setminus \\{i\\}} \\frac{|S|!(|F| - |S| - 1)!}{|F|!} (f(S \\cup \\{i\\}) - f(S))$$\n"
            "3. **Directional Impact**:\n"
            "   - **Positive $\\phi_i > 0$ (Red)**: Pushes model prediction toward **Phishing** (e.g. Insecure HTTP `+0.22`, High Entropy `+0.18`, Raw IP `+0.25`).\n"
            "   - **Negative $\\phi_i < 0$ (Green)**: Pushes model prediction toward **Legitimate** (e.g. Valid HTTPS `-0.15`, Clean Established Domain `-0.14`).\n"
            "4. **Additive Efficiency**: The sum of all feature Shapley values plus the base value equals the exact output probability score:\n"
            "   $$f(x) = \\mathbb{E}[f(x)] + \\sum_{i=1}^{M} \\phi_i$$\n\n"
            "**Key Benefit**: Provides mathematical proof for every alert rather than relying on an opaque black-box model."
        ),
        "actions": ["What is LIME?", "What is the difference between SHAP and LIME?", "Explain Feature Importance", "Open What-If Simulator"]
    },

    "lime_xai": {
        "title": "LIME (Local Interpretable Model-agnostic Explanations)",
        "category": "xai",
        "keywords": ["lime", "local interpretable", "surrogate", "perturbation", "linear model", "decision boundary", "proximity weight", "local rules", "what is lime"],
        "summary": "LIME builds local linear surrogate models around individual predictions to extract human-readable decision rules.",
        "content": (
            "### 🔬 LIME (Local Interpretable Model-agnostic Explanations)\n\n"
            "**LIME** explains individual predictions by constructing an interpretable **local surrogate linear model** in the immediate neighborhood of the scanned URL.\n\n"
            "#### How LIME Works in 3 Steps:\n"
            "1. **Local Feature Perturbation**: LIME generates synthetic variations around the target URL by slightly altering feature values (e.g. modifying subdomain count, path length, entropy).\n"
            "2. **Proximity Kernel Weighting**: Samples are weighted by exponential distance kernel $\\pi_x(z) = \\exp(-D(x,z)^2 / \\sigma^2)$ so closer points have higher influence.\n"
            "3. **Linear Surrogate Fitting**: Fits an interpretable ridge regression model to extract local if-then decision rules.\n\n"
            "**Example LIME Decision Rule**:\n"
            "• `subdomain_count > 2.00` $\\rightarrow$ `+0.31` Phishing Risk\n"
            "• `https_status <= 0.00` $\\rightarrow$ `+0.27` Phishing Risk\n"
            "• `entropy > 4.20` $\\rightarrow$ `+0.22` Phishing Risk\n\n"
            "**SHAP vs LIME**: SHAP computes exact cooperative game theoretical credit globally and locally, whereas LIME tests local sensitivity boundaries."
        ),
        "actions": ["What is SHAP?", "What is the difference between SHAP and LIME?", "What is Counterfactual What-If?", "Explain 21 Features"]
    },

    # ------------------ THE 10 DETECTION MODULES ------------------
    "pipeline_10_modules": {
        "title": "The Complete 10-Module Detection Architecture",
        "category": "pipeline",
        "keywords": ["10 modules", "10 detection modules", "ten modules", "pipeline", "architecture", "10-module pipeline", "explain the 10 detection modules", "system architecture", "how does your system detect phishing urls", "project modules"],
        "summary": "PhishGuard's end-to-end 10-module architecture spanning dataset ingestion to remediation playbooks.",
        "content": (
            "### 🌐 PhishGuard's 10-Module Detection Pipeline Architecture\n\n"
            "PhishGuard operates as a tightly integrated **10-module pipeline** designed for maximum detection accuracy, explainability, and forensic auditability:\n\n"
            "| Module # | Module Name | Primary Responsibility |\n"
            "| :--- | :--- | :--- |\n"
            "| **Module 1** | **Dataset Collection & Preprocessing** | Ingests, cleans, deduplicates, and splits balanced benchmark datasets from PhishTank, OpenPhish, and Alexa Top 1M. |\n"
            "| **Module 2** | **URL Input & Validation** | Validates RFC 3986 URL syntax, normalizes protocol schemes, parses hostnames, and detects pre-classification evasion flags. |\n"
            "| **Module 3** | **URL Feature Extraction** | Extracts 21+ numerical, statistical, lexical, and structural features including Shannon entropy and typosquatting. |\n"
            "| **Module 4** | **Feature Preprocessing** | Scales, normalizes (`StandardScaler`), and validates feature matrices against trained ML schemas. |\n"
            "| **Module 5** | **Phishing URL Classification** | Executes multi-model inference (Random Forest, Decision Tree, Logistic Regression, Ensemble) with performance metrics. |\n"
            "| **Module 6** | **Risk & Confidence Analysis** | Synthesizes ML probabilities with live network telemetry into a 0-100 Risk Score across 5 standardized risk tiers. |\n"
            "| **Module 7** | **Explainable AI (XAI)** | Generates game-theoretic SHAP and local surrogate LIME feature attribution waterfall charts and natural language insights. |\n"
            "| **Module 8** | **Feature Importance Analysis** | Computes global Gini feature importance across models and per-prediction local feature rankings. |\n"
            "| **Module 9** | **Detection History & SQLite Persistence** | Manages persistent SQLite storage (WAL mode, foreign keys) for scan telemetry, full feature sets, and execution audit logs. |\n"
            "| **Module 10** | **Security Recommendation Module** | Produces prioritized, actionable remediation playbooks for end-users, SOC analysts, and firewall containment. |"
        ),
        "actions": ["Explain Module 1", "Explain Module 3", "Explain Module 7", "Explain Module 10"]
    },

    "module_1": {
        "title": "Module 1: Dataset Collection & Preprocessing",
        "category": "pipeline",
        "keywords": ["module 1", "module1", "dataset collection", "dataset preprocessing", "benchmark dataset", "phishtank", "openphish", "alexa 1m", "train test split"],
        "summary": "Module 1 generates, ingests, cleans, deduplicates, and splits balanced benchmark datasets for model training.",
        "content": (
            "### 📊 Module 1: Dataset Collection & Preprocessing\n\n"
            "**Purpose**: Ensures high-quality, balanced ground truth data for training and evaluating machine learning models.\n\n"
            "#### Key Operations:\n"
            "1. **Data Ingestion**: Pulls verified malicious URLs from active threat feeds (PhishTank, OpenPhish, APWG) and legitimate URLs from Alexa Top 1M, Majestic 1M, and Tranco.\n"
            "2. **Cleaning & Deduplication**: Strips tracking fragments, normalizes scheme protocols (`http`/`https`), and removes duplicate domain records.\n"
            "3. **Stratified Splitting**: Splits data into balanced 80/20 train/test partitions ensuring proportional representation across TLDs and attack categories.\n"
            "4. **Benchmark Caching**: Persists `phishing_benchmark_dataset.csv` in `backend/data/` for rapid model training."
        ),
        "actions": ["Explain Module 2", "Explain the 10 detection modules.", "How are models retrained?", "Explain Module 5"]
    },

    "module_2": {
        "title": "Module 2: URL Input & Validation",
        "category": "pipeline",
        "keywords": ["module 2", "module2", "url validation", "rfc 3986", "url input", "syntax check", "scheme normalization"],
        "summary": "Module 2 validates RFC 3986 syntax, normalizes protocols, parses hostnames, and detects evasion flags.",
        "content": (
            "### 🔍 Module 2: URL Input & Validation\n\n"
            "**Purpose**: Sanitizes and validates user-submitted URL strings before feature extraction and inference.\n\n"
            "#### Key Operations:\n"
            "1. **RFC 3986 Syntax Verification**: Checks URL structure, port validity, and character encoding.\n"
            "2. **Protocol Normalization**: Automatically prepends default `http://` or `https://` schemes if omitted by the user.\n"
            "3. **Hostname Parsing**: Uses `urllib.parse` and regex to safely isolate scheme, netloc, path, params, query, and fragment.\n"
            "4. **Pre-Scan Evasion Checks**: Detects raw IP address hosts, Punycode markers (`xn--`), and RFC 1738 `@` userinfo tricks."
        ),
        "actions": ["Explain Module 3", "Explain Module 1", "Explain the 10 detection modules.", "What is RFC-1738 @ trick?"]
    },

    "module_3": {
        "title": "Module 3: URL Feature Extraction",
        "category": "pipeline",
        "keywords": ["module 3", "module3", "feature extraction", "extract features", "url feature extractor", "21 features extraction"],
        "summary": "Module 3 computes all 21 lexical, structural, statistical, and security features from the validated URL.",
        "content": (
            "### ⚙️ Module 3: URL Feature Extraction\n\n"
            "**Purpose**: Transforms raw URL strings into a 21-dimensional quantitative feature vector for machine learning analysis.\n\n"
            "#### Extracted Feature Categories:\n"
            "• **Length & Structural**: `url_length`, `domain_length`, `path_length`, `subdomain_count`, `count_slashes`, `count_dots`.\n"
            "• **Special Symbols**: `count_hyphens`, `count_underscores`, `count_question_marks`, `count_equals`, `count_percent`, `count_digits`.\n"
            "• **Evasion & Protocol Flags**: `https_status`, `ip_address`, `has_at_symbol`, `has_double_slash_redirect`, `has_prefix_suffix`, `is_shortened_url`.\n"
            "• **Statistical & Semantic**: `suspicious_keywords`, `entropy` (Shannon randomness), `tld_risk_score`."
        ),
        "actions": ["Explain Module 4", "Explain 21 Features", "Explain Shannon Character Entropy", "Explain Module 5"]
    },


    "module_4": {
        "title": "Module 4: Feature Preprocessing",
        "category": "pipeline",
        "keywords": ["module 4", "module4", "preprocessing", "scaling", "standardscaler", "feature scaler", "normalization"],
        "summary": "Module 4 prepares extracted features for XGBoost model ingestion through ordering, validation, and imputation.",
        "content": (
            "### 🎛️ Module 4: Feature Preprocessing\n\n"
            "**Purpose**: Prepares extracted feature dictionaries for model ingestion by enforcing ordering, scaling, and validation.\n\n"
            "#### Key Operations:\n"
            "1. **Schema Alignment**: Converts feature dictionaries into ordered NumPy arrays matching the exact 21-feature column definition.\n"
            "2. **Feature Scaling & Imputation**: Normalizes numerical metrics and validates input tensor consistency for XGBoost.\n"
            "3. **Missing Value & Boundary Imputation**: Clamps outliers and ensures non-null values across all dimensions."
        ),
        "actions": ["Explain Module 5", "Explain Module 3", "Explain XGBoost Model", "Explain the 10 detection modules."]
    },

    "module_5": {
        "title": "Module 5: Phishing URL Classification",
        "category": "pipeline",
        "keywords": ["module 5", "module5", "phishing classification", "classification module", "inference", "model prediction", "xgboost model", "xgbooster"],
        "summary": "Module 5 runs high-performance XGBoost machine learning inference to classify URLs as Legitimate or Phishing.",
        "content": (
            "### 🤖 Module 5: Phishing URL Classification\n\n"
            "**Purpose**: Executes the trained XGBoost model to classify the URL and generate calibrated probability distributions.\n\n"
            "#### Active Model Engine:\n"
            "• **XGBoost model Classifier**: High-performance gradient boosted decision trees (100 estimators, max depth 6, logloss objective, ~99.4% accuracy).\n\n"
            "#### Outputs:\n"
            "• Binary classification: `\"Phishing\"` or `\"Legitimate\"`.\n"
            "• Exact phishing probability percentage: $P(y=1|x) \\in [0.0, 100.0]\\%$."
        ),
        "actions": ["Explain Module 6", "Explain Module 7", "Explain XGBoost Model", "Explain Confusion Matrix"]
    },

    "module_6": {
        "title": "Module 6: Risk & Confidence Analysis",
        "category": "pipeline",
        "keywords": ["module 6", "module6", "risk analysis", "confidence score", "risk level", "risk confidence analysis", "risk score 0-100"],
        "summary": "Module 6 synthesizes ML probabilities with network intelligence into a 0-100 Risk Score across 5 tiers.",
        "content": (
            "### 🛡️ Module 6: Risk & Confidence Analysis\n\n"
            "**Purpose**: Translates raw ML output probabilities and live threat intelligence into actionable risk tiers and confidence ratings.\n\n"
            "#### 1. Confidence Score Formula:\n"
            "$$\\text{Confidence} = |P(\\text{phishing}) - 0.5| \\times 200\\%$$\n"
            "A probability of 98% yields 96% confidence; a borderline probability of 52% yields 4% confidence.\n\n"
            "#### 2. The 5 Risk Tiers (0-100 Risk Score):\n"
            "• **Safe (0 - 15)**: Clean authenticated domain, valid TLS certificate, zero risk indicators.\n"
            "• **Low Risk (16 - 35)**: Minimal anomalies (e.g. longer path) but reputable authority.\n"
            "• **Medium Risk (36 - 65)**: Multiple suspicious markers (keyword match, high entropy).\n"
            "• **High Risk (66 - 85)**: Strong phishing heuristics (subdomain stacking, untrusted TLD, IP host).\n"
            "• **Critical (86 - 100)**: Active blacklisted threat or confirmed credential harvester clone."
        ),
        "actions": ["Explain Module 7", "Explain Module 5", "What does the confidence score mean?", "Explain the 10 detection modules."]
    },

    "module_7": {
        "title": "Module 7: Explainable AI (XAI) Engine",
        "category": "pipeline",
        "keywords": ["module 7", "module7", "xai module", "explainable ai module", "shap and lime module", "xai engine", "waterfall explanation"],
        "summary": "Module 7 computes cooperative game-theoretic SHAP attributions and LIME local surrogate rules.",
        "content": (
            "### 🧠 Module 7: Explainable AI (XAI) Engine\n\n"
            "**Purpose**: Converts black-box machine learning predictions into mathematically verified, human-interpretable explanations.\n\n"
            "#### XAI Components in Module 7:\n"
            "1. **SHAP (TreeExplainer)**: Computes exact Shapley additive values ($\\phi_i$) showing how each feature shifted probability from the baseline prior.\n"
            "2. **LIME (Local Interpretable Surrogate)**: Generates synthetic local perturbations to extract intuitive if-then decision rules.\n"
            "3. **Natural Language Summarizer**: Automatically translates numerical attributions into plain English security insights for analysts."
        ),
        "actions": ["Explain SHAP", "Explain LIME", "Explain Module 8", "Explain the 10 detection modules."]
    },

    "module_8": {
        "title": "Module 8: Feature Importance Analysis",
        "category": "pipeline",
        "keywords": ["module 8", "module8", "feature importance", "feature importance analysis", "gini importance", "global importance", "xgboost gain"],
        "summary": "Module 8 computes global XGBoost feature importances (gain & weight) and local per-scan importance rankings.",
        "content": (
            "### 📊 Module 8: Feature Importance Analysis\n\n"
            "**Purpose**: Evaluates and ranks which URL characteristics exert the greatest influence on model decisions globally and locally.\n\n"
            "#### Analytical Modes:\n"
            "• **Global Importance (XGBoost Gain & Weight)**: Evaluates the total improvement in accuracy brought by a feature to the branches it is on across all gradient boosted trees.\n"
            "• **Local Feature Ranking**: Ranks the top positive (risk-increasing) and negative (safety-increasing) contributors for the specific scanned URL.\n"
            "• **Interactive Visualizations**: Powers horizontal importance bar charts and SHAP waterfall diagrams in the web UI."
        ),
        "actions": ["Explain Module 9", "Explain Module 7", "Explain 21 Features", "Explain the 10 detection modules."]
    },

    "module_9": {
        "title": "Module 9: Detection History & SQLite Persistence",
        "category": "pipeline",
        "keywords": ["module 9", "module9", "detection history", "database module", "sqlite persistence", "scan history", "url scans table"],
        "summary": "Module 9 manages high-performance SQLite storage (WAL mode) for scan logs, features, and audit trails.",
        "content": (
            "### 🗄️ Module 9: Detection History & SQLite Persistence\n\n"
            "**Purpose**: Provides reliable, relational persistence for all URL scan telemetry, extracted features, and audit logs.\n\n"
            "#### Database Design:\n"
            "• **Engine**: SQLite with Write-Ahead Logging (`WAL` mode) for high concurrent read/write throughput.\n"
            "• **Key Tables**:\n"
            "  - `users`: User profiles, bcrypt password hashes, and roles.\n"
            "  - `url_scans`: Scanned URLs, verdicts, probabilities, risk tiers, SHAP/LIME JSON summaries, and timestamps.\n"
            "  - `url_features`: Full 21-feature raw metrics linked by foreign key (`scan_id`).\n"
            "• **Auditability**: Enables compliance PDF report generation, CSV export, and historical trend dashboards."
        ),
        "actions": ["Explain Module 10", "Explain Module 1", "Explain the 10 detection modules.", "Download PDF Audit Report"]
    },

    "module_10": {
        "title": "Module 10: Security Recommendation Module",
        "category": "pipeline",
        "keywords": ["module 10", "module10", "security recommendations", "remediation module", "actionable recommendations", "security playbook"],
        "summary": "Module 10 generates prioritized remediation playbooks for end-users, SOC analysts, and firewall containment.",
        "content": (
            "### 🛡️ Module 10: Security Recommendation Module\n\n"
            "**Purpose**: Synthesizes the classification verdict, feature drivers, and threat intelligence into actionable remediation instructions.\n\n"
            "#### Recommendation Categories:\n"
            "1. **End-User Actions**: Warnings against clicking, guidance on credential resets, and passkey adoption.\n"
            "2. **SOC & Enterprise Incident Response**: Firewall domain blocklist rules, DNS sinkholing commands, and proxy containment.\n"
            "3. **Threat Feed Contribution**: One-click reporting to Google Safe Browsing, PhishTank, and APWG."
        ),
        "actions": ["Explain Module 1", "What should I do if I clicked a phishing link?", "Explain the 10 detection modules.", "Cybersecurity protection tips"]
    }
}

# =====================================================================
# 📊 COMPARISON MATRIX FOR DUAL-TOPIC INQUIRIES
# =====================================================================

COMPARISON_PAIRS = [
    {
        "keys": ["shap_xai", "lime_xai"],
        "match_words": ["shap", "lime"],
        "table": (
            "### ⚖️ Explainable AI Comparison: SHAP vs LIME\n\n"
            "| Dimension | SHAP (SHapley Additive exPlanations) | LIME (Local Interpretable Model-agnostic Explanations) |\n"
            "| :--- | :--- | :--- |\n"
            "| **Theoretical Basis** | Cooperative Game Theory (Lloyd Shapley, Nobel Prize 2012) | Local Perturbation & Linear Surrogate Modeling |\n"
            "| **Mathematical Guarantee** | Additive Efficiency & Consistency Guaranteed | Heuristic Approximation (No formal uniqueness guarantee) |\n"
            "| **Explanation Scope** | Both Global feature importance & Local prediction waterfall | Primarily Local individual prediction boundaries |\n"
            "| **Computation Method** | Computes marginal contributions across all feature subsets | Perturbs sample points locally and fits ridge regression |\n"
            "| **Output Representation** | Exact additive values ($\\sum \\phi_i + \\text{Base} = P$) | Local decision threshold rules (e.g. `subdomains > 2`) |\n"
            "| **Role in PhishGuard** | Primary mathematical proof behind risk probability score | Secondary verification of local sensitivity boundaries |"
        )
    },
    {
        "keys": ["phishing_overview", "malware_overview"],
        "match_words": ["phishing", "malware"],
        "table": (
            "### ⚖️ Threat Comparison: Phishing vs Malware\n\n"
            "| Dimension | Phishing | Malware (Malicious Software) |\n"
            "| :--- | :--- | :--- |\n"
            "| **Definition** | Social engineering attack deceiving humans into giving up data | Executable code designed to compromise or damage machines |\n"
            "| **Primary Target** | Human psychology (trust, panic, urgency, authority) | Software, operating system, firmware, hardware |\n"
            "| **Attack Mechanism** | Fake login portals, deceptive links, brand typosquatting | Ransomware encryption, keyloggers, Trojans, worms |\n"
            "| **Outcome** | Credential harvesting, 2FA interception, unauthorized access | File encryption, system destruction, backdoor access |\n"
            "| **Relationship** | **Phishing is the delivery vector** used to deliver malware payloads | **Malware is the technical payload** executed after phishing |"
        )
    },
    {
        "keys": ["network_web_security", "mfa_2fa_passkeys"],
        "match_words": ["symmetric", "asymmetric"],
        "table": (
            "### ⚖️ Cryptography Comparison: Symmetric vs Asymmetric Encryption\n\n"
            "| Dimension | Symmetric Encryption (e.g. AES-256) | Asymmetric Encryption (e.g. RSA, ECC) |\n"
            "| :--- | :--- | :--- |\n"
            "| **Key Count** | Single Shared Secret Key for encryption and decryption | Key Pair: Public Key (encrypts) + Private Key (decrypts) |\n"
            "| **Speed / Overhead** | Extremely fast; ideal for encrypting gigabytes of data | Computationally intensive; ~1000x slower than symmetric |\n"
            "| **Key Distribution** | Difficult: Key must be shared securely beforehand | Easy: Public key can be distributed freely to anyone |\n"
            "| **Primary Use Cases** | Bulk database encryption, TLS session data payloads | Digital signatures, SSL/TLS handshake, FIDO2 Passkeys |"
        )
    },
    {
        "keys": ["mfa_2fa_passkeys"],
        "match_words": ["authentication", "authorization"],
        "table": (
            "### ⚖️ Security Control Comparison: Authentication vs Authorization\n\n"
            "| Dimension | Authentication (AuthN) | Authorization (AuthZ) |\n"
            "| :--- | :--- | :--- |\n"
            "| **Core Question** | *'Who are you?'* (Identity Verification) | *'What are you permitted to do?'* (Access Governance) |\n"
            "| **Verification Factor** | Passwords, TOTP tokens, Biometrics, Passkeys | Role-Based Access Control (RBAC), OAuth 2.0 Scopes |\n"
            "| **Sequence** | Must occur first before authorization can take place | Evaluated after identity is successfully authenticated |\n"
            "| **Example in PhishGuard**| Logging in with username and password (JWT issued) | Checking if `role == 'admin'` to access Retrain Model API |"
        )
    }
]

# =====================================================================
# 🌐 EXTERNAL LLM PROVIDER HUB (GEMINI / GROQ / OPENAI / OLLAMA)
# =====================================================================

def build_system_prompt(scan_ctx_str: str = "") -> str:
    """Builds a comprehensive system instruction including project architecture and domain knowledge."""
    return (
        "You are PhishGuard AI, an elite Cybersecurity, Machine Learning, and Explainable AI (XAI) Assistant "
        "integrated into the 'Intelligent Phishing URL Detection Using Explainable AI' system.\n\n"
        "### YOUR DOMAIN KNOWLEDGE:\n"
        "- Complete mastery of Cybersecurity: Phishing, Spear phishing, Whaling, Smishing, Vishing, Pharming, "
        "Social engineering, Malware, Ransomware (double extortion), Spyware, Trojans, Viruses, Worms, Botnets, "
        "Password attacks, Brute force, Credential theft, Email security (SPF/DKIM/DMARC), Network security, Web security "
        "(OWASP Top 10, SQLi, XSS, CSRF, SSRF), Cloud/Mobile security, Encryption (AES, RSA, ECC, Symmetric vs Asymmetric), "
        "Authentication vs Authorization, MFA/2FA, FIDO2 Passkeys, Firewalls, VPN, IDS/IPS, HTTPS/SSL/TLS, Cyber hygiene, Incident response.\n"
        "- Intelligent Phishing URL Detection: URL anatomy, domain/subdomain stacking, URL length, special characters (@, //, -, _), "
        "suspicious keywords, raw IP hosts, URL shortening, typosquatting, IDN homograph/Punycode, brand impersonation, 21 extracted features, "
        "ML classification (Random Forest, Decision Tree, Logistic Regression, Ensemble), datasets, metrics (Accuracy, Precision, Recall, F1, "
        "Confusion Matrix, False Positives/Negatives), Confidence score, Risk score (0-100 across 5 tiers: Safe, Low, Medium, High, Critical), "
        "Explainable AI (SHAP cooperative game theory & LIME local surrogate rules), Feature Importance (Gini & Shapley), Security recommendations.\n"
        "- Project's 10-Module Pipeline:\n"
        "  1. Dataset Collection & Preprocessing | 2. URL Validation | 3. Feature Extraction (21 features) | "
        "  4. Feature Preprocessing | 5. ML Classification | 6. Risk & Confidence | 7. SHAP & LIME XAI | "
        "  8. Feature Importance | 9. SQLite Persistence | 10. Security Recommendations.\n\n"
        "### INSTRUCTIONS FOR RESPONDING:\n"
        "1. For general cybersecurity questions: provide clear, structured, technical markdown explanations with bullet points and best practices.\n"
        "2. For questions about the current scanned URL: use the EXACT scan context provided below. NEVER hallucinate or invent feature values, probabilities, or verdicts. "
        "If no URL has been scanned, inform the user to scan a URL first.\n"
        "3. For questions about project functionality: explain how the relevant module operates in PhishGuard.\n"
        "4. Maintain multi-turn conversational context naturally (resolve pronouns like 'it', 'this', 'that module').\n\n"
        f"### ACTIVE SCAN CONTEXT:\n{scan_ctx_str if scan_ctx_str else 'No active URL scan loaded. (Prompt user to scan a URL if they ask about their current link).'}"
    )

def query_external_llm_if_available(prompt: str, scan_ctx_str: str = "", history: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """Attempts to generate a response via configured external LLM providers (Gemini, Groq, OpenAI, or Ollama)."""
    system_prompt = build_system_prompt(scan_ctx_str)
    
    # 1. Google Gemini API (gemini-1.5-flash / gemini-2.0-flash)
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if gemini_key:
        models_to_try = ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]
        for model in models_to_try:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
                
                # Format conversation history
                contents = []
                if history:
                    for h in history[-6:]:
                        role = "user" if h.get("role") == "user" else "model"
                        contents.append({"role": role, "parts": [{"text": h.get("text", "")}]})
                
                contents.append({"role": "user", "parts": [{"text": prompt}]})
                
                payload = {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": contents,
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1500}
                }
                res = requests.post(url, json=payload, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0] and "parts" in candidates[0]["content"]:
                        return candidates[0]["content"]["parts"][0].get("text", "")
            except Exception as e:
                logger.debug(f"Gemini model {model} attempt failed: {e}")
                continue

    # 2. Groq API
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"}
            messages = [{"role": "system", "content": system_prompt}]
            if history:
                for h in history[-6:]:
                    r = "user" if h.get("role") == "user" else "assistant"
                    messages.append({"role": r, "content": h.get("text", "")})
            messages.append({"role": "user", "content": prompt})
            
            payload = {
                "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 1500
            }
            res = requests.post(url, headers=headers, json=payload, timeout=10)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.debug(f"Groq API call failed: {e}")

    # 3. OpenAI API
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            messages = [{"role": "system", "content": system_prompt}]
            if history:
                for h in history[-6:]:
                    r = "user" if h.get("role") == "user" else "assistant"
                    messages.append({"role": r, "content": h.get("text", "")})
            messages.append({"role": "user", "content": prompt})
            
            payload = {
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 1500
            }
            res = requests.post(url, headers=headers, json=payload, timeout=10)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.debug(f"OpenAI API call failed: {e}")

    # 4. Local Ollama Instance
    ollama_host = os.getenv("OLLAMA_HOST")
    if ollama_host:
        try:
            url = f"{ollama_host}/api/generate"
            payload = {
                "model": os.getenv("OLLAMA_MODEL", "llama3"),
                "system": system_prompt,
                "prompt": prompt,
                "stream": False
            }
            res = requests.post(url, json=payload, timeout=6)
            if res.status_code == 200:
                return res.json().get("response")
        except Exception as e:
            logger.debug(f"Ollama API call failed: {e}")

    return None

# =====================================================================
# 🧠 NATURAL LANGUAGE INTENT CLASSIFICATION & TOKEN MATCHING
# =====================================================================

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can",
    "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't",
    "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have",
    "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself", "him",
    "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't",
    "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no", "nor",
    "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out",
    "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some",
    "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to",
    "too", "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've",
    "were", "weren't", "what", "what's", "when", "when's", "where", "where's", "which", "while", "who",
    "who's", "whom", "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll",
    "you're", "you've", "your", "yours", "yourself", "yourselves", "tell", "explain", "describe", "meaning"
}

def tokenize_query(query: str) -> List[str]:
    """Tokenizes and cleans a user query string."""
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\s]', ' ', query.lower())
    tokens = [t.strip() for t in cleaned.split() if t.strip() and t.strip() not in STOP_WORDS]
    return tokens

def match_knowledge_base(query: str) -> List[Tuple[str, float]]:
    """Ranks knowledge base items by multi-word phrase and keyword relevance."""
    query_norm = " " + re.sub(r'[^a-zA-Z0-9]', ' ', query.lower()) + " "
    tokens = tokenize_query(query)
    query_words = set(query.lower().split())
    scores = {}

    for key, item in KNOWLEDGE_BASE.items():
        score = 0.0
        unique_kws = set(k.lower() for k in item["keywords"])
        title_norm = re.sub(r'[^a-zA-Z0-9]', ' ', item["title"].lower()).strip()
        
        # Title match
        if title_norm and re.search(r'\b' + re.escape(title_norm) + r'\b', query_norm):
            score += 30.0

        # Direct Keyword matching
        for kw in unique_kws:
            if not kw:
                continue
            kw_words = kw.split()
            if re.search(r'\b' + re.escape(kw) + r'\b', query_norm):
                score += 15.0 + (len(kw_words) * 12.0)
            else:
                sig = [w for w in kw_words if w not in STOP_WORDS and len(w) > 2]
                if len(sig) >= 2 and all(w in query_words for w in sig):
                    score += 8.0 + (len(sig) * 4.0)
            if kw in tokens and len(kw) > 2:
                score += 5.0

        # Summary / Content token overlap
        content_lower = (item["summary"] + " " + item["content"]).lower()
        for tok in tokens:
            if len(tok) > 3 and tok in content_lower:
                score += 0.5

        if score > 0:
            scores[key] = score

    return sorted(scores.items(), key=lambda x: x[1], reverse=True)

# =====================================================================
# 🗣️ MULTI-TURN CONVERSATION & PRONOUN RESOLVER
# =====================================================================

def resolve_contextual_pronouns(raw_query: str, history: Optional[List[Dict[str, Any]]]) -> str:
    """Resolves conversational pronouns ('it', 'this', 'that', 'they') using recent conversation history."""
    if not history or len(history) == 0:
        return raw_query
        
    query_lower = raw_query.lower()
    pronoun_patterns = [r'\bhow does it work\b', r'\bhow does that work\b', r'\bwhat is it\b', r'\bwhy is it dangerous\b', 
                        r'\bwhich feature affected it\b', r'\bwhat does it do\b', r'\bhow to prevent it\b', r'\bhow to stop it\b']
    
    needs_resolution = any(re.search(p, query_lower) for p in pronoun_patterns) or query_lower in ["how does it work?", "what does it mean?", "how to fix it?", "why?", "tell me more"]
    
    if needs_resolution:
        # Look back through previous user messages for the last substantive subject
        for prev in reversed(history):
            if prev.get("role") == "user":
                prev_text = prev.get("text", "")
                tokens = tokenize_query(prev_text)
                if tokens:
                    subject = " ".join(tokens[:3])
                    return f"{raw_query} (regarding {subject})"
    return raw_query

def generate_live_scan_explanation(target_url: str, scan_ctx: Optional[Dict[str, Any]], query_text: str) -> Tuple[str, List[str]]:
    """Generates an accurate, non-hallucinated forensic explanation based strictly on actual scan data."""
    active_url = (scan_ctx.get("url") if scan_ctx else "") or target_url
    if not active_url:
        # User asked about current URL when no URL has been scanned yet
        reply = (
            "### 🔍 No Active URL Scan Available\n\n"
            "You haven't scanned a URL yet in this session! To inspect link safety and view Explainable AI (SHAP & LIME) proofs:\n\n"
            "1. Navigate to the **URL Scanner** tab in the navigation bar.\n"
            "2. Paste any link (e.g. `http://paypal-security-update.xyz/signin.php` or `https://www.google.com`).\n"
            "3. Click **Scan URL** — our machine learning ensemble will extract 21 features and generate real-time SHAP waterfall charts.\n\n"
            "Once scanned, ask me: *'Why was this URL classified as phishing?'* or *'Is my current URL safe?'* and I will explain the exact live forensic telemetry!"
        )
        actions = [
            "What is phishing?",
            "How does phishing URL detection work?",
            "Explain the 10 detection modules.",
            "What is SHAP & LIME Explainable AI?",
            "What is Typosquatting?"
        ]
        return reply, actions

    # Extract actual telemetry from scan_ctx
    url = active_url
    domain = scan_ctx.get("domain", "") or urlparse(url).netloc
    prediction = scan_ctx.get("prediction", "Phishing")
    prob = scan_ctx.get("phishing_probability", 50.0)
    conf = scan_ctx.get("confidence_score", 0.0)
    risk_level = scan_ctx.get("risk_level", "High")
    key_factors = scan_ctx.get("key_factors", [])
    shap_explanation = scan_ctx.get("shap_explanation")
    lime_explanation = scan_ctx.get("lime_explanation")
    features = scan_ctx.get("features") or {}
    recs = scan_ctx.get("ai_recommendations") or []
    threat_intel = scan_ctx.get("threat_intel") or {}

    is_phish = prediction == "Phishing" or (isinstance(prob, (int, float)) and prob >= 50.0)

    # 1. Header & Executive Summary
    if is_phish:
        reply_lines = [
            f"### 🚨 Forensic Explainable AI Report: `{url}`\n",
            f"**Verdict**: ⚠️ **Phishing Threat Flagged** • **Risk Level**: **{risk_level}**",
            f"• **Phishing Probability**: **{prob:.1f}%**",
            f"• **Model Confidence Score**: **{conf:.1f}%**",
            f"• **Target Domain / Apex Host**: `{domain}`\n",
            "#### 🔍 Key Risk Drivers & Architectural Anomalies:"
        ]
    else:
        safe_pct = 100.0 - prob if isinstance(prob, (int, float)) else 95.0
        reply_lines = [
            f"### 🛡️ Forensic Explainable AI Report: `{url}`\n",
            f"**Verdict**: ✅ **Legitimate & Verified Safe** • **Risk Level**: **{risk_level}**",
            f"• **Safety Probability**: **{safe_pct:.1f}%**",
            f"• **Model Confidence Score**: **{conf:.1f}%**",
            f"• **Target Domain / Apex Host**: `{domain}`\n",
            "#### 🔍 Key Authenticity Indicators:"
        ]

    # 2. Key factors & features
    if key_factors:
        for kf in key_factors[:5]:
            reply_lines.append(f"• **{kf}**")
    elif features:
        # Dynamically highlight interesting features
        if features.get("ip_address"):
            reply_lines.append("• **Raw Numerical IP Host**: Direct IP addressing evades domain-level reputation blocklists.")
        if features.get("has_at_symbol"):
            reply_lines.append("• **RFC-1738 '@' Credential Obfuscation**: Uses `@` symbol to trick user into reading a false domain.")
        if features.get("subdomain_count", 0) > 2:
            reply_lines.append(f"• **Subdomain Stacking**: Contains {features.get('subdomain_count')} subdomains to mask the real apex domain.")
        if features.get("entropy", 0.0) > 4.0:
            reply_lines.append(f"• **High Shannon Character Entropy** (`{features.get('entropy', 0.0):.2f}`): Indicates algorithmic character randomness or token encoding.")
        if features.get("https_status") is False:
            reply_lines.append("• **Insecure Protocol**: Uses unencrypted HTTP transport.")

    # 3. SHAP feature contributions
    if shap_explanation and isinstance(shap_explanation, dict) and shap_explanation.get("contributions"):
        conts = shap_explanation.get("contributions", [])
        if is_phish:
            top_shap = [c for c in conts if c.get("contribution", 0) > 0][:4]
            if top_shap:
                reply_lines.append("\n#### 📊 Top SHAP (SHapley) Feature Attributions (Pushed Toward Phishing):")
                for sc in top_shap:
                    feat_name = sc.get("display_name") or sc.get("feature_name", "Feature")
                    val = sc.get("value", "")
                    contrib = sc.get("contribution", 0.0)
                    reply_lines.append(f"• **{feat_name}** (`{val}`): Contributed **+{contrib:.3f}** to phishing risk.")
        else:
            top_shap = [c for c in conts if c.get("contribution", 0) < 0][:4]
            if top_shap:
                reply_lines.append("\n#### 📊 Top SHAP (SHapley) Feature Attributions (Pushed Toward Legitimate):")
                for sc in top_shap:
                    feat_name = sc.get("display_name") or sc.get("feature_name", "Feature")
                    val = sc.get("value", "")
                    contrib = abs(sc.get("contribution", 0.0))
                    reply_lines.append(f"• **{feat_name}** (`{val}`): Provided **-{contrib:.3f}** safety credit.")

    # 4. LIME Decision Rules
    if lime_explanation and isinstance(lime_explanation, dict) and lime_explanation.get("contributions"):
        lime_rules = lime_explanation.get("contributions", [])[:3]
        if lime_rules:
            reply_lines.append("\n#### 🔬 LIME Local Surrogate Decision Rules:")
            for lr in lime_rules:
                desc = lr.get("description") or f"{lr.get('display_name')} = {lr.get('value')}"
                reply_lines.append(f"• `{desc}` (Local Weight: **{lr.get('contribution', 0.0):+.3f}**)")

    # 5. Actionable Recommendations
    reply_lines.append("\n#### 🛡️ Actionable Security Recommendations:")
    if is_phish:
        reply_lines.extend([
            "1. 🚫 **Do NOT click, navigate to, or enter credentials** on this web page.",
            "2. 🔑 If credentials were submitted, change your password immediately on the **official website** and enable multi-factor authentication.",
            "3. 📄 Export a compliance **PDF Security Audit Report** or experiment with feature changes in the **What-If Simulator**."
        ])
        actions = [
            f"Explain SHAP values for {domain}",
            "Why is this domain high risk?",
            "Open What-If Simulator",
            "Download PDF Audit Report",
            "What should I do if I clicked a phishing link?",
            "Explain 21 Features"
        ]
    else:
        reply_lines.extend([
            "• **Verified Safe**: This URL exhibits clean domain architecture and standard lexical entropy.",
            "• **Security Best Practice**: Even on legitimate sites, always inspect your browser's address bar before typing passwords."
        ])
        actions = [
            "Scan another URL",
            "Explain SHAP values for this URL",
            "How does What-If Simulation work?",
            "What is the difference between SHAP and LIME?",
            "What is Phishing?"
        ]

    return "\n".join(reply_lines), actions[:6]

# =====================================================================
# ⚡ CONVERSATIONAL, IDENTITY & INTENT HANDLERS
# =====================================================================

def handle_conversational_queries(raw_query: str) -> Optional[Tuple[str, List[str]]]:
    """Handles standard greetings, identity questions, capabilities, and system overviews."""
    q = raw_query.lower().strip("?!. ")
    
    # 1. Greetings
    greetings = ["hello", "hi", "hey", "good morning", "good afternoon", "good evening", "greetings", "howdy", "sup"]
    if q in greetings or any(q.startswith(g + " ") for g in greetings):
        reply = (
            "### 👋 Hello! I am PhishGuard AI Security Assistant\n\n"
            "I am your dedicated **Cybersecurity, Machine Learning & Explainable AI Copilot**.\n\n"
            "#### How I Can Help You:\n"
            "• 🔍 **Live URL Forensics & Scan Explanations**: Explain why links are marked phishing or safe using live SHAP & LIME metrics.\n"
            "• 🧠 **Explainable AI (SHAP & LIME)**: Demystify mathematical game theory and local surrogate linear models.\n"
            "• 🌐 **10-Module Pipeline**: Explain our complete 10-module detection architecture.\n"
            "• 🛡️ **Cybersecurity & Threat Concepts**: Learn about Phishing, Ransomware, MFA/Passkeys, Zero Trust, SQLi, and incident response.\n\n"
            "**Type any custom question below** or select one of the suggested topics!"
        )
        actions = [
            "What is phishing?",
            "How does phishing URL detection work?",
            "Explain the 10 detection modules.",
            "What is SHAP & LIME Explainable AI?",
            "Is my current URL safe?",
            "What should I do if I clicked a phishing link?"
        ]
        return reply, actions

    # 2. Identity / Capabilities
    if any(p in q for p in ["who are you", "what are you", "what can you do", "what is your name", "what do you do", "help me", "how to use", "what is phishguard"]):
        reply = (
            "### 🤖 About PhishGuard AI Security Copilot\n\n"
            "I am an intelligent AI assistant specialized in **Cybersecurity, Intelligent Phishing URL Detection, Machine Learning, and Explainable AI**.\n\n"
            "#### Core Capabilities:\n"
            "1. **Universal Security Intelligence**: Ask me **any custom question** on cyber threats, attack vectors, encryption, authentication, network protocols, and incident containment.\n"
            "2. **Live URL Telemetry Binding**: Real-time explainability of your scanned URLs with exact 21-feature breakdowns and SHAP/LIME proofs.\n"
            "3. **10-Module Pipeline Mastery**: Complete architectural knowledge of Modules 1 through 10 in our detection pipeline.\n"
            "4. **Actionable Incident Playbooks**: Clear step-by-step guidance for compromised accounts, ransomware, and credential theft.\n\n"
            "**Go ahead and type your custom question in the box below!**"
        )
        actions = [
            "What is phishing?",
            "Explain the 10 detection modules.",
            "What is SHAP?",
            "What is LIME?",
            "Which features made this URL suspicious?",
            "Cybersecurity protection tips"
        ]
        return reply, actions

    # 3. Gratitude
    if any(p in q for p in ["thank you", "thanks", "awesome", "great job", "appreciate it", "good bot", "cool"]):
        reply = (
            "### 🛡️ You're Very Welcome!\n\n"
            "Always stay vigilant online. Remember: **Verify before you click, enforce hardware/app-based MFA, and inspect domain apexes.**\n\n"
            "Feel free to ask any other questions about cybersecurity, web vulnerabilities, machine learning models, or link safety!"
        )
        actions = [
            "What is Zero Trust?",
            "Explain the 10 detection modules.",
            "What is Typosquatting?",
            "Open What-If Simulator",
            "Download PDF Audit Report",
            "What is Quishing (QR Phishing)?"
        ]
        return reply, actions

    return None

# =====================================================================
# ⚡ DYNAMIC INTENT CLASSIFIER & UNIVERSAL REASONING SYNTHESIZER
# =====================================================================

def synthesize_comprehensive_answer(
    raw_query: str, 
    matched_topics: List[Tuple[str, float]], 
    target_url: Optional[str] = None, 
    scan_ctx: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None
) -> Tuple[str, List[str]]:
    """Synthesizes a clear, structured, technical answer for any user-typed cybersecurity question."""
    query_lower = raw_query.lower()
    
    # 0. Check conversational handler first
    conv = handle_conversational_queries(raw_query)
    if conv:
        return conv

    # 1. Check for comparative queries (e.g. "X vs Y", "difference between", "SHAP & LIME")
    is_comparison = any(term in query_lower for term in [" vs ", " vs. ", "versus", "difference between", "compare", "which is better", " & ", " and "])
    if is_comparison:
        for pair in COMPARISON_PAIRS:
            match_words = pair.get("match_words", [])
            matched_count = sum(1 for mw in match_words if mw in query_lower)
            if (matched_count >= 2) or (matched_count >= 1 and any(term in query_lower for term in [" vs ", " vs. ", "versus", "difference between", "compare", "which is better"])):
                actions = [f"Explain {KNOWLEDGE_BASE[k]['title']}" for k in pair["keys"] if k in KNOWLEDGE_BASE] + ["Explain the 10 detection modules.", "Cybersecurity protection tips"]
                return pair["table"], actions[:6]

    # 2. Check if the question matches a primary knowledge topic with high confidence
    if matched_topics and matched_topics[0][1] >= 8.0:
        primary_key, primary_score = matched_topics[0]
        primary_item = KNOWLEDGE_BASE[primary_key]
        
        reply = primary_item["content"]
        
        if len(matched_topics) > 1 and matched_topics[1][1] >= 6.0:
            sec_key = matched_topics[1][0]
            sec_item = KNOWLEDGE_BASE[sec_key]
            reply += (
                f"\n\n---\n\n"
                f"#### 🔗 Related Security Concept: **{sec_item['title']}**\n"
                f"{sec_item['summary']}\n\n"
                f"You can ask: *'Explain {sec_item['title']}'* for a deeper forensic breakdown."
            )
            
        actions = primary_item.get("actions", [])
        return reply, actions

    # 3. ADVANCED DYNAMIC REASONING ENGINE FOR ANY ARBITRARY USER QUESTION
    tokens = tokenize_query(raw_query)
    
    # Classify User Intent
    intents = []
    if any(q in query_lower for q in ["how to", "how do i", "how can i", "steps to", "guide", "setup", "configure", "secure my", "harden", "protect"]):
        intents.append("how_to")
    if any(q in query_lower for q in ["what is", "what are", "define", "meaning of", "explain", "tell me about", "describe", "what does"]):
        intents.append("definition")
    if any(q in query_lower for q in ["why", "reason", "cause", "what makes"]):
        intents.append("why")
    if any(q in query_lower for q in ["is it safe", "can i", "is this", "should i", "safe to", "risk", "dangerous"]):
        intents.append("risk_eval")
    if any(q in query_lower for q in ["can someone", "can hackers", "can an attacker", "is it possible", "can a virus", "can an email"]):
        intents.append("possibility")
    if any(q in query_lower for q in ["hacked", "clicked", "stolen", "lost", "compromised", "help", "breached", "scammed", "entered password"]):
        intents.append("incident")
    if any(q in query_lower for q in ["difference", "compare", "vs", "versus", "better"]):
        intents.append("comparison")

    # Clean query into subject title
    subject = raw_query.strip("? .!").title()
    for prefix in ["What Is ", "What Are ", "How To ", "How Do I ", "How Can I ", "Explain ", "Tell Me About ", "Can Someone ", "Why Is ", "Is It Possible To "]:
        if subject.startswith(prefix):
            subject = subject[len(prefix):]
            break

    reply_lines = [
        f"### 🛡️ PhishGuard AI Security Intelligence\n",
        f"**Inquiry Topic**: **{subject}**\n"
    ]

    # Structure tailored answer based on intent and topic classification
    if "incident" in intents:
        reply_lines.append(
            "#### 🚨 Immediate Containment & Incident Response Action Plan:\n"
            "If you or your organization experienced an incident related to this inquiry, take these rapid steps:\n"
            "1. 🔒 **Reset Credentials Immediately**: Change passwords on an independent, secure device and invalidate all active web sessions.\n"
            "2. 🛡️ **Enforce Hardware/App-Based MFA**: Upgrade from SMS to FIDO2 Passkeys or Authenticator apps.\n"
            "3. 💻 **Network Isolation**: Disconnect the affected computer or mobile phone from the Wi-Fi network and execute an offline malware/EDR scan.\n"
            "4. 💳 **Financial Alert**: If banking or card info was entered, immediately contact your financial institution's fraud desk.\n"
            "5. 📢 **Report**: Submit malicious links to PhishGuard and Google Safe Browsing."
        )
    elif "how_to" in intents:
        reply_lines.append(
            f"#### 🛠️ Step-by-Step Security Implementation Guide for *{subject}*:\n"
            "1. **Audit Attack Surface**: Identify all endpoints, accounts, protocols, and communication channels exposed to this vector.\n"
            "2. **Implement Defense-in-Depth**: Apply layered controls — combine protocol encryption (TLS), robust authentication (FIDO2/Passkeys), and endpoint monitoring.\n"
            "3. **Least Privilege & Segmentation**: Ensure accounts operate with minimal necessary permissions and isolate critical resources.\n"
            "4. **Continuous Inspection**: Leverage automated Explainable AI and anomaly detection (such as PhishGuard's 21-feature extractor) to verify incoming data.\n"
            "5. **Routine Backup & Recovery**: Maintain isolated, encrypted backups using the 3-2-1 rule."
        )
    elif "possibility" in intents:
        reply_lines.append(
            f"#### 🔍 Threat Feasibility & Attack Mechanics:\n"
            f"**Yes, cyber adversaries actively exploit this vector.** Here is how this attack mechanism operates:\n\n"
            "• **Delivery & Social Engineering**: Attackers craft high-urgency lures across messaging apps, emails, or rogue Wi-Fi to lower victim vigilance.\n"
            "• **Payload Execution & Evasion**: Links often deploy redirect chains, Punycode lookalikes, or AitM reverse proxies that harvest live session tokens.\n"
            "• **Impact**: Unauthorized account takeover, credential exfiltration, or device compromise.\n\n"
            "#### 🛡️ How to Protect Yourself:\n"
            "• Never tap unknown links in chat apps without verifying the sender out-of-band.\n"
            "• Paste suspicious URLs into **PhishGuard URL Scanner** to inspect SHAP feature attributions before interacting."
        )
    elif "risk_eval" in intents:
        reply_lines.append(
            f"#### ⚠️ Risk Assessment & Forensic Evaluation:\n"
            "When evaluating whether a link, file, or communication is safe:\n"
            "• **Never trust cosmetic appearances**: Attackers easily clone brand logos, obtain valid SSL certificates, and spoof display names.\n"
            "• **Inspect the Destination Apex Domain**: Check the characters immediately before the first `/` to confirm the true hosting entity.\n"
            "• **Evaluate Entropy & Obfuscation**: High character randomness (`entropy > 4.2`) or deep subdomain nesting indicates malicious intent.\n"
            "• **Scan with PhishGuard**: Run real-time machine learning inference to calculate exact probability and SHAP feature drivers."
        )
    else:
        reply_lines.append(
            f"#### 💡 Core Technical Breakdown & Architectural Concepts:\n"
            f"In modern cybersecurity and intelligent network architecture, **{subject}** is evaluated through multi-layered defensive heuristics:\n\n"
            "1. **Threat Mechanics**: Exploits human psychological biases (urgency, authority) combined with protocol deception (subdomain stacking, DNS spoofing, session hijacking).\n"
            "2. **Explainable AI Integration**: Machine learning models (like PhishGuard's Random Forest) analyze lexical, structural, and entropy metrics to quantify risk with mathematical precision.\n"
            "3. **Zero Trust Hardening**: Security postures assume perimeters are breachable, requiring continuous verification at every layer."
        )

    # Correlate with top related topics in the Knowledge Base
    top_matches = [KNOWLEDGE_BASE[k] for k, s in matched_topics[:3]] if matched_topics else []
    if top_matches:
        reply_lines.append("\n#### 🧠 Correlated Cybersecurity Knowledge:\n")
        for tm in top_matches:
            reply_lines.append(f"• **{tm['title']}**: {tm['summary']}")

    reply_lines.append(
        "\n#### 🛡️ Actionable Security Best Practices:\n"
        "• Deploy phishing-resistant FIDO2 Passkeys and password managers.\n"
        "• Always verify suspicious links using the **PhishGuard URL Scanner** before clicking.\n"
        "• Leverage Explainable AI (SHAP & LIME) to understand the underlying mathematical drivers behind security alerts."
    )

    reply_text = "\n".join(reply_lines)

    # Contextually generate dynamic follow-up chips
    actions = []
    for tm in top_matches:
        actions.append(f"Explain {tm['title']}")
    actions.extend([
        "What is phishing?",
        "How does phishing URL detection work?",
        "Explain the 10 detection modules.",
        "What is SHAP & LIME Explainable AI?",
        "Is my current URL safe?",
        "What should I do if I clicked a phishing link?"
    ])

    return reply_text, list(dict.fromkeys(actions))[:6]

# =====================================================================
# 🚀 MAIN CHATBOT ROUTE
# =====================================================================

@router.post("", response_model=ChatbotResponse)
def query_ai_security_bot(query: ChatbotQuery):
    raw_msg = query.message.strip()
    msg = raw_msg.lower()
    ctx = query.prediction_context or {}
    scanned_url = query.scanned_url_context or ctx.get("url", "")
    history = query.history or []
    
    # 0. Contextual Pronoun Resolution
    resolved_query = resolve_contextual_pronouns(raw_msg, history)
    resolved_msg = resolved_query.lower()
    
    # 1. Extract any URLs present directly inside the user's message
    found_urls = re.findall(
        r'https?://[^\s<>"\',;]+|[a-zA-Z0-9-]+\.(?:xyz|top|tk|buzz|gq|ml|cf|icu|com|net|org|io|biz|info)/[^\s<>"\',;]*',
        raw_msg
    )
    target_url = found_urls[0] if found_urls else scanned_url
    
    # 2. Check if user specifically asks about the current scanned URL or an inline URL
    explicit_url_prompts = [
        "why was this url", "why is this url", "why was this link", "why is this link",
        "why was this site", "why is this site", "why did this url", "why did this link",
        "why was it classified as phishing", "why was it classified as legitimate",
        "why was it flagged", "why is it flagged", "why was this flagged", "why is this flagged",
        "explain this url", "explain this link", "explain this website", "explain my url",
        "explain the scanned url", "explain the scan result", "explain this scan",
        "analyze this url", "analyze this link", "break down this url", "break down this link",
        "what is the risk score of this url", "what is the risk score of this link",
        "what is the verdict for this url", "what is the verdict of this link",
        "why is this domain high risk", "why is this domain safe", "is this scanned url safe",
        "tell me about this scanned url", "tell me about this link", "is my current url safe",
        "which features made this url suspicious", "which feature affected it the most",
        "why did the model mark this url as phishing", "what made this url suspicious",
        "explain the shap result", "explain the lime result", "why is this url high risk",
        "what should i do if this url is phishing"
    ]
    
    general_educational_queries = [
        "what is phishing", "how does phishing work", "how does phishing url detection work",
        "what is spear phishing", "what is email phishing", "what is quishing",
        "what to do if i clicked", "cybersecurity protection tips", "how to protect against phishing",
        "what is the difference between phishing and malware", "how does machine learning detect phishing urls",
        "what is shap", "what is lime", "explain the 10 detection modules", "what does the confidence score mean",
        "how can i identify a phishing url", "what should i do if i clicked a phishing link",
        "how can i protect myself from phishing"
    ]
    
    is_general_edu = any(g in resolved_msg for g in general_educational_queries)
    is_url_specific = (bool(found_urls) or any(p in resolved_msg for p in explicit_url_prompts)) and not is_general_edu
    
    # -------------------------------------------------------------
    # ROUTE 1: LIVE SCAN TELEMETRY / FORENSIC INQUIRY
    # -------------------------------------------------------------
    if is_url_specific:
        reply, suggested_actions = generate_live_scan_explanation(target_url, ctx, raw_msg)
        return ChatbotResponse(
            reply=reply,
            suggested_actions=suggested_actions[:6],
            related_security_topics=["Explain SHAP", "Explain LIME", "Open What-If Simulator", "Explain the 10 detection modules."]
        )

    # -------------------------------------------------------------
    # ROUTE 2: EXTERNAL LLM PROVIDER (IF CONFIGURED IN ENVIRONMENT)
    # -------------------------------------------------------------
    scan_ctx_summary = ""
    if ctx and ctx.get("url"):
        scan_ctx_summary = (
            f"URL: {ctx.get('url')}\n"
            f"Verdict: {ctx.get('prediction', 'Unknown')}\n"
            f"Phishing Probability: {ctx.get('phishing_probability', 0.0)}%\n"
            f"Confidence Score: {ctx.get('confidence_score', 0.0)}%\n"
            f"Risk Level: {ctx.get('risk_level', 'Unknown')}\n"
            f"Key Factors: {json.dumps(ctx.get('key_factors', []))}\n"
            f"SHAP Summary: {json.dumps(ctx.get('shap_explanation', {}))}\n"
            f"Features: {json.dumps(ctx.get('features', {}))}"
        )
        
    llm_reply = query_external_llm_if_available(resolved_query, scan_ctx_summary, history)
    if llm_reply:
        actions = [
            "What is phishing?",
            "How does phishing URL detection work?",
            "Explain the 10 detection modules.",
            "What is SHAP & LIME Explainable AI?",
            "Is my current URL safe?",
            "What should I do if I clicked a phishing link?"
        ]
        return ChatbotResponse(
            reply=llm_reply,
            suggested_actions=actions[:6],
            related_security_topics=["Explain SHAP", "Explain LIME", "Open What-If Simulator", "Explain the 10 detection modules."]
        )

    # -------------------------------------------------------------
    # ROUTE 3: BUILT-IN EXPERT AI REASONING SYNTHESIZER
    # -------------------------------------------------------------
    matched_topics = match_knowledge_base(resolved_query)
    
    reply, suggested_actions = synthesize_comprehensive_answer(
        raw_query=resolved_query,
        matched_topics=matched_topics,
        target_url=target_url,
        scan_ctx=ctx,
        history=history
    )
    
    related_topics = [
        "What is phishing?",
        "How does phishing URL detection work?",
        "Explain the 10 detection modules.",
        "What is SHAP & LIME Explainable AI?",
        "What does the confidence score mean?",
        "What is Typosquatting & Punycode?",
        "Machine Learning Models in PhishGuard",
        "Actionable Cybersecurity Defense Guide"
    ]
    
    return ChatbotResponse(
        reply=reply,
        suggested_actions=suggested_actions[:6],
        related_security_topics=related_topics
    )
