import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app.ml.predictor import predict_url
from backend.app.api.threat_lookup import lookup_threat_indicator
from backend.app.api.email_scanner import analyze_phishing_email, EmailScanRequest

print("=" * 70)
print("COMPREHENSIVE LEGITIMATE & PHISHING DETECTION VERIFICATION SUITE")
print("=" * 70)

# 1. Extensive Real-World Legitimate URLs
legit_test_urls = [
    # Top Search & Tech
    ("https://www.google.com", "Google Homepage"),
    ("https://www.google.com/search?q=machine+learning", "Google Search Query"),
    ("https://github.com/torvalds/linux", "GitHub Public Repository"),
    ("https://github.com/login", "GitHub Login Page"),
    ("https://en.wikipedia.org/wiki/Phishing", "Wikipedia Article"),
    ("https://www.amazon.com/dp/B08N5WRWNW", "Amazon Product Page"),
    ("https://www.microsoft.com/en-us/security", "Microsoft Security Page"),
    ("https://stackoverflow.com/questions/123456/how-to-fix", "StackOverflow Question"),
    ("https://docs.python.org/3/library/urllib.parse.html", "Python Documentation"),
    ("https://openai.com/index/chatgpt", "OpenAI ChatGPT Page"),
    ("https://accounts.google.com/signin/v2/identifier", "Google Accounts Sign-in"),
    ("https://www.paypal.com/signin", "PayPal Official Sign-in"),
    ("https://developer.apple.com/account/", "Apple Developer Portal"),
    ("https://account.microsoft.com/", "Microsoft Account Portal"),
    ("https://www.chase.com/secure/login", "Chase Secure Login"),
    ("https://www.linkedin.com/checkpoint/rp/request-password-reset", "LinkedIn Password Reset"),
    ("https://instagram.com/accounts/login/", "Instagram Login"),
    ("https://portal.azure.com/#home", "Azure Portal"),
    ("https://login.microsoftonline.com/common/oauth2/authorize", "Microsoft SSO OAuth"),
    ("https://us04web.zoom.us/j/71234567890?pwd=abc", "Zoom Meeting Link"),
    ("https://bit.ly/my-portfolio-2026", "Legitimate Bitly Link"),
    ("https://tinyurl.com/meeting-link-daily", "Legitimate TinyURL Link"),
    ("https://linktr.ee/mycompany", "Linktree Profile"),
    ("https://forms.gle/xyz123abc", "Google Forms Link"),
    ("https://maps.app.goo.gl/xyz456", "Google Maps Shortlink"),
    ("https://wa.me/1234567890", "WhatsApp Direct Chat Link"),
    
    # Standard & Unlisted Small Business / Education / Gov / Blog URLs
    ("https://mit.edu/research", "MIT University Research"),
    ("https://incometax.gov.in/iec/foportal/", "Government Income Tax Portal"),
    ("https://city-library-catalog.org/account/login?redirect=/my-books", "Library Catalog Login"),
    ("https://family-counseling-services.org/portal/verify-email?token=928103981203", "Counseling Email Verification Token"),
    ("https://johns-bakery-shop.com/menu-and-prices", "Local Bakery Menu"),
    ("https://acme-consulting-group.com/auth/login.html", "Consulting Firm Auth Login"),
    ("https://travelwithsarah.net/2026/best-destinations-in-europe", "Travel Blog Post"),
    ("https://quantum-computing-research-lab.org/publications", "Research Lab Publications"),
    ("https://modern-architecture-studio.com/client-area/signin", "Architecture Studio Client Sign-in"),
    ("https://digital-art-gallery-showcase.com/artist/register-update", "Art Gallery Registration")
]

print("\n--- [TEST 1] Testing Legitimate URLs (Must be classified as Legitimate) ---")
legit_fails = []
for url, desc in legit_test_urls:
    res = predict_url(url, include_xai=False)
    status = "PASS [LEGIT]" if res.prediction == "Legitimate" else "FAIL [PHISHING]"
    if res.prediction != "Legitimate":
        legit_fails.append((url, desc, res.phishing_probability, res.risk_level))
    print(f"[{status:15s}] Prob: {res.phishing_probability:5.1f}% | Risk: {res.risk_level:8s} | {desc} ({url})")

print(f"\nLegitimate URLs Result: {len(legit_test_urls) - len(legit_fails)} / {len(legit_test_urls)} Passed.")
assert len(legit_fails) == 0, f"Failed on legitimate URLs: {legit_fails}"

# 2. Genuine Phishing Attack URLs
phish_test_urls = [
    ("http://paypal-security-update.xyz/signin.php", "PayPal Lookalike Credential Harvest"),
    ("http://apple-id-recovery-support.com/auth/challenge", "Apple ID Clone"),
    ("http://chase-verify-identity-login.top/login.html", "Chase Banking Trojan"),
    ("http://binance-security-kyc.buzz/wallet/verify", "Crypto Wallet Drainer"),
    ("http://192.168.1.100/login/bankofamerica-auth.php?token=928103", "Direct IP Host Banking Phish"),
    ("http://google.com@chase-security.top/login", "RFC-1738 At-Symbol Destination Spoof"),
    ("http://netflix-billing-resolve-account.buzz/verify?ref=39104", "Payment Fraud Buzz TLD"),
    ("http://login-verify-paypal-account-security-update-portal.xyz/signin", "Keyword Stuffed Subdomain Abuse")
]

print("\n--- [TEST 2] Testing Genuine Phishing URLs (Must be classified as Phishing) ---")
phish_fails = []
for url, desc in phish_test_urls:
    res = predict_url(url, include_xai=False)
    status = "PASS [PHISHING]" if res.prediction == "Phishing" else "FAIL [LEGIT]"
    if res.prediction != "Phishing":
        phish_fails.append((url, desc, res.phishing_probability, res.risk_level))
    print(f"[{status:15s}] Prob: {res.phishing_probability:5.1f}% | Risk: {res.risk_level:8s} | {desc} ({url})")

print(f"\nPhishing URLs Result: {len(phish_test_urls) - len(phish_fails)} / {len(phish_test_urls)} Caught.")
assert len(phish_fails) == 0, f"Failed on phishing URLs: {phish_fails}"

# 3. Threat IOC Lookup
threat_queries = [
    ("google.com", "Safe", False),
    ("https://github.com/torvalds/linux", "Safe", False),
    ("paypal.com", "Safe", False),
    ("city-library-catalog.org", "Safe", False),
    ("https://johns-bakery-shop.com/menu", "Safe", False),
    ("paypal-security-update.xyz", "Critical", True),
    ("apple-id-recovery-support.com", "Critical", True),
    ("chase-verify-identity-login.top", "Critical", True)
]

print("\n--- [TEST 3] Testing Threat IOC Lookup ---")
for query, expected_risk, expected_bad in threat_queries:
    res = lookup_threat_indicator(query)
    match_status = "PASS" if res.is_blacklisted == expected_bad and res.risk_level == expected_risk else "FAIL"
    print(f"[{match_status:4s}] {query:35s} -> Risk: {res.risk_level:8s} | Rep: {res.reputation_score:4.1f} | Bad: {res.is_blacklisted} | Expected: {expected_risk} (Bad: {expected_bad})")
    assert res.is_blacklisted == expected_bad, f"Threat lookup bad flag mismatch for {query}"
    assert res.risk_level == expected_risk, f"Threat lookup risk level mismatch for {query}"

# 4. Email Scanner
print("\n--- [TEST 4] Testing Email Phishing Scanner ---")
# Case A: Legitimate Corporate Security Alert
legit_email = EmailScanRequest(
    subject="Security notice: New sign-in detected on Google Account",
    body="A new login was recorded from your browser. If this was you, no action is needed. Review at https://myaccount.google.com/security",
    sender="no-reply@accounts.google.com"
)
legit_res = analyze_phishing_email(legit_email)
print(f"Legitimate Email Verdict: {legit_res.overall_verdict} (Score: {legit_res.phishing_probability}, Risk: {legit_res.risk_level})")
assert legit_res.risk_level in ["Safe", "Low", "Low Risk"], f"Legitimate email falsely scored high: {legit_res.overall_verdict}"

# Case B: Legitimate Team Update with Unlisted Domain
team_email = EmailScanRequest(
    subject="Meeting notes and restaurant menu",
    body="Hi team, here are the project files: https://github.com/torvalds/linux and menu for tonight https://johns-bakery-shop.com/menu-and-prices",
    sender="manager@mycompany.org"
)
team_res = analyze_phishing_email(team_email)
print(f"Team Email Verdict: {team_res.overall_verdict} (Score: {team_res.phishing_probability}, Risk: {team_res.risk_level})")
assert team_res.risk_level in ["Safe", "Low", "Low Risk"], f"Team email falsely scored high: {team_res.overall_verdict}"

# Case C: Malicious Spoofed Phishing Email
phish_email = EmailScanRequest(
    subject="URGENT: Your Chase checking account has been suspended",
    body="Your debit card has been disabled. Confirm your identity within 24 hours at http://chase-verify-identity-login.top/auth/login.php",
    sender="security@chase-auth-alert.top"
)
phish_res = analyze_phishing_email(phish_email)
print(f"Phishing Email Verdict: {phish_res.overall_verdict} (Score: {phish_res.phishing_probability}, Risk: {phish_res.risk_level})")
assert phish_res.risk_level in ["Critical", "High"], f"Phishing email not detected as Critical: {phish_res.overall_verdict}"

print("\n" + "=" * 70)
print("ALL VERIFICATION TESTS PASSED 100% SUCCESSFULLY!")
print("=" * 70)
