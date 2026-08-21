import sys
import os
import requests
import json

BASE_URL = "http://127.0.0.1:8000/api"

def test_url_scanner(url):
    print(f"\n[URL SCANNER] Scanning custom URL: {url}")
    payload = {"url": url, "model_name": "XGBoost", "include_xai": True}
    res = requests.post(f"{BASE_URL}/predict", json=payload, timeout=10)
    assert res.status_code == 200, f"Error {res.status_code}: {res.text}"
    data = res.json()
    print(f"  -> Prediction: {data['prediction']} | Prob: {data['phishing_probability']:.1f}% | Risk: {data['risk_level']}")
    print(f"  -> Live DNS: {data['threat_intel']['dns_resolved_ip']} ({data['threat_intel']['dns_status']})")
    print(f"  -> Live SSL: {data['threat_intel']['ssl_valid']} ({data['threat_intel']['ssl_issuer']})")
    print(f"  -> Longevity: {data['threat_intel']['domain_age']}")
    return data

def test_email_scanner(email):
    print(f"\n[EMAIL SCANNER] Scanning custom email: {email}")
    payload = {"email": email}
    res = requests.post(f"{BASE_URL}/email-scan", json=payload, timeout=10)
    assert res.status_code == 200, f"Error {res.status_code}: {res.text}"
    data = res.json()
    print(f"  -> Verdict: {data['overall_verdict']} | Prob: {data['phishing_probability']:.1f}% | Risk: {data['risk_level']}")
    print(f"  -> MX Provider: {data['dns_info']['mail_provider']} (Has MX: {data['dns_info']['has_mx']})")
    print(f"  -> SPF Active: {data['dns_info']['has_spf']} | DMARC Active: {data['dns_info']['has_dmarc']}")
    return data

def test_threat_ioc(indicator):
    print(f"\n[THREAT IOC] Looking up custom indicator: {indicator}")
    res = requests.get(f"{BASE_URL}/threat-lookup/{indicator}", timeout=10)
    assert res.status_code == 200, f"Error {res.status_code}: {res.text}"
    data = res.json()
    print(f"  -> Risk Level: {data['risk_level']} | Rep Score: {data['reputation_score']} | Blacklisted: {data['is_blacklisted']}")
    print(f"  -> Resolved IP: {data['resolved_ip']}")
    print(f"  -> DNS Records Count: {len(data['dns_records'])}")
    print(f"  -> WHOIS Age: {data['whois_age_days']} days ({data['whois_registrar']})")
    return data

if __name__ == "__main__":
    print("=================================================================")
    print("TESTING REAL-TIME ANALYSIS ON ARBITRARY CUSTOM REAL-WORLD INPUTS")
    print("=================================================================")

    # Custom Legitimate URLs
    test_url_scanner("https://cs.stanford.edu/research")
    test_url_scanner("https://www.bbc.com/news/technology")
    test_url_scanner("https://danluu.com/")
    
    # Custom Phishing URLs
    test_url_scanner("http://paypal-verification-account-security.xyz/login.php")
    test_url_scanner("http://chase-update-billing-auth.top/verify.html")
    test_url_scanner("http://192.168.1.50/login/apple-id-verify.php")
    
    # Custom Emails
    test_email_scanner("security@stanford.edu")
    test_email_scanner("billing-update@paypal-auth-alert.xyz")
    test_email_scanner("support@apple-id-notice.top")
    
    # Custom Threat IOCs
    test_threat_ioc("cs.stanford.edu")
    test_threat_ioc("bbc.com")
    test_threat_ioc("paypal-verification-account-security.xyz")
    test_threat_ioc("1.1.1.1")

    print("\n=================================================================")
    print("ALL CUSTOM REAL-TIME TESTS COMPLETED SUCCESSFULLY!")
    print("=================================================================")
