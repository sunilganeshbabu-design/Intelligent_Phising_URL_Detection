import requests
import json
import sys

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

test_questions = [
    'Why was this URL classified as phishing?',
    'What is SQL injection and how does it compromise databases?',
    'What is Cross-Site Scripting (XSS)?',
    'How do I secure my home Wi-Fi and router?',
    'What is Zero Trust security architecture?',
    'What is the difference between SHAP and LIME?',
    'How do hackers bypass 2FA using EvilProxy?',
    'What is Quishing (QR Phishing)?',
    'What is Ransomware and double extortion?',
    'Cybersecurity protection tips',
    'What is SQL injection?',
    'How to secure home Wi-Fi?',
    'What is Zero Trust?',
    'What is SHAP & LIME Explainable AI?',
    'Explain XGBooster Model',
    'Explain Shannon Character Entropy',
    'What is ROC-AUC metric?',
    'How do hackers bypass 2FA?',
    'What is Typosquatting & Punycode?',
    'What is Ransomware?',
    'Does a VPN protect against phishing?',
    'What is DNS Spoofing?',
    'Why is HTTPS not enough?',
    'What is OWASP Top 10?',
    'What to do if I clicked a phishing link?',
    'Passwords vs 2FA vs Passkeys',
    'What is SPF, DKIM, and DMARC?',
    'Best password managers guide'
]

print("=" * 80)
print("TESTING CHATBOT SUGGESTED QUESTIONS WITH SCANNED URL CONTEXT")
print("=" * 80)

for q in test_questions:
    r = requests.post(
        'http://127.0.0.1:8000/api/chatbot',
        json={
            'message': q,
            'scanned_url_context': 'https://www.google.com',
            'prediction_context': {
                'url': 'https://www.google.com',
                'prediction': 'Legitimate',
                'phishing_probability': 0.0
            }
        }
    )
    res = r.json()
    lines = [l for l in res.get('reply', '').split('\n') if l.strip()]
    first_line = lines[0] if lines else 'NO_REPLY'
    print(f"Q: {q}\n   -> {first_line}\n")
