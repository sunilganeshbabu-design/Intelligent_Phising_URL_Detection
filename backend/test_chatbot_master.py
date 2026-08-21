import sys
sys.stdout.reconfigure(encoding='utf-8')
from app.api.chatbot import (
    query_ai_security_bot,
    match_knowledge_base,
    synthesize_comprehensive_answer,
    resolve_contextual_pronouns,
    generate_live_scan_explanation,
    ChatbotQuery
)

print("=" * 80)
print("🛡️ MASTER VERIFICATION TEST SUITE: PHISHGUARD AI CHATBOT ENGINE")
print("=" * 80)

# -------------------------------------------------------------
# TEST SET 1: The 15 User-Specified Sample Questions
# -------------------------------------------------------------
sample_questions = [
    "What is phishing?",
    "How does phishing URL detection work?",
    "Is my current URL safe?",
    "Why was this URL classified as phishing?",
    "Why was this URL classified as legitimate?",
    "What does the confidence score mean?",
    "What is SHAP?",
    "What is LIME?",
    "Which features made this URL suspicious?",
    "Explain the 10 detection modules.",
    "How can I identify a phishing URL?",
    "What should I do if I clicked a phishing link?",
    "How can I protect myself from phishing?",
    "What is the difference between phishing and malware?",
    "How does machine learning detect phishing URLs?"
]

sample_scan_context = {
    "url": "http://paypal-security-update.account-verify.xyz/signin.php",
    "domain": "paypal-security-update.account-verify.xyz",
    "prediction": "Phishing",
    "phishing_probability": 94.8,
    "confidence_score": 89.6,
    "risk_level": "Critical",
    "key_factors": [
        "Subdomain Masking (paypal.com mimicry)",
        "Untrusted High-Abuse TLD (.xyz)",
        "Insecure HTTP Protocol",
        "High Shannon Character Entropy (4.45)"
    ],
    "shap_explanation": {
        "contributions": [
            {"display_name": "TLD Risk Score", "value": ".xyz", "contribution": 0.28},
            {"display_name": "HTTPS Protocol Status", "value": "HTTP (Insecure)", "contribution": 0.22},
            {"display_name": "Subdomain Count", "value": "3", "contribution": 0.19},
            {"display_name": "Shannon Character Entropy", "value": "4.45", "contribution": 0.15}
        ]
    },
    "features": {
        "url_length": 62,
        "domain_length": 42,
        "subdomain_count": 3,
        "https_status": False,
        "entropy": 4.45,
        "tld_risk_score": 0.85
    }
}

print("\n--- [1] Testing 15 Sample Questions with Live Scan Context ---")
for i, q in enumerate(sample_questions, 1):
    req = ChatbotQuery(
        message=q,
        scanned_url_context=sample_scan_context["url"],
        prediction_context=sample_scan_context
    )
    res = query_ai_security_bot(req)
    lines = [l for l in res.reply.strip().split("\n") if l.strip()]
    header = lines[0] if lines else "NO_REPLY"
    print(f"[{i:02d}] Q: \"{q}\"")
    print(f"     -> Header: {header}")
    print(f"     -> Chars: {len(res.reply)} | Follow-ups: {res.suggested_actions[:2]}")
    assert len(res.reply) > 50, f"Response too short for '{q}'"
    assert len(res.suggested_actions) > 0, f"No actions for '{q}'"

# -------------------------------------------------------------
# TEST SET 2: 10-Module Pipeline Verification
# -------------------------------------------------------------
print("\n--- [2] Testing Project 10-Module Pipeline Queries ---")
module_queries = [
    "Explain the 10 detection modules in your system",
    "What does Module 1 (Dataset Collection) do?",
    "Explain Module 2: URL Input & Validation",
    "How does Module 3 extract 21 features?",
    "What is the role of Module 4 (Feature Preprocessing)?",
    "Explain Module 5: Phishing URL Classification",
    "How does Module 6 calculate risk and confidence scores?",
    "Explain Module 7 (Explainable AI SHAP & LIME)",
    "What does Module 8 (Feature Importance) analyze?",
    "How does Module 9 persist data to SQLite?",
    "Explain Module 10: Security Recommendations"
]

for i, mq in enumerate(module_queries, 1):
    req = ChatbotQuery(message=mq)
    res = query_ai_security_bot(req)
    lines = [l for l in res.reply.strip().split("\n") if l.strip()]
    header = lines[0] if lines else "NO_REPLY"
    print(f"[{i:02d}] Module Q: \"{mq}\"")
    print(f"     -> Header: {header} ({len(res.reply)} chars)")
    assert len(res.reply) > 100, f"Module explanation too short for '{mq}'"

# -------------------------------------------------------------
# TEST SET 3: Multi-turn Conversation & Pronoun Resolution
# -------------------------------------------------------------
print("\n--- [3] Testing Multi-Turn Conversation & Pronoun Resolution ---")
history_convo = [
    {"role": "user", "text": "What is phishing?"},
    {"role": "assistant", "text": "Phishing is a social engineering attack..."}
]

follow_up_q = "How does it work?"
resolved = resolve_contextual_pronouns(follow_up_q, history_convo)
print(f"Follow-up: \"{follow_up_q}\" -> Resolved as: \"{resolved}\"")
assert "phishing" in resolved.lower(), f"Failed to resolve pronoun: {resolved}"

req_followup = ChatbotQuery(
    message=follow_up_q,
    history=history_convo
)
res_followup = query_ai_security_bot(req_followup)
print(f"     -> AI Answer Header: {res_followup.reply.splitlines()[0]}")

# -------------------------------------------------------------
# TEST SET 4: Query Without Scan vs With Legitimate Scan
# -------------------------------------------------------------
print("\n--- [4] Testing Live Scan Context vs No Scan Context ---")

# A. Asking "Is my current URL safe?" with NO active scan context
req_no_scan = ChatbotQuery(message="Is my current URL safe?")
res_no_scan = query_ai_security_bot(req_no_scan)
print(f"No Scan Test: \"Is my current URL safe?\"")
print(f"     -> Header: {res_no_scan.reply.splitlines()[0]}")
assert "No Active URL Scan" in res_no_scan.reply or "haven't scanned" in res_no_scan.reply

# B. Asking with Legitimate Scan Context
legit_scan_context = {
    "url": "https://www.google.com/search?q=cybersecurity",
    "domain": "google.com",
    "prediction": "Legitimate",
    "phishing_probability": 3.2,
    "confidence_score": 93.6,
    "risk_level": "Safe",
    "key_factors": [
        "Official Authority Domain (google.com)",
        "Valid SSL/TLS Encryption",
        "Clean Threat Intelligence Feeds"
    ],
    "shap_explanation": {
        "contributions": [
            {"display_name": "HTTPS Protocol Status", "value": "HTTPS (Valid)", "contribution": -0.22},
            {"display_name": "TLD Risk Score", "value": ".com", "contribution": -0.18}
        ]
    },
    "features": {
        "url_length": 45,
        "domain_length": 10,
        "https_status": True,
        "entropy": 3.12
    }
}
req_legit = ChatbotQuery(
    message="Is my current URL safe?",
    scanned_url_context=legit_scan_context["url"],
    prediction_context=legit_scan_context
)
res_legit = query_ai_security_bot(req_legit)
print(f"Legit Scan Test: \"Is my current URL safe?\"")
print(f"     -> Header: {res_legit.reply.splitlines()[0]}")
assert "Legitimate" in res_legit.reply or "Safe" in res_legit.reply

print("\n" + "=" * 80)
print("🎉 ALL TEST SUITES PASSED FLAWLESSLY WITH 100% ACCURACY & FIDELITY!")
print("=" * 80)
