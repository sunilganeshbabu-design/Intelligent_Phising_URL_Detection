import sys
sys.stdout.reconfigure(encoding='utf-8')
import requests
import json

BASE = 'http://127.0.0.1:8000/api/chatbot'

test_queries = [
    # 1. Custom attack vector question
    "How do hackers bypass 2FA using reverse proxies like EvilProxy?",
    
    # 2. Custom comparison question
    "What is the difference between SHAP and LIME?",
    
    # 3. Custom incident response question
    "I accidentally clicked on a phishing link and entered my password, what should I do?",
    
    # 4. Custom machine learning question
    "How does the XGBooster model classify phishing URLs and optimize detection accuracy?",
    
    # 5. Custom technical metric question
    "How does Shannon character entropy help detect DGA botnets?",
    
    # 6. Direct URL analysis question
    "Is this URL safe: http://paypal-security-update.account-verify.xyz/signin.php?",
    
    # 7. General cybersecurity hygiene question
    "What are the best practices to secure my home Wi-Fi and passwords?",
    
    # 8. Web application security question
    "What is SQL injection and how does it compromise databases?",
    
    # 9. Web application security question
    "What is Cross-Site Scripting (XSS)?",
    
    # 10. Modern architectural question
    "What is Zero Trust security architecture and what are its 3 core principles?",
    
    # 11. Mobile link safety question
    "Can someone hack my phone by sending a link on WhatsApp?"
]

print("=== TESTING UPGRADED PHISHGUARD AI CHATBOT ENGINE ===\n")

for i, q in enumerate(test_queries, 1):
    print(f"[{i}] User Query: \"{q}\"")
    res = requests.post(BASE, json={"message": q})
    assert res.status_code == 200, f"Failed with code {res.status_code}: {res.text}"
    data = res.json()
    reply = data["reply"]
    actions = data.get("suggested_actions", [])
    
    lines = [l for l in reply.strip().split("\n") if l.strip()]
    print(f"    [+] AI Response Header: {lines[0] if lines else ''}")
    print(f"    [+] Length: {len(reply)} chars | Follow-up Chips: {len(actions)}")
    print(f"    [+] Follow-ups: {actions[:3]}")
    print()

print("ALL 11 COMPREHENSIVE CHATBOT TEST CASES PASSED SUCCESSFULLY!")
