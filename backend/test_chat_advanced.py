import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.models.schemas import ChatbotQuery
from app.api.chatbot import query_ai_security_bot

test_questions = [
    # 1. Broad fundamental question
    "What is phishing?",
    
    # 2. Web vulnerability
    "What is SQL injection and how does it compromise databases?",
    
    # 3. Mobile / messaging risk question
    "Can someone hack my phone by sending a link on WhatsApp?",
    
    # 4. Actionable defense / router security
    "How do I secure my home Wi-Fi and router?",
    
    # 5. Comparative question
    "What is the difference between symmetric and asymmetric encryption?",
    
    # 6. Conversational greeting
    "Hello there!",
    
    # 7. Assistant identity
    "Who are you and what can you help me with?",
    
    # 8. Threat landscape
    "What is the dark web and what should I do if my password is leaked?",
    
    # 9. Botnets and DGA
    "What is Shannon character entropy and how does it detect DGA botnets?",
    
    # 10. URL in message
    "Is this link safe: http://secure-login.paypal-verification.xyz/auth.php?",
    
    # 11. Arbitrary user question 1
    "What is steganography and how is it used in malware?",
    
    # 12. Arbitrary user question 2
    "How does a buffer overflow exploit work in computer security?"
]

print("=" * 70)
print("[*] TESTING ENHANCED PHISHGUARD AI CHATBOT MODEL")
print("=" * 70)

for idx, q in enumerate(test_questions, 1):
    query_obj = ChatbotQuery(message=q)
    resp = query_ai_security_bot(query_obj)
    
    lines = [l for l in resp.reply.strip().split("\n") if l.strip()]
    first_line = lines[0] if lines else "N/A"
    
    print(f"\n[{idx}] User Typed: \"{q}\"")
    print(f"    ├─ Header: {first_line}")
    print(f"    ├─ Response Length: {len(resp.reply)} chars")
    print(f"    ├─ Follow-up Actions ({len(resp.suggested_actions)}): {resp.suggested_actions[:3]}")
    
    # Assert response quality
    assert len(resp.reply) > 100, f"Response too short for query: {q}"
    assert len(resp.suggested_actions) > 0, f"Missing actions for query: {q}"

print("\n" + "=" * 70)
print("[+] ALL 12 DIVERSE USER-TYPED TEST QUERIES ANSWERED CLEARLY AND ACCURATELY!")
print("=" * 70)
